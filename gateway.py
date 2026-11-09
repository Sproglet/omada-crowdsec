#!/usr/bin/env python3
"""Synchronize a small, dedicated Omada IP group with local CrowdSec IPv4 bans."""

import argparse
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, build_opener, ProxyHandler

from probe import Controller, ProbeError, validate_config


GROUP_NAME = "CrowdSec-Gateway"
RULE_NAME = "CrowdSec gateway bans (managed by omada-crowdsec)"
GROUP_SIZE = 16
MAX_GROUPS = 4
MAX_IPS = GROUP_SIZE * MAX_GROUPS
PLACEHOLDER = "192.0.2.1"  # Documentation-only /32 keeps an empty group nonempty.
ORIGINS = {"crowdsec", "cscli"}
UNITS = {"h": 3600, "m": 60, "s": 1, "ms": .001, "us": .000001,
         "µs": .000001, "μs": .000001, "ns": .000000001}


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def duration_seconds(value):
    if not isinstance(value, str) or value.startswith("-"):
        return 0
    parts = list(re.finditer(r"(\d+(?:\.\d+)?)(ms|us|µs|μs|ns|h|m|s)", value))
    if not parts or "".join(part.group() for part in parts) != value:
        raise ProbeError("Invalid decision duration from CrowdSec.")
    seconds = sum(float(part[1]) * UNITS[part[2]] for part in parts)
    if not math.isfinite(seconds):
        raise ProbeError("Nonfinite decision duration from CrowdSec.")
    return seconds


def protected_networks(values):
    try:
        return [ipaddress.ip_network(value, strict=False) for value in values]
    except (TypeError, ValueError):
        raise ProbeError("A protected IP/CIDR is invalid.") from None


def public_ipv4(value, protected):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        return None
    address = network.network_address
    if network.version != 4 or network.prefixlen != 32 or not address.is_global or address.is_multicast:
        return None
    if any(address in exclusion for exclusion in protected if exclusion.version == 4):
        return None
    return str(address)


def decision_cache(decisions, protected, now):
    if not isinstance(decisions, list):
        raise ProbeError("CrowdSec did not return a decisions list.")
    cache = {}
    for decision in decisions:
        if not isinstance(decision, dict):
            raise ProbeError("Invalid decision object from CrowdSec.")
        if (str(decision.get("origin", "")).lower() not in ORIGINS
                or str(decision.get("scope", "")).lower() != "ip"
                or decision.get("type") != "ban"):
            continue
        address = public_ipv4(decision.get("value"), protected)
        if address is None:
            continue
        seconds = duration_seconds(decision.get("duration"))
        if seconds <= 0:
            continue
        try:
            decision_id = int(decision["id"])
        except (KeyError, TypeError, ValueError):
            raise ProbeError("CrowdSec decision has no valid ID.") from None
        old = cache.get(address, {"until": 0, "id": 0})
        cache[address] = {"until": max(old["until"], now + seconds),
                          "id": max(old["id"], decision_id)}
    return cache


def select_ips(cache, protected, now, limit):
    valid = {}
    for address, decision in cache.items():
        normalized = public_ipv4(address, protected)
        if normalized and decision["until"] > now:
            valid[normalized] = decision
    ordered = sorted(valid, key=lambda ip: (-valid[ip]["id"], int(ipaddress.ip_address(ip))))
    return valid, ordered[:limit]


def group_name(index):
    return GROUP_NAME if index == 0 else f"{GROUP_NAME}-{index + 1}"


def managed_group_ids(settings):
    if "group_ids" in settings:
        return settings["group_ids"]
    return [settings["group_id"]] if settings.get("group_id") else []


def group_payload(addresses, name=GROUP_NAME):
    if len(addresses) > GROUP_SIZE:
        raise ProbeError(f"An ER605 IP group may contain at most {GROUP_SIZE} entries in this integration.")
    return {"name": name, "type": 0, "ipList": [
        {"ip": address, "mask": 32, "description": "Managed by omada-crowdsec"}
        for address in (addresses or [PLACEHOLDER])]}


def acl_payload(group_ids, any_id, wan_ids, enabled):
    group_ids = [group_ids] if isinstance(group_ids, str) else group_ids
    if (not isinstance(group_ids, list) or not 1 <= len(group_ids) <= MAX_GROUPS
            or not all(isinstance(identity, str) and identity.strip() for identity in group_ids)
            or len(set(group_ids)) != len(group_ids) or any_id in group_ids or not wan_ids):
        raise ProbeError("Refusing an ACL with an empty or unrestricted source or no WAN interfaces.")
    return {"description": RULE_NAME, "status": enabled, "policy": 0,
            "protocols": [256], "sourceIds": list(group_ids), "destinationIds": [any_id],
            "syslog": False, "sourceType": 1, "destinationType": 1,
            "direction": {"lanToWan": False, "lanToLan": False,
                          "wanInIds": sorted(wan_ids), "vpnInIds": []},
            "stateMode": 1, "states": {"stateNew": True, "established": True,
                                      "related": True, "invalid": True}}


def validate_settings(settings):
    if not isinstance(settings, dict) or not isinstance(settings.get("site_id"), str) or not settings["site_id"]:
        raise ProbeError("A target site_id is required in settings.json.")
    if type(settings.get("apply")) is not bool or type(settings.get("controller_insecure")) is not bool:
        raise ProbeError("apply and controller_insecure must be booleans.")
    if type(settings.get("max_ips")) is not int or not 1 <= settings["max_ips"] <= MAX_IPS:
        raise ProbeError(f"max_ips must be within 1–{MAX_IPS} for this ER605 configuration.")
    if type(settings.get("interval_seconds")) is not int or not 30 <= settings["interval_seconds"] <= 3600:
        raise ProbeError("interval_seconds must be within 30–3600.")
    if not isinstance(settings.get("protected_ips"), list):
        raise ProbeError("protected_ips must be a list.")
    protected_networks(settings["protected_ips"])
    identities = managed_group_ids(settings)
    if (not isinstance(identities, list) or len(identities) > MAX_GROUPS
            or not all(isinstance(identity, str) and identity.strip() for identity in identities)
            or len(set(identities)) != len(identities)
            or (identities and settings.get("group_id") != identities[0])):
        raise ProbeError("Managed group IDs must be unique and start with the saved primary group ID.")
    if settings["apply"] and not all(settings.get(key) for key in ("group_id", "acl_id", "wan_ids")):
        raise ProbeError("Run setup.py --enable to provision the dedicated group and rule first.")
    if settings["apply"] and settings["max_ips"] > len(identities) * GROUP_SIZE:
        raise ProbeError("Provision extra IP groups with setup.py --capacity before increasing max_ips.")


def log(event, **fields):
    print(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "event": event, **fields}), flush=True)


class Gateway:
    def __init__(self, settings, client_path, key_path, state_path, crowdsec_url=None):
        validate_settings(settings)
        self.settings = settings
        config = json.loads(Path(client_path).read_text())
        validate_config(config)
        self.controller = Controller(config, settings["controller_insecure"])
        self.key = Path(key_path).read_text().strip()
        if not self.key:
            raise ProbeError("CrowdSec bouncer key is empty.")
        self.state_path = Path(state_path)
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {"cache": {}}
        if not isinstance(self.state, dict) or not isinstance(self.state.get("cache"), dict):
            raise ProbeError("Invalid synchronization state.")
        self.crowdsec_url = (crowdsec_url or settings["crowdsec_url"]).rstrip("/")
        self.authenticated_at = 0
        self.last_report = None

    def request(self, suffix, body=None, method=None):
        if not self.controller.token or time.time() - self.authenticated_at > 6000:
            self.controller.authenticate()
            self.authenticated_at = time.time()
        path = self.controller.api + "/sites/" + quote(self.settings["site_id"], safe="") + suffix
        try:
            return self.controller.request(path, body, method)
        except ProbeError as error:
            if error.code not in (-44112, -44113, 401):
                raise
            self.controller.authenticate()
            self.authenticated_at = time.time()
            return self.controller.request(path, body, method)

    def pages(self, suffix):
        rows = []
        for page in range(1, 101):
            result = self.request(suffix + "?" + urlencode({"page": page, "pageSize": 100}))
            if not isinstance(result, dict) or not isinstance(result.get("data"), list):
                raise ProbeError("Invalid gateway ACL list response.")
            batch = result["data"]
            rows.extend(batch)
            total = result.get("totalRows")
            if not batch or (isinstance(total, int) and len(rows) >= total) or (total is None and len(batch) < 100):
                return rows
        raise ProbeError("Too many gateway ACL pages.")

    def discover(self):
        mode = self.request("/acls/osg-config-mode")
        if not isinstance(mode, dict) or mode.get("mode") != 0:
            raise ProbeError("Gateway ACL mode changed; only 'Through profiles' (mode 0) is supported.")
        groups = self.request("/profiles/groups/0")
        if not isinstance(groups, list) or not all(isinstance(group, dict) for group in groups):
            raise ProbeError("Invalid IP-group response.")
        any_groups = [group for group in groups if group.get("name") == "IPGroup_Any"]
        if len(any_groups) != 1:
            raise ProbeError("Could not identify the built-in IPGroup_Any destination.")
        any_group = any_groups[0]
        entries = any_group.get("ipList")
        # This OC300 omits buildIn. Verify identity and all-IPv4 contents instead;
        # an explicit contradictory flag still fails validation.
        if (not isinstance(any_group.get("groupId"), str) or not any_group["groupId"].strip()
                or type(any_group.get("type")) is not int or any_group["type"] != 0
                or any_group.get("buildIn", True) is not True
                or not isinstance(entries, list) or len(entries) != 1
                or not isinstance(entries[0], dict) or entries[0].get("ip") != "0.0.0.0"
                or type(entries[0].get("mask")) is not int or entries[0]["mask"] != 0):
            raise ProbeError("IPGroup_Any identity or all-IPv4 contents are invalid.")
        result = self.request("/setting/wan-ports?function=0")
        if not isinstance(result, dict) or not isinstance(result.get("wanPorts"), list):
            raise ProbeError("Invalid available-WAN response.")
        ports = [port for port in result["wanPorts"] if port.get("portUuid")]
        if not ports or len({port["portUuid"] for port in ports}) != len(ports):
            raise ProbeError("Could not identify unique WAN interfaces for the ACL.")
        return {"groups": groups, "any_id": any_group["groupId"],
                "ports": ports, "acls": self.pages("/acls/osg-acls")}

    def protections(self, discovery):
        values = list(self.settings["protected_ips"])
        values.extend(port["ip"] for port in discovery["ports"] if port.get("ip"))
        return protected_networks(values)

    def snapshot(self, protected):
        now = time.time()
        query = urlencode({"origins": ",".join(sorted(ORIGINS)), "scope": "Ip", "type": "ban"})
        request = Request(self.crowdsec_url + "/v1/decisions?" + query,
                          headers={"X-Api-Key": self.key, "Accept": "application/json"})
        try:
            with build_opener(ProxyHandler({})).open(request, timeout=15) as response:
                data = response.read(16 * 1024 * 1024 + 1)
                if len(data) > 16 * 1024 * 1024:
                    raise ProbeError("CrowdSec response exceeds 16 MiB; refusing an oversized snapshot.")
                payload = json.loads(data)
        except HTTPError as error:
            raise ProbeError(f"CrowdSec HTTP {error.code}") from None
        except (URLError, OSError, ValueError):
            raise ProbeError("CrowdSec snapshot unavailable.") from None
        self.state["cache"] = decision_cache([] if payload is None else payload, protected, now)
        self.state["last_crowdsec_success"] = now
        save_json(self.state_path, self.state)

    def candidates(self, discovery, require_fresh=False):
        protected = self.protections(discovery)
        try:
            self.snapshot(protected)
        except ProbeError as error:
            if require_fresh:
                raise
            log("crowdsec_unavailable", error=str(error), action="expire cached bans; retry next interval")
        valid, selected = select_ips(self.state["cache"], protected, time.time(), self.settings["max_ips"])
        self.state["cache"] = valid
        save_json(self.state_path, self.state)
        return selected, len(valid)

    def owned_groups(self, discovery, require_acl=True):
        identities = managed_group_ids(self.settings)
        if not identities or discovery["any_id"] in identities:
            raise ProbeError("Dedicated IP-group ID is missing or refers to IPGroup_Any; refusing changes.")
        groups = []
        for index, identity in enumerate(identities):
            matches = [group for group in discovery["groups"] if group.get("groupId") == identity]
            # Creation IDs, names and types establish ownership even when the
            # OC300 omits buildIn. Validate every group before writing any group.
            if (len(matches) != 1 or matches[0].get("name") != group_name(index)
                    or matches[0].get("buildIn", False) is not False
                    or type(matches[0].get("type")) is not int or matches[0]["type"] != 0):
                raise ProbeError("Dedicated IP-group identity changed; refusing to modify it.")
            groups.append(matches[0])
        others = [rule for rule in discovery["acls"] if rule.get("id") != self.settings.get("acl_id")
                  and set(identities).intersection(rule.get("sourceIds", []) + rule.get("destinationIds", []))]
        if others:
            raise ProbeError("Another gateway rule references the managed group; refusing changes.")
        if not require_acl:
            return groups, None
        rules = [rule for rule in discovery["acls"] if rule.get("id") == self.settings.get("acl_id")]
        if len(rules) != 1:
            raise ProbeError("Dedicated gateway ACL is missing or ambiguous.")
        rule = rules[0]
        if type(rule.get("status")) is not bool:
            raise ProbeError("Dedicated gateway ACL status is invalid.")
        expected = acl_payload(identities, discovery["any_id"], self.settings["wan_ids"], rule.get("status"))
        for field in ("description", "policy", "sourceType", "destinationType", "stateMode", "states"):
            if rule.get(field) != expected[field]:
                raise ProbeError(f"Dedicated gateway ACL {field} changed; refusing IP-group updates.")
        for field in ("sourceIds", "destinationIds", "protocols"):
            if sorted(rule.get(field, [])) != sorted(expected[field]):
                raise ProbeError(f"Dedicated gateway ACL {field} changed; refusing IP-group updates.")
        direction = rule.get("direction", {})
        if (direction.get("lanToWan", False) or direction.get("lanToLan", False)
                or direction.get("vpnInIds", []) or sorted(direction.get("wanInIds", [])) != expected["direction"]["wanInIds"]):
            raise ProbeError("Dedicated gateway ACL direction changed; refusing IP-group updates.")
        if not set(self.settings["wan_ids"]).issubset({port["portUuid"] for port in discovery["ports"]}):
            raise ProbeError("A configured WAN interface disappeared; review the gateway rule.")
        return groups, rule

    def owned(self, discovery, require_acl=True):
        groups, rule = self.owned_groups(discovery, require_acl)
        return groups[0], rule

    def _write_group_members(self, groups, selected, acl_enabled):
        if len(selected) > len(groups) * GROUP_SIZE:
            raise ProbeError("Selected bans exceed the provisioned IP-group capacity.")
        for index, group in enumerate(groups):
            addresses = selected[index * GROUP_SIZE:(index + 1) * GROUP_SIZE]
            wanted = group_payload(addresses, group_name(index))
            current = {(entry.get("ip"), entry.get("mask")) for entry in group.get("ipList", [])}
            target = {(entry["ip"], entry["mask"]) for entry in wanted["ipList"]}
            if current != target:
                identity = quote(group["groupId"], safe="")
                self.request("/profiles/groups/0/" + identity, wanted, "PATCH")
                log("group_updated", group=wanted["name"], bans=len(addresses), acl_enabled=acl_enabled)

    def update_group(self, discovery, selected):
        groups, rule = self.owned_groups(discovery)
        self._write_group_members(groups, selected, rule["status"])

    def plan(self):
        discovery = self.discover()
        selected, eligible = self.candidates(discovery, require_fresh=True)
        identities = list(managed_group_ids(self.settings))
        count = max(len(identities), math.ceil(self.settings["max_ips"] / GROUP_SIZE))
        identities.extend(f"DEDICATED_GROUP_{index + 1}_TO_BE_CREATED" for index in range(len(identities), count))
        result = {"site_id": self.settings["site_id"], "mode": "apply" if self.settings["apply"] else "dry-run",
                  "wan_interfaces": [{"id": port["portUuid"], "name": port.get("portName", "")}
                                     for port in discovery["ports"]],
                  "protected_ips": [str(value) for value in self.protections(discovery)],
                  "eligible_local_bans": eligible, "gateway_cap": self.settings["max_ips"],
                  "selected_ips": selected, "groups": [
                      group_payload(selected[index * GROUP_SIZE:(index + 1) * GROUP_SIZE], group_name(index))
                      for index in range(count)],
                  "rule": acl_payload(identities, discovery["any_id"],
                                      self.settings.get("wan_ids") or [port["portUuid"] for port in discovery["ports"]], True),
                  "existing_gateway_acls": len(discovery["acls"])}
        return result

    def cycle(self):
        discovery = self.discover()
        selected, eligible = self.candidates(discovery)
        if self.settings["apply"]:
            self.update_group(discovery, selected)
            _, rule = self.owned(discovery)
            if not rule["status"]:
                log("acl_disabled", action="kept disabled; only setup.py --enable enables the rule")
        report = (self.settings["apply"], tuple(selected), eligible)
        if report != self.last_report:
            log("sync" if self.settings["apply"] else "dry_run", selected_ips=selected,
                eligible=eligible, cap=self.settings["max_ips"], protected_ips=self.settings["protected_ips"])
            self.last_report = report
        if time.time() - self.state.get("last_crowdsec_success", 0) < 3 * self.settings["interval_seconds"]:
            self.state["last_success"] = time.time()
        save_json(self.state_path, self.state)

    def clear(self):
        self.update_group(self.discover(), [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, default=Path("/config/settings.json"))
    parser.add_argument("--client", type=Path, default=Path("/run/secrets/client.json"))
    parser.add_argument("--key", type=Path, default=Path("/run/secrets/crowdsec-key"))
    parser.add_argument("--state", type=Path, default=Path("/state/state.json"))
    parser.add_argument("--crowdsec-url", help="Override LAPI URL for a host-side check")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--plan", action="store_true", help="Read and print a plan without changing Omada")
    modes.add_argument("--once", action="store_true", help="Run one synchronization cycle")
    modes.add_argument("--health", action="store_true", help="Check the last successful cycle")
    args = parser.parse_args()
    settings = json.loads(args.settings.read_text())
    validate_settings(settings)
    if args.health:
        state = json.loads(args.state.read_text())
        return 0 if time.time() - state.get("last_success", 0) < 3 * settings["interval_seconds"] else 1
    gateway = Gateway(settings, args.client, args.key, args.state, args.crowdsec_url)
    if args.plan:
        print(json.dumps(gateway.plan(), indent=2))
        return 0
    if args.once:
        gateway.cycle()
        return 0
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    log("starting", mode="apply" if settings["apply"] else "dry-run", cap=settings["max_ips"])
    try:
        while not stop.is_set():
            settings = json.loads(args.settings.read_text())
            validate_settings(settings)
            if gateway.settings["apply"] and not settings["apply"]:
                gateway.clear()
            gateway.settings = settings
            try:
                gateway.cycle()
            except (ProbeError, OSError, ValueError, KeyError, TypeError) as error:
                log("sync_error", error=str(error))
            stop.wait(settings["interval_seconds"])
    finally:
        if gateway.settings["apply"]:
            try:
                gateway.clear()
                log("stopped", action="managed group cleared")
            except (ProbeError, OSError, ValueError, KeyError, TypeError) as error:
                log("stop_cleanup_failed", error=str(error))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProbeError, OSError, ValueError, KeyError, TypeError) as error:
        log("fatal", error=str(error))
        raise SystemExit(1)
