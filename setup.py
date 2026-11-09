#!/usr/bin/env python3
"""Install the Omada CrowdSec container in dry-run mode, then explicitly enable it."""

import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from gateway import (Gateway, GROUP_NAME, RULE_NAME, GROUP_SIZE, MAX_IPS, ProbeError,
                     acl_payload, group_name, group_payload, managed_group_ids,
                     save_json, validate_settings)


ROOT = Path(__file__).resolve().parent
DATA = ROOT
SETTINGS = DATA / "config/settings.json"
CLIENT = DATA / "secrets/client.json"
KEY = DATA / "secrets/crowdsec-key"
STATE = DATA / "state/state.json"
SERVICE = "omada-crowdsec"


def docker(*args, capture=False):
    result = subprocess.run(["docker", *args], cwd=ROOT, text=True,
                            capture_output=capture, check=False)
    if result.returncode:
        # Captured output may contain a newly generated API key.
        raise ProbeError("Docker command failed: " + " ".join(args[:4]))
    return result.stdout if capture else None


def prepare():
    if not SETTINGS.is_file():
        raise ProbeError("Copy config/settings.example.json to config/settings.json and edit it first.")
    if not CLIENT.is_file():
        raise ProbeError("Configure Omada credentials first: python3 probe.py --configure")
    settings = json.loads(SETTINGS.read_text())
    validate_settings(settings)
    for folder in (DATA / "config", DATA / "secrets", DATA / "state"):
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder.chmod(0o700)
    CLIENT.chmod(0o600)
    if not KEY.is_file():
        crowdsec_container = settings.get("crowdsec_container", os.environ.get("CROWDSEC_CONTAINER", "crowdsec"))
        key = docker("exec", crowdsec_container, "cscli", "bouncers", "add", SERVICE, "-o", "raw", capture=True).strip()
        if not re.fullmatch(r"[A-Za-z0-9_+/=-]{20,256}", key):
            raise ProbeError("CrowdSec did not return a valid raw key. No key was printed. "
                             "If the bouncer was created, remove that unused entry before retrying.")
        fd = os.open(KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(key + "\n")
        print("Registered a dedicated CrowdSec bouncer; saved its key locally.")
    KEY.chmod(0o600)
    return settings


def install_compose():
    docker("compose", "config", "--quiet", capture=True)


def host_gateway(settings, preview=False):
    state = DATA / "state/preview-state.json" if preview else STATE
    return Gateway(settings, CLIENT, KEY, state,
                   crowdsec_url=settings.get("crowdsec_host_url", "http://127.0.0.1:8080"))


def enable(settings):
    # Stop the sole writer before provisioning; no other containers are restarted.
    docker("compose", "stop", SERVICE, capture=True)
    settings["apply"] = False
    save_json(SETTINGS, settings)
    gateway = host_gateway(settings)
    discovery = gateway.discover()
    selected, _ = gateway.candidates(discovery, require_fresh=True)
    if not settings.get("group_id"):
        if any(group.get("name") == GROUP_NAME for group in discovery["groups"]):
            raise ProbeError("A group named CrowdSec-Gateway already exists without our ownership record. Review it first.")
        if discovery["acls"]:
            raise ProbeError("Gateway ACLs were added since the initial check. Review their order before creating the managed rule.")
        result = gateway.request("/profiles/groups", group_payload([]), "POST")
        if not isinstance(result, dict) or not isinstance(result.get("id"), str) or not result["id"]:
            raise ProbeError("Group creation response has no ID; review the created group before retrying.")
        settings["group_id"] = result["id"]
        settings["wan_ids"] = [port["portUuid"] for port in discovery["ports"]]
        save_json(SETTINGS, settings)
        print("Created the dedicated IP group with a documentation-only placeholder.")
        discovery = gateway.discover()
    if not settings.get("acl_id"):
        candidates = [rule for rule in discovery["acls"] if rule.get("description") == RULE_NAME]
        if not candidates:
            group, _ = gateway.owned(discovery, require_acl=False)
            if discovery["acls"]:
                raise ProbeError("Other gateway ACLs exist; review their order before creating the managed rule.")
            body = acl_payload(managed_group_ids(settings), discovery["any_id"], settings["wan_ids"], False)
            gateway.request("/acls/osg-acls", body, "POST")
            discovery = gateway.discover()
            candidates = [rule for rule in discovery["acls"] if rule.get("description") == RULE_NAME]
        if len(candidates) != 1 or not candidates[0].get("id"):
            raise ProbeError("Could not uniquely identify the newly created disabled ACL.")
        settings["acl_id"] = candidates[0]["id"]
        save_json(SETTINGS, settings)
        print("Created the WAN-IN deny rule in disabled state.")
    discovery = gateway.discover()
    gateway.owned(discovery)
    gateway.update_group(discovery, selected)
    try:
        body = acl_payload(managed_group_ids(settings), discovery["any_id"], settings["wan_ids"], True)
        gateway.request("/acls/osg-acls/" + settings["acl_id"], body, "PUT")
        _, rule = gateway.owned(gateway.discover())
        if rule["status"] is not True:
            raise ProbeError("Controller did not confirm the managed ACL is enabled.")
        settings["apply"] = True
        validate_settings(settings)
        save_json(SETTINGS, settings)
    except (ProbeError, OSError, ValueError, KeyError, TypeError):
        settings["apply"] = False
        save_json(SETTINGS, settings)
        try:
            body = acl_payload(managed_group_ids(settings), discovery["any_id"], settings["wan_ids"], False)
            gateway.request("/acls/osg-acls/" + settings["acl_id"], body, "PUT")
            gateway.clear()
            print("Activation failed; the managed rule was disabled and its group cleared.")
        except (ProbeError, OSError, ValueError, KeyError, TypeError):
            print("Activation could not be verified or rolled back. Check the dedicated CrowdSec rule in Omada before retrying.", file=sys.stderr)
        raise
    print(f"Enabled WAN-IN blocking for {len(selected)} active local IPv4 bans.")


def disable(settings):
    docker("compose", "stop", SERVICE, capture=True)
    settings["apply"] = False
    save_json(SETTINGS, settings)
    gateway = host_gateway(settings)
    if settings.get("acl_id"):
        discovery = gateway.discover()
        gateway.owned(discovery)
        body = acl_payload(managed_group_ids(settings), discovery["any_id"], settings["wan_ids"], False)
        gateway.request("/acls/osg-acls/" + settings["acl_id"], body, "PUT")
        gateway.clear()
    print("Gateway rule disabled; container will run in dry-run mode.")


def rule_body(identities, discovery, settings, rule):
    body = acl_payload(identities, discovery["any_id"], settings["wan_ids"], rule["status"])
    for field in ("syslog", "timeRangeId"):
        if field in rule:
            body[field] = rule[field]
    return body


def verify_members(groups, selected):
    for index, group in enumerate(groups):
        wanted = group_payload(selected[index * GROUP_SIZE:(index + 1) * GROUP_SIZE], group_name(index))["ipList"]
        current = group.get("ipList", [])
        if (len(current) != len(wanted)
                or {(entry.get("ip"), entry.get("mask")) for entry in current}
                != {(entry["ip"], entry["mask"]) for entry in wanted}):
            raise ProbeError("Controller did not confirm the requested IP-group contents.")


def set_capacity(settings, limit):
    if type(limit) is not int or not 1 <= limit <= MAX_IPS:
        raise ProbeError(f"Capacity must be within 1–{MAX_IPS}.")
    if not settings["apply"]:
        raise ProbeError("Enable the integration before changing its provisioned capacity.")
    original = copy.deepcopy(settings)
    staged = copy.deepcopy(original)
    staged["apply"] = False
    working = copy.deepcopy(staged)
    working["max_ips"] = limit
    working["group_ids"] = list(managed_group_ids(original))
    validate_settings(working)
    receipts_path = DATA / "config/capacity-groups.json"
    receipts = json.loads(receipts_path.read_text()) if receipts_path.exists() else []
    if (not isinstance(receipts, list) or not all(isinstance(item, dict)
            and isinstance(item.get("id"), str) and isinstance(item.get("name"), str) for item in receipts)):
        raise ProbeError("Invalid saved capacity-group ownership records.")
    gateway = host_gateway(staged)
    # Build before stopping the writer, so a broken image cannot interrupt it.
    docker("compose", "build", SERVICE)
    save_json(DATA / "config/settings.before-capacity.json", original)
    docker("compose", "stop", SERVICE, capture=True)
    save_json(SETTINGS, staged)
    try:
        discovery = gateway.discover()
        gateway.owned_groups(discovery)
        required = (limit + GROUP_SIZE - 1) // GROUP_SIZE
        for index in range(len(working["group_ids"]), required):
            name = group_name(index)
            matches = [group for group in discovery["groups"] if group.get("name") == name]
            if matches:
                if (len(matches) != 1 or not any(item["id"] == matches[0].get("groupId")
                        and item["name"] == name for item in receipts)):
                    raise ProbeError(f"A group named {name} exists without our creation record; refusing to adopt it.")
                identity = matches[0]["groupId"]
            else:
                result = gateway.request("/profiles/groups", group_payload([], name), "POST")
                if not isinstance(result, dict) or not isinstance(result.get("id"), str) or not result["id"]:
                    raise ProbeError("Additional group creation returned no ID; review it before retrying.")
                identity = result["id"]
                receipts.append({"id": identity, "name": name})
                save_json(receipts_path, receipts)
            working["group_ids"].append(identity)
            validate_settings(working)
            discovery = gateway.discover()
        gateway.settings = working
        groups, _ = gateway.owned_groups(discovery, require_acl=False)
        selected, _ = gateway.candidates(discovery, require_fresh=True)
        # Extra groups are populated before the ACL references them. Existing
        # groups retain the same managed rule and only receive filtered /32 bans.
        gateway.settings = staged
        _, rule = gateway.owned_groups(discovery)
        gateway.settings = working
        gateway._write_group_members(groups, selected, rule["status"])
        discovery = gateway.discover()
        groups, _ = gateway.owned_groups(discovery, require_acl=False)
        verify_members(groups, selected)
        # Recheck the original rule just before changing its source list, and
        # preserve a manual disable or schedule instead of enabling the rule.
        gateway.settings = staged
        _, rule = gateway.owned_groups(discovery)
        gateway.settings = working
        if sorted(rule["sourceIds"]) != sorted(working["group_ids"]):
            gateway.request("/acls/osg-acls/" + settings["acl_id"],
                            rule_body(working["group_ids"], discovery, working, rule), "PUT")
        _, confirmed = gateway.owned_groups(gateway.discover())
        if not rule["status"] and confirmed["status"]:
            raise ProbeError("The controller unexpectedly enabled a manually disabled rule.")
        working["apply"] = original["apply"]
        validate_settings(working)
        save_json(SETTINGS, working)
        settings.clear()
        settings.update(working)
    except (ProbeError, OSError, ValueError, KeyError, TypeError):
        try:
            gateway.settings = staged
            discovery = gateway.discover()
            try:
                _, current_rule = gateway.owned_groups(discovery)
            except ProbeError:
                gateway.settings = working
                _, current_rule = gateway.owned_groups(discovery)
                gateway.request("/acls/osg-acls/" + original["acl_id"],
                                rule_body(managed_group_ids(original), discovery, original, current_rule), "PUT")
            gateway.settings = staged
            discovery = gateway.discover()
            previous, _ = gateway.candidates(discovery)
            gateway.update_group(discovery, previous)
            save_json(SETTINGS, original)
            settings.clear()
            settings.update(original)
            print("Capacity change failed; the original rule and capacity were restored.", file=sys.stderr)
        except (ProbeError, OSError, ValueError, KeyError, TypeError):
            save_json(SETTINGS, staged)
            print("Capacity rollback could not be verified; integration left in dry-run mode. "
                  "Check the managed rule in Omada before retrying.", file=sys.stderr)
        docker("compose", "up", "-d", "--no-deps", SERVICE)
        raise
    print(f"Gateway capacity set to {limit} IPv4 bans across {len(working['group_ids'])} groups; "
          f"{len(selected)} active bans selected. Rule status preserved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--plan", action="store_true", help="Install/start in dry-run mode and print the proposed rule")
    modes.add_argument("--enable", action="store_true", help="Provision and enable the dedicated WAN-IN rule")
    modes.add_argument("--disable", action="store_true", help="Disable the dedicated rule and clear its group")
    modes.add_argument("--capacity", type=int, metavar="IPS",
                       help=f"Set capacity to 1–{MAX_IPS}, provisioning additional managed IP groups as needed")
    args = parser.parse_args()
    settings = prepare()
    if args.enable or args.disable or args.capacity is not None:
        install_compose()
        if args.capacity is not None:
            set_capacity(settings, args.capacity)
        elif args.enable:
            enable(settings)
        else:
            disable(settings)
    else:
        plan = host_gateway(settings, preview=True).plan()
        print(json.dumps(plan, indent=2))
        save_json(DATA / "config/plan.json", plan)
        if settings["apply"]:
            print("Existing gateway synchronization left running; no configuration or container changes made.")
            return 0
        install_compose()
    if args.capacity is not None:
        docker("compose", "up", "-d", "--no-deps", SERVICE)
    else:
        docker("compose", "up", "-d", "--build", "--no-deps", SERVICE)
    print("Container installed. Routine updates use: docker compose up -d")
    if not settings["apply"]:
        print("Dry-run mode: no Omada group or firewall changes are made by the container.")
        print("After reviewing the plan and granting network-configuration modify permission, run:")
        print("  python3 setup.py --enable")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ProbeError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        if isinstance(error, ProbeError) and error.code in (-1005, 403):
            print("Grant this application's target site permission to modify network configuration, then retry.", file=sys.stderr)
        sys.exit(1)
