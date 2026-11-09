#!/usr/bin/env python3
"""Check Omada Open API access without changing controller configuration."""

import argparse
import getpass
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = Path("/run/secrets/client.json")
if (SCRIPT_DIR / "Dockerfile").is_file():
    DEFAULT_CONFIG = SCRIPT_DIR / "secrets/client.json"


class ProbeError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Keep credentials and tokens on the configured controller.
        return None


def base_url(value):
    value = value.strip().rstrip("/")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ProbeError("Use the controller's HTTPS URL without a path, e.g. https://controller.example")
    return value


def validate_config(config):
    keys = ("base_url", "omadac_id", "client_id", "client_secret")
    if not isinstance(config, dict) or not all(
            isinstance(config.get(key), str) and config[key].strip() for key in keys):
        raise ProbeError("Credential file must contain base_url, omadac_id, client_id and client_secret.")
    if config["omadac_id"] == config["client_id"]:
        raise ProbeError("Omada ID and Client ID are identical. Copy the separate Omada ID from the "
                         "application's View/details page, then run --configure to correct it.")


def group_details(group):
    """Show only profile identity and subnet fields, never arbitrary API data."""
    if not isinstance(group, dict):
        return {"response_type": type(group).__name__}
    details = {key: group[key] for key in (
        "name", "type", "groupId", "id", "buildIn", "builtIn", "isBuiltIn", "count")
        if key in group}
    details["fields"] = sorted(group)
    entries = group.get("ipList")
    if isinstance(entries, list):
        details["ipList"] = [
            {key: entry[key] for key in ("ip", "mask") if key in entry}
            if isinstance(entry, dict) else {"response_type": type(entry).__name__}
            for entry in entries]
    return details


def configure(path):
    previous = {}
    if path.exists():
        previous = json.loads(path.read_text())
        if not isinstance(previous, dict):
            raise ProbeError("Existing credential file is not a JSON object.")
        print("Updating saved credentials. Press Enter to keep an existing value.")

    def prompt(label, key):
        old = previous.get(key, "")
        suffix = f" [{old}]" if old else ""
        return input(label + suffix + ": ").strip() or old

    config = {
        "base_url": base_url(prompt("Local controller HTTPS URL", "base_url")),
        "omadac_id": prompt("Omada ID (controller ID in application View/details)", "omadac_id"),
        "client_id": prompt("Client ID", "client_id"),
        "client_secret": getpass.getpass(
            "Client secret (hidden; Enter keeps saved secret): " if previous.get("client_secret")
            else "Client secret (hidden): ").strip() or previous.get("client_secret", ""),
    }
    validate_config(config)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(config, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    print(f"Saved credentials to {path} (mode 600).")


class Controller:
    def __init__(self, config, insecure=False, ca_file=None):
        self.base = base_url(config["base_url"])
        self.config = config
        context = ssl.create_default_context(cafile=ca_file)
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPSHandler(context=context), NoRedirects())
        self.token = None
        self.api = "/openapi/v1/" + quote(config["omadac_id"], safe="")

    def request(self, path, body=None, method=None):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "AccessToken=" + self.token
        request = Request(self.base + path, headers=headers,
                          data=json.dumps(body).encode() if body is not None else None,
                          method=method or ("POST" if body is not None else "GET"))
        try:
            with self.opener.open(request, timeout=20) as response:
                payload = json.load(response)
        except HTTPError as error:
            raise ProbeError(f"HTTP {error.code} at {path.split('?')[0]}", error.code) from None
        except URLError as error:
            raise ProbeError(f"Connection failed: {error.reason}") from None
        except (ValueError, TimeoutError):
            raise ProbeError("Controller response was invalid JSON or timed out.") from None
        if not isinstance(payload, dict) or payload.get("errorCode") != 0:
            code = payload.get("errorCode", "missing") if isinstance(payload, dict) else "missing"
            raise ProbeError(f"Omada API error {code} at {path.split('?')[0]}", code)
        return payload.get("result")

    def authenticate(self):
        # This is the only POST: it obtains a token, without changing settings.
        result = self.request("/openapi/authorize/token?grant_type=client_credentials", {
            "omadacId": self.config["omadac_id"],
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
        })
        if not isinstance(result, dict) or not result.get("accessToken"):
            raise ProbeError("Authentication response did not contain an access token.")
        self.token = result["accessToken"]

    def pages(self, path):
        rows = []
        for page in range(1, 101):
            result = self.request(path + "?" + urlencode({"page": page, "pageSize": 100}))
            if not isinstance(result, dict) or not isinstance(result.get("data"), list):
                raise ProbeError("Unexpected paginated response format.")
            batch = result["data"]
            rows.extend(batch)
            total = result.get("totalRows")
            if not batch or (isinstance(total, int) and len(rows) >= total) or (total is None and len(batch) < 100):
                return rows
        raise ProbeError("Pagination exceeded 100 pages.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configure", action="store_true", help="Create or update saved credentials; Enter keeps existing values")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--site", help="Check this site ID or exact site name; otherwise list sites only")
    parser.add_argument("--group-details", action="store_true",
                        help="With --site, show IP-group IDs, built-in flags and subnets for diagnostics")
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--ca-file", help="PEM certificate authority for the controller certificate")
    tls.add_argument("--insecure", action="store_true", help="Allow the local controller's self-signed certificate")
    args = parser.parse_args()
    if args.group_details and not args.site:
        parser.error("--group-details requires --site")
    if args.configure:
        configure(args.config)
        return 0
    if not args.config.is_file():
        raise ProbeError("Configure credentials first: python3 probe.py --configure")
    if args.config.stat().st_mode & 0o077:
        raise ProbeError(f"Restrict credential file permissions: chmod 600 {args.config}")
    config = json.loads(args.config.read_text())
    validate_config(config)
    controller = Controller(config, args.insecure, args.ca_file)
    controller.authenticate()
    print("OK  Client-mode authentication")
    sites = controller.pages(controller.api + "/sites")
    for site in sites:
        print(f"SITE  {site['siteId']}  {site['name']}")
    if not args.site:
        print("Run again with --site 'site name' to check IP groups and gateway ACLs.")
        return 0
    matches = [site for site in sites if args.site in (site["siteId"], site["name"])]
    if len(matches) != 1:
        raise ProbeError("Select exactly one listed site by its site ID or exact name.")
    path = controller.api + "/sites/" + quote(matches[0]["siteId"], safe="")
    failed = False
    for label, suffix, paginated in (
            ("IP groups", "/profiles/groups/0", False),
            ("Gateway ACL mode", "/acls/osg-config-mode", False),
            ("Gateway ACLs", "/acls/osg-acls", True)):
        try:
            result = controller.pages(path + suffix) if paginated else controller.request(path + suffix)
            if label == "Gateway ACL mode":
                print(f"OK  {label}: {result}")
            elif isinstance(result, list):
                print(f"OK  {label}: {len(result)} entries")
                if label == "IP groups":
                    for group in result:
                        print(f"    {group.get('name', '')}: {group.get('count', len(group.get('ipList', [])))} IP entries")
                        if args.group_details:
                            print("    " + json.dumps(group_details(group), sort_keys=True))
            else:
                raise ProbeError("Unexpected list response format.")
        except ProbeError as error:
            print(f"CHECK  {label}: {error}")
            failed = True
    print("No IP groups or firewall rules were changed. Write access remains untested.")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ProbeError, OSError, ValueError, KeyError, EOFError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
