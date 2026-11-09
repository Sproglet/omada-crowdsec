# CrowdSec to TP-Link Omada gateway connector

This project reads eligible local IPv4 bans from a CrowdSec Local API and syncs
them into a dedicated Omada IP group referenced by a WAN-IN deny ACL. CrowdSec
continues to enforce its full decisions at the host/reverse proxy; the Omada
gateway provides an additional network-edge block for selected IPv4 addresses.

This is an independent community project, not an official CrowdSec or TP-Link
product. It uses the Omada Controller Open API and has been tested with an
OC300 controller and ER605 v2 gateway. Other controller and gateway models or
firmware versions may expose different API behavior. Review the dry-run plan
and verify blocking from an external client before relying on it.

## What it manages

- Reads only `ban` decisions from the local `crowdsec` and `cscli` origins.
- Filters to public IPv4 `/32` addresses, excludes configured protected
  addresses and the gateway's WAN addresses, and caps the selected set.
- Creates a dedicated IP group and a disabled WAN-IN deny ACL, then enables
  the ACL only when explicitly requested with `--enable`.
- Updates only groups recorded as created by this integration. It checks the
  group's identity and ACL scope before writing, and refuses groups shared by
  other gateway rules.
- Polls once per minute by default. The ER605 ACL group has no independent
  expiry, so the synchronizer must stay running to remove expired bans.

The integration supports the Omada gateway ACL mode **Through profiles** and
IPv4 WAN-IN rules. The current implementation supports up to 64 individual
IPv4 addresses across four groups, with at most 16 entries per group. This is
an integration limit, not a claim about every Omada device's hardware limit.
IPv6, CIDR blocks, community-list imports, and challenges are not synchronized.

## Requirements

- Docker Engine with the Docker Compose plugin and Python 3.10 or later.
- A running CrowdSec Local API and a Docker network that this service can join.
- An Omada hardware controller with a Client-mode Open API application scoped
  to the target site. Read-only permissions are enough for probing; enabling
  requires permission to modify that site's network configuration.
- A supported Omada gateway using ACL mode **Through profiles**, with WAN-IN
  interfaces available to the API.

## Configure

Clone the repository and enter its directory. Create a dedicated Docker
network or use the existing network that connects your CrowdSec container.
Copy `.env.example` to `.env` and set `CROWDSEC_NETWORK` to that network's
actual Docker network name. Set `CROWDSEC_CONTAINER` when the CrowdSec
container is not named `crowdsec`.

Configure the Omada API credentials locally. This command writes a mode-600
file under `secrets/` and does not print the client secret:

```sh
python3 probe.py --configure
```

Use a trusted HTTPS certificate for the controller. The probe verifies TLS by
default; for a locally-issued certificate, install its CA into the host's
trust store or pass `--ca-file /path/to/controller-ca.pem`. `--insecure` is
available only as an explicit diagnostic override.

List sites and inspect the target site without changing Omada configuration:

```sh
python3 probe.py
python3 probe.py --site 'YOUR SITE NAME'
```

Copy `config/settings.example.json` to `config/settings.json`, then set:

- `site_id`: the exact site ID shown by the probe.
- `crowdsec_url`: the LAPI URL reachable from the container on the configured
  Docker network, usually `http://crowdsec:8080` if that is its network alias.
- `crowdsec_host_url`: the LAPI URL reachable from the host-side setup script,
  for example a loopback URL if CrowdSec publishes the LAPI port locally.
- `protected_ips`: trusted public IP addresses or CIDRs that must never be
  blocked. Add all management and remote-access addresses you rely on.
- `controller_insecure`: leave `false` unless you deliberately accept
  disabling controller TLS certificate verification.

Keep `apply` set to `false`. Review the plan and start the container in dry-run
mode:

```sh
python3 setup.py --plan
```

The installer registers a dedicated CrowdSec bouncer by running `cscli` inside
the configured CrowdSec container, and stores its key under `secrets/`. The
key, Omada credentials, settings, and runtime state are excluded from Git.
The host-side `docker compose` command must be able to access the Docker
daemon. If your LAPI uses a different URL from the example, update both URLs
in `config/settings.json` as needed.

## Enable and operate

Review the proposed IPs, WAN interfaces, destination group, and rule scope.
Grant the Omada API application network-configuration modify permission for
the target site. Then explicitly provision and enable the managed ACL:

```sh
python3 setup.py --enable
```

The command creates the dedicated group, creates the WAN-IN deny ACL disabled,
populates and verifies the group, and only then enables the ACL. Review the
rule in Omada before relying on it. The rule blocks matching inbound traffic
to the selected WAN interfaces, including forwarded services. It does not
replace application-layer CrowdSec inspection.

Routine operations:

```sh
docker compose up -d
docker logs --tail 30 omada-crowdsec
python3 setup.py --capacity 32
python3 setup.py --disable
```

`--capacity` can be used from 1 to 64 after enabling the integration.
`--disable` disables the managed ACL and clears its IP groups. A graceful
container stop also attempts to clear the groups, but the gateway can retain
the last list if the process is killed or the controller is unreachable.

For an end-to-end test, use an external client address that is not protected,
add a short CrowdSec decision for that address, and verify from that external
network that a fresh connection is blocked at the gateway. Do not test from a
protected management address or rely on a forwarded HTTP header to simulate
the source IP.

## Security and data handling

Never commit `secrets/`, `config/settings.json`, `state/`, `.env`, or generated
plans/backups. The included `.gitignore` excludes them. If a credential is ever
committed or pushed, deleting the file is not enough: revoke and replace the
credential, then clean the Git history before publishing.

The service needs Omada credentials capable of modifying network settings
when enabled. Keep the API application scoped to the intended site and grant
only the required permissions. Run with verified TLS; use `controller_insecure`
only when you understand and accept the risk of a man-in-the-middle attack.

## Development

Run the offline behavior tests with:

```sh
python3 -B -m unittest -v test_gateway.py
```

The tests use a fake controller and do not contact or modify a live Omada
controller. API operations are based on TP-Link's [Omada Open API
documentation](https://omada-northbound-docs.tplinkcloud.com/) and its
[organization-level access guide](https://omada-northbound-docs.tplinkcloud.com/guides/organization-level-access-guide).
# omada-crowdsec
