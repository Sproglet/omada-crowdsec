"""Behavioral checks for the gateway's mutation boundaries and expiry handling."""

import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import gateway
import setup


class ContainerLayoutTests(unittest.TestCase):
    def test_runtime_imports_and_help_work_from_app(self):
        # Execute the shipped sources with their actual container __file__ paths
        # in a fresh process, without credentials, mounts or network access.
        script = """
from pathlib import Path
import sys
from types import ModuleType
source = Path(sys.argv[1])
for name in ('probe', 'gateway'):
    module = ModuleType(name)
    module.__file__ = '/app/' + name + '.py'
    sys.modules[name] = module
    exec(compile((source / (name + '.py')).read_text(), module.__file__, 'exec'), module.__dict__)
assert sys.modules['probe'].DEFAULT_CONFIG == Path('/run/secrets/client.json')
for name in ('probe', 'gateway'):
    sys.argv = [name + '.py', '--help']
    try:
        sys.modules[name].main()
    except SystemExit as error:
        assert error.code == 0
    else:
        raise AssertionError('CLI help did not exit')
"""
        result = subprocess.run([sys.executable, "-B", "-c", script, str(Path(__file__).resolve().parent)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--group-details", result.stdout)
        self.assertIn("--health", result.stdout)

    def test_host_probe_keeps_repository_credential_path(self):
        import probe
        expected = Path(__file__).resolve().parent / "secrets/client.json"
        self.assertEqual(probe.DEFAULT_CONFIG, expected)


def settings(apply=False):
    value = {"site_id": "test-site", "apply": apply, "controller_insecure": True,
             "max_ips": 16, "interval_seconds": 60, "protected_ips": ["8.8.8.8"],
             "crowdsec_url": "http://crowdsec:8080"}
    if apply:
        value.update(group_id="managed-group", acl_id="managed-rule", wan_ids=["wan-1"])
    return value


def decision(value, identity=1, duration="1h", **overrides):
    result = {"value": value, "id": identity, "duration": duration,
              "scope": "Ip", "type": "ban", "origin": "crowdsec"}
    result.update(overrides)
    return result


class FakeController:
    def __init__(self, config, insecure=False):
        self.api = "/openapi/v1/test-controller"
        self.token = None
        self.calls = []
        self.mode = 0
        self.groups = [{"groupId": "any", "name": "IPGroup_Any", "type": 0,
                        "count": 1, "ipList": [{"ip": "0.0.0.0", "mask": 0}]}]
        self.rules = []
        self.fail_enable = False
        self.fail_expansion = False

    def authenticate(self):
        self.calls.append(("POST", "/openapi/authorize/token", None))
        self.token = "sample-token"

    def request(self, path, body=None, method=None):
        method = method or ("POST" if body is not None else "GET")
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == "GET":
            if path.endswith("/acls/osg-config-mode"):
                return {"mode": self.mode}
            if path.endswith("/profiles/groups/0"):
                return copy.deepcopy(self.groups)
            if "/setting/wan-ports?" in path:
                return {"enable": True, "wanPorts": [{"portUuid": "wan-1", "portName": "WAN", "ip": "9.9.9.9"}]}
            if "/acls/osg-acls?" in path:
                return {"totalRows": len(self.rules), "data": copy.deepcopy(self.rules)}
        if method == "POST" and path.endswith("/profiles/groups"):
            identity = "managed-group" if body["name"] == gateway.GROUP_NAME else "managed-group-" + body["name"].rsplit("-", 1)[1]
            self.groups.append({**copy.deepcopy(body), "groupId": identity})
            return {"id": identity}
        if method == "POST" and path.endswith("/acls/osg-acls"):
            self.rules.append({**copy.deepcopy(body), "id": "managed-rule"})
            return None
        if method == "PATCH" and "/profiles/groups/0/" in path:
            identity = path.rsplit("/", 1)[-1]
            next(group for group in self.groups if group["groupId"] == identity).update(copy.deepcopy(body))
            return None
        if method == "PUT" and "/acls/osg-acls/" in path:
            if body["status"] and self.fail_enable:
                raise gateway.ProbeError("Permission denied", -1005)
            if len(body["sourceIds"]) > 1 and self.fail_expansion:
                raise gateway.ProbeError("Multiple groups rejected", -1005)
            identity = path.rsplit("/", 1)[-1]
            next(rule for rule in self.rules if rule["id"] == identity).update(copy.deepcopy(body))
            return None
        raise AssertionError((method, path))


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.client = self.root / "client.json"
        self.client.write_text(json.dumps({"base_url": "https://controller.example", "omadac_id": "controller",
                                           "client_id": "client", "client_secret": "sample-secret"}))
        self.key = self.root / "key"
        self.key.write_text("sample-crowdsec-key")
        self.state_path = self.root / "state.json"
        self.patches = [patch.object(gateway, "Controller", FakeController),
                        patch.object(gateway, "log"), patch("builtins.print")]
        for item in self.patches:
            item.start()
        self.clock = patch.object(gateway.time, "time", return_value=1000)
        self.clock.start()

    def tearDown(self):
        self.clock.stop()
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def instance(self, apply=False):
        return gateway.Gateway(settings(apply), self.client, self.key, self.state_path)

    def install_owned(self, instance, selected=None, enabled=True):
        controller = instance.controller
        identities = gateway.managed_group_ids(instance.settings) or ["managed-group"]
        selected = selected or []
        for index, identity in enumerate(identities):
            payload = gateway.group_payload(selected[index * 16:(index + 1) * 16], gateway.group_name(index))
            controller.groups.append({**payload, "groupId": identity})
        controller.rules.append({**gateway.acl_payload(identities, "any", ["wan-1"], enabled), "id": "managed-rule"})

    def multi_instance(self, selected=None):
        config = settings(True)
        config.update(max_ips=64, group_ids=["managed-group", "managed-group-2", "managed-group-3", "managed-group-4"])
        instance = gateway.Gateway(config, self.client, self.key, self.state_path)
        self.install_owned(instance, selected)
        return instance

    def capacity_change(self, instance, config, limit=64):
        def host(value):
            instance.settings = value
            return instance
        with patch.object(setup, "DATA", self.root / "data"), \
                patch.object(setup, "SETTINGS", self.root / "settings.json"), \
                patch.object(setup, "docker") as docker, \
                patch.object(setup, "host_gateway", side_effect=host):
            setup.set_capacity(config, limit)
        return docker

    def fresh_snapshot(self, instance, decisions):
        def snapshot(protected):
            instance.state["cache"] = gateway.decision_cache(decisions, protected, gateway.time.time())
            instance.state["last_crowdsec_success"] = gateway.time.time()
        return patch.object(instance, "snapshot", side_effect=snapshot)

    def mutations(self, instance):
        return [call for call in instance.controller.calls if call[0] != "GET" and "/authorize/token" not in call[1]]

    def test_filters_addresses_origins_types_and_ranges(self):
        items = [decision("8.8.8.8"), decision("1.1.1.1/32"), decision("10.0.0.1"),
                 decision("127.0.0.1"), decision("224.0.0.1"), decision("2.2.2.0/24", scope="Range"),
                 decision("2606:4700:4700::1111"), decision("3.3.3.3", origin="CAPI"),
                 decision("4.4.4.4", origin="cscli-import"), decision("5.5.5.5", type="captcha"),
                 decision("6.6.6.6", origin="cscli")]
        cache = gateway.decision_cache(items, gateway.protected_networks(["8.8.8.0/24"]), 1000)
        self.assertEqual(set(cache), {"1.1.1.1", "6.6.6.6"})

    def test_duplicate_bans_preserve_longest_expiry(self):
        cache = gateway.decision_cache([decision("1.1.1.1", 10, "1m"), decision("1.1.1.1", 11, "2h")], [], 1000)
        self.assertEqual(cache["1.1.1.1"], {"id": 11, "until": 8200})

    def test_cap_prioritizes_newest_and_removes_expired(self):
        cache = gateway.decision_cache([decision(f"11.1.1.{number}", number) for number in range(1, 22)], [], 1000)
        cache["11.1.1.21"]["until"] = 999
        valid, selected = gateway.select_ips(cache, [], 1000, 16)
        self.assertEqual(len(valid), 20)
        self.assertEqual(len(selected), 16)
        self.assertEqual(selected[0], "11.1.1.20")
        self.assertNotIn("11.1.1.21", selected)

    def test_four_groups_hold_64_bans_with_16_host_entries_each(self):
        instance = self.multi_instance()
        items = [decision(f"11.1.1.{number}", number) for number in range(1, 72)]
        with self.fresh_snapshot(instance, items):
            instance.cycle()
        groups = instance.controller.groups[1:]
        self.assertEqual([len(group["ipList"]) for group in groups], [16, 16, 16, 16])
        actual = {entry["ip"] for group in groups for entry in group["ipList"]}
        self.assertEqual(len(actual), 64)
        self.assertIn("11.1.1.71", actual)
        self.assertNotIn("11.1.1.7", actual)
        self.assertTrue(all(entry["mask"] == 32 for group in groups for entry in group["ipList"]))
        self.assertEqual(len(self.mutations(instance)), 4)

    def test_multi_group_cleanup_clears_all_owned_groups(self):
        instance = self.multi_instance([f"11.1.1.{number}" for number in range(1, 65)])
        instance.clear()
        self.assertTrue(all(group["ipList"][0]["ip"] == gateway.PLACEHOLDER
                            and len(group["ipList"]) == 1 for group in instance.controller.groups[1:]))
        self.assertEqual(len(self.mutations(instance)), 4)
        self.assertEqual(instance.controller.groups[0]["ipList"][0]["mask"], 0)

    def test_all_group_ownership_is_checked_before_first_write(self):
        for modification in ("name", "shared"):
            with self.subTest(modification=modification):
                instance = self.multi_instance()
                if modification == "name":
                    instance.controller.groups[3]["name"] = "User-managed group"
                else:
                    instance.controller.rules.append({"id": "user-rule", "sourceIds": ["managed-group-3"]})
                with self.fresh_snapshot(instance, [decision("1.1.1.1")]):
                    with self.assertRaises(gateway.ProbeError):
                        instance.cycle()
                self.assertEqual(self.mutations(instance), [])

    def test_active_settings_cannot_exceed_allocated_group_capacity(self):
        config = settings(True)
        config["max_ips"] = 64
        with self.assertRaisesRegex(gateway.ProbeError, "--capacity"):
            gateway.validate_settings(config)
        config.update(group_ids=["managed-group", "managed-group-2", "managed-group-3", "managed-group-4"])
        gateway.validate_settings(config)
        config["max_ips"] = 65
        with self.assertRaises(gateway.ProbeError):
            gateway.validate_settings(config)

    def test_single_group_payload_rejects_more_than_16_addresses(self):
        with self.assertRaises(gateway.ProbeError):
            gateway.group_payload([f"11.1.1.{number}" for number in range(1, 18)])

    def test_capacity_expands_groups_before_committing_rule_and_preserves_disable(self):
        config = settings(True)
        instance = gateway.Gateway(config, self.client, self.key, self.state_path)
        self.install_owned(instance, enabled=False)
        instance.controller.rules[0]["timeRangeId"] = "user-schedule"
        instance.controller.rules[0]["syslog"] = True
        with self.fresh_snapshot(instance, [decision(f"11.1.1.{number}", number) for number in range(1, 36)]):
            docker = self.capacity_change(instance, config)
        mutations = self.mutations(instance)
        self.assertEqual([call[0] for call in mutations], ["POST", "POST", "POST", "PATCH", "PATCH", "PATCH", "PUT"])
        self.assertTrue(all(call[2]["ipList"][0]["ip"] == gateway.PLACEHOLDER for call in mutations[:3]))
        self.assertEqual(len(instance.controller.rules[0]["sourceIds"]), 4)
        self.assertFalse(instance.controller.rules[0]["status"])
        self.assertEqual(instance.controller.rules[0]["timeRangeId"], "user-schedule")
        self.assertTrue(instance.controller.rules[0]["syslog"])
        saved = json.loads((self.root / "settings.json").read_text())
        self.assertTrue(saved["apply"])
        self.assertEqual(saved["max_ips"], 64)
        self.assertEqual(len(saved["group_ids"]), 4)
        self.assertEqual(docker.call_args_list[0].args, ("compose", "build", setup.SERVICE))
        self.assertEqual(docker.call_args_list[1].args, ("compose", "stop", setup.SERVICE))

    def test_failed_capacity_commit_restores_previous_scope_and_retry_reuses_groups(self):
        config = settings(True)
        instance = gateway.Gateway(config, self.client, self.key, self.state_path)
        self.install_owned(instance)
        instance.controller.fail_expansion = True
        items = [decision(f"11.1.1.{number}", number) for number in range(1, 36)]
        with self.fresh_snapshot(instance, items):
            with self.assertRaises(gateway.ProbeError):
                self.capacity_change(instance, config)
        saved = json.loads((self.root / "settings.json").read_text())
        self.assertTrue(saved["apply"])
        self.assertEqual(saved["max_ips"], 16)
        self.assertEqual(instance.controller.rules[0]["sourceIds"], ["managed-group"])
        self.assertEqual(len(instance.controller.groups[1]["ipList"]), 16)
        instance.controller.fail_expansion = False
        instance.controller.calls.clear()
        with self.fresh_snapshot(instance, items):
            self.capacity_change(instance, config)
        self.assertEqual(config["max_ips"], 64)
        self.assertFalse(any(call[0] == "POST" for call in self.mutations(instance)))

    def test_capacity_does_not_adopt_unowned_numbered_groups(self):
        config = settings(True)
        instance = gateway.Gateway(config, self.client, self.key, self.state_path)
        self.install_owned(instance)
        instance.controller.groups.append({**gateway.group_payload(["1.1.1.1"], "CrowdSec-Gateway-2"), "groupId": "user-owned"})
        with self.fresh_snapshot(instance, []):
            with self.assertRaisesRegex(gateway.ProbeError, "creation record"):
                self.capacity_change(instance, config)
        self.assertEqual(config["max_ips"], 16)
        self.assertFalse(any("user-owned" in call[1] or call[0] == "POST" for call in self.mutations(instance)))

    def test_lowering_capacity_clears_unused_groups_without_rewriting_rule(self):
        instance = self.multi_instance([f"11.1.1.{number}" for number in range(1, 65)])
        config = instance.settings
        items = [decision(f"11.1.1.{number}", number) for number in range(1, 65)]
        with self.fresh_snapshot(instance, items):
            self.capacity_change(instance, config, 10)
        self.assertEqual(config["max_ips"], 10)
        self.assertEqual(len(instance.controller.groups[1]["ipList"]), 10)
        self.assertTrue(all(group["ipList"][0]["ip"] == gateway.PLACEHOLDER for group in instance.controller.groups[2:]))
        self.assertFalse(any(call[0] in ("POST", "PUT") for call in self.mutations(instance)))

    def test_dry_run_plan_and_cycle_never_mutate_omada(self):
        instance = self.instance()
        with self.fresh_snapshot(instance, [decision("1.1.1.1"), decision("9.9.9.9")]):
            plan = instance.plan()
            instance.cycle()
        self.assertEqual(plan["selected_ips"], ["1.1.1.1"])
        self.assertEqual(plan["rule"]["protocols"], [256])
        self.assertFalse(plan["rule"]["direction"]["lanToWan"])
        self.assertFalse(plan["rule"]["direction"]["lanToLan"])
        self.assertEqual(self.mutations(instance), [])

    def test_plan_recognizes_observed_oc300_any_group_without_builtin_flag(self):
        instance = self.instance()
        instance.controller.groups = [{
            "count": 1, "groupId": "643b14753543725331737b88",
            "ipList": [{"ip": "0.0.0.0", "mask": 0}],
            "name": "IPGroup_Any", "type": 0}]
        with self.fresh_snapshot(instance, []):
            plan = instance.plan()
        self.assertEqual(plan["rule"]["destinationIds"], ["643b14753543725331737b88"])
        self.assertEqual(self.mutations(instance), [])

    def test_documented_builtin_flags_are_still_supported(self):
        instance = self.instance(True)
        self.install_owned(instance)
        instance.controller.groups[0]["buildIn"] = True
        instance.controller.groups[1]["buildIn"] = False
        with self.fresh_snapshot(instance, [decision("1.1.1.1")]):
            instance.cycle()
        self.assertEqual(len(self.mutations(instance)), 1)
        self.assertTrue(self.mutations(instance)[0][1].endswith("/managed-group"))

    def test_refuses_invalid_or_ambiguous_any_group_before_writes(self):
        for fields in (
                {"groupId": ""}, {"groupId": None}, {"groupId": True},
                {"type": None}, {"type": 1}, {"type": False}, {"buildIn": False},
                {"ipList": []}, {"ipList": None}, {"ipList": [None]},
                {"ipList": [{"ip": "10.0.0.0", "mask": 8}]},
                {"ipList": [{"ip": "0.0.0.0", "mask": 32}]},
                {"ipList": [{"ip": "0.0.0.0", "mask": False}]},
                {"duplicate": True}):
            with self.subTest(fields=fields):
                instance = self.instance(True)
                self.install_owned(instance)
                if fields.get("duplicate"):
                    instance.controller.groups.append(copy.deepcopy(instance.controller.groups[0]))
                else:
                    instance.controller.groups[0].update(fields)
                with self.assertRaises(gateway.ProbeError):
                    instance.cycle()
                self.assertEqual(self.mutations(instance), [])

    def test_explicit_builtin_flag_on_managed_group_prevents_writes(self):
        instance = self.instance(True)
        self.install_owned(instance)
        instance.controller.groups[1]["buildIn"] = True
        with self.fresh_snapshot(instance, [decision("1.1.1.1")]):
            with self.assertRaises(gateway.ProbeError):
                instance.cycle()
        self.assertEqual(self.mutations(instance), [])

    def test_updates_only_managed_group_and_uses_host_masks(self):
        instance = self.instance(True)
        self.install_owned(instance)
        with self.fresh_snapshot(instance, [decision("1.1.1.1")]):
            instance.cycle()
        mutations = self.mutations(instance)
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][0], "PATCH")
        self.assertTrue(mutations[0][1].endswith("/profiles/groups/0/managed-group"))
        self.assertEqual(mutations[0][2]["ipList"][0]["mask"], 32)
        self.assertEqual(instance.controller.groups[0]["name"], "IPGroup_Any")

    def test_unchanged_membership_avoids_controller_writes(self):
        instance = self.instance(True)
        self.install_owned(instance, ["1.1.1.1"])
        with self.fresh_snapshot(instance, [decision("1.1.1.1")]):
            instance.cycle()
            instance.cycle()
        self.assertEqual(self.mutations(instance), [])

    def test_lapi_outage_expires_cached_bans(self):
        instance = self.instance(True)
        self.install_owned(instance, ["1.1.1.1"])
        instance.state["cache"] = {"1.1.1.1": {"until": 999, "id": 1}}
        with patch.object(instance, "snapshot", side_effect=gateway.ProbeError("offline")):
            instance.cycle()
        group = instance.controller.groups[1]
        self.assertEqual(group["ipList"][0]["ip"], gateway.PLACEHOLDER)
        self.assertEqual(instance.state["cache"], {})

    def test_outage_preserves_unexpired_cached_bans_across_restart(self):
        gateway.save_json(self.state_path, {"cache": {"1.1.1.1": {"until": 1100, "id": 1}}})
        instance = self.instance(True)
        self.install_owned(instance, ["1.1.1.1"])
        with patch.object(instance, "snapshot", side_effect=gateway.ProbeError("offline")):
            instance.cycle()
        self.assertEqual(self.mutations(instance), [])
        self.assertIn("1.1.1.1", instance.state["cache"])

    def test_rejects_custom_acl_mode_before_any_mutation(self):
        instance = self.instance(True)
        instance.controller.mode = 1
        with self.assertRaises(gateway.ProbeError):
            instance.cycle()
        self.assertEqual(self.mutations(instance), [])

    def test_refuses_modified_direction_group_identity_and_shared_group(self):
        for change in ("direction", "identity", "shared"):
            with self.subTest(change=change):
                instance = self.instance(True)
                self.install_owned(instance)
                if change == "direction":
                    instance.controller.rules[0]["direction"]["lanToWan"] = True
                elif change == "identity":
                    instance.controller.groups[1]["name"] = "User group"
                else:
                    instance.controller.rules.append({"id": "unrelated", "sourceIds": ["managed-group"]})
                with self.fresh_snapshot(instance, [decision("1.1.1.1")]):
                    with self.assertRaises(gateway.ProbeError):
                        instance.cycle()
                self.assertEqual(self.mutations(instance), [])

    def test_manual_rule_disable_is_respected(self):
        instance = self.instance(True)
        self.install_owned(instance, enabled=False)
        with self.fresh_snapshot(instance, [decision("1.1.1.1")]):
            instance.cycle()
        self.assertFalse(instance.controller.rules[0]["status"])
        self.assertFalse(any(call[0] == "PUT" for call in self.mutations(instance)))

    def test_cleanup_clears_only_owned_group(self):
        instance = self.instance(True)
        self.install_owned(instance, ["1.1.1.1"])
        instance.clear()
        self.assertEqual(instance.controller.groups[1]["ipList"][0]["ip"], gateway.PLACEHOLDER)
        self.assertEqual(len(self.mutations(instance)), 1)

    def test_no_empty_or_unrestricted_source_group_can_be_used(self):
        for group_id in ("", "any"):
            with self.assertRaises(gateway.ProbeError):
                gateway.acl_payload(group_id, "any", ["wan-1"], True)

    def test_bad_duration_does_not_replace_existing_cache(self):
        with self.assertRaises(gateway.ProbeError):
            gateway.decision_cache([decision("1.1.1.1", duration="invalid")], [], 1000)
        self.assertAlmostEqual(gateway.duration_seconds("2h3m4.5s"), 7384.5)
        self.assertEqual(gateway.duration_seconds("-1s"), 0)

    def test_snapshot_requests_local_origins_and_filters_again_in_process(self):
        instance = self.instance()
        payload = [decision("1.1.1.1"), decision("2.2.2.2", origin="CAPI")]
        with patch.object(gateway, "build_opener") as factory:
            factory.return_value.open.return_value = io.BytesIO(json.dumps(payload).encode())
            instance.snapshot([])
            request = factory.return_value.open.call_args.args[0]
        query = parse_qs(urlsplit(request.full_url).query)
        self.assertEqual(query["origins"], ["crowdsec,cscli"])
        self.assertEqual(query["type"], ["ban"])
        self.assertEqual(set(instance.state["cache"]), {"1.1.1.1"})

    def test_invalid_snapshot_does_not_clear_good_cached_bans(self):
        instance = self.instance()
        previous = {"1.1.1.1": {"id": 1, "until": 1100}}
        instance.state["cache"] = copy.deepcopy(previous)
        with patch.object(gateway, "build_opener") as factory:
            factory.return_value.open.return_value = io.BytesIO(b'{}')
            with self.assertRaises(gateway.ProbeError):
                instance.snapshot([])
        self.assertEqual(instance.state["cache"], previous)

    def test_successful_empty_snapshot_removes_previous_bans(self):
        instance = self.instance()
        instance.state["cache"] = {"1.1.1.1": {"id": 1, "until": 1100}}
        with patch.object(gateway, "build_opener") as factory:
            factory.return_value.open.return_value = io.BytesIO(b'null')
            instance.snapshot([])
        self.assertEqual(instance.state["cache"], {})

    def test_compose_validation_uses_standalone_project(self):
        with patch.object(setup, "docker") as docker:
            setup.install_compose()
        docker.assert_called_once_with("compose", "config", "--quiet", capture=True)

    def test_enable_provisions_disabled_rule_before_populating_and_enabling(self):
        config = settings()
        instance = gateway.Gateway(config, self.client, self.key, self.state_path)
        path = self.root / "settings.json"
        with patch.object(setup, "SETTINGS", path), patch.object(setup, "docker"), \
                patch.object(setup, "host_gateway", return_value=instance), \
                self.fresh_snapshot(instance, [decision("1.1.1.1")]):
            setup.enable(config)
        mutations = self.mutations(instance)
        self.assertEqual([call[0] for call in mutations], ["POST", "POST", "PATCH", "PUT"])
        self.assertEqual(mutations[0][2]["ipList"][0]["ip"], gateway.PLACEHOLDER)
        self.assertFalse(mutations[1][2]["status"])
        self.assertTrue(mutations[-1][2]["status"])
        self.assertTrue(json.loads(path.read_text())["apply"])

    def test_failed_activation_rolls_back_to_disabled_rule_and_empty_group(self):
        config = settings()
        instance = gateway.Gateway(config, self.client, self.key, self.state_path)
        instance.controller.fail_enable = True
        path = self.root / "settings.json"
        with patch.object(setup, "SETTINGS", path), patch.object(setup, "docker"), \
                patch.object(setup, "host_gateway", return_value=instance), \
                self.fresh_snapshot(instance, [decision("1.1.1.1")]):
            with self.assertRaises(gateway.ProbeError):
                setup.enable(config)
        self.assertFalse(json.loads(path.read_text())["apply"])
        self.assertFalse(instance.controller.rules[0]["status"])
        self.assertEqual(instance.controller.groups[1]["ipList"][0]["ip"], gateway.PLACEHOLDER)

    def test_bootstrap_does_not_append_after_new_unreviewed_acl(self):
        config = settings()
        instance = gateway.Gateway(config, self.client, self.key, self.state_path)
        instance.controller.rules.append({"id": "existing", "description": "User permit"})
        with patch.object(setup, "SETTINGS", self.root / "settings.json"), patch.object(setup, "docker"), \
                patch.object(setup, "host_gateway", return_value=instance), self.fresh_snapshot(instance, []):
            with self.assertRaises(gateway.ProbeError):
                setup.enable(config)
        self.assertEqual(self.mutations(instance), [])

    def test_provisioning_recovers_a_previously_created_disabled_rule(self):
        config = settings()
        config.update(group_id="managed-group", wan_ids=["wan-1"])
        instance = gateway.Gateway(config, self.client, self.key, self.state_path)
        self.install_owned(instance, enabled=False)
        with patch.object(setup, "SETTINGS", self.root / "settings.json"), patch.object(setup, "docker"), \
                patch.object(setup, "host_gateway", return_value=instance), self.fresh_snapshot(instance, []):
            setup.enable(config)
        self.assertTrue(instance.controller.rules[0]["status"])
        self.assertFalse(any(call[0] == "POST" for call in self.mutations(instance)))


if __name__ == "__main__":
    unittest.main()
