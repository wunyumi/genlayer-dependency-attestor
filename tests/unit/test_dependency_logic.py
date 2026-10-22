"""Fast local checks for the dependency policy state machine."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


class FakeAddress:
    as_hex = "0x" + "1" * 40


class FakeContract:
    def __new__(cls):
        instance = super().__new__(cls)
        instance.audits = {}
        return instance


class FakeResponse:
    def __init__(self, payload):
        self.status_code = 200
        self.body = payload.encode("utf-8")


def load_contract():
    identity = lambda value: value
    public = types.SimpleNamespace(write=identity, view=identity)

    def get(url):
        import json
        if "raw.githubusercontent.com" in url:
            return FakeResponse('{"requests": [{"name": "httpx", "license": "MIT"}]}')
        return FakeResponse(json.dumps({"number": 7, "title": "Policy evidence", "body": "The manifest is reviewed.", "state": "closed"}))

    def prompt(_text, response_format=None):
        return {"decision": "COMPLIANT", "rationale": "The manifest satisfies the policy."}

    class Return:
        def __init__(self, calldata):
            self.calldata = calldata

    fake = types.ModuleType("genlayer")
    fake.allow_storage = identity
    fake.Address = FakeAddress
    fake.u256 = int
    fake.TreeMap = dict
    fake.gl = types.SimpleNamespace(
        Contract=FakeContract,
        public=public,
        nondet=types.SimpleNamespace(web=types.SimpleNamespace(get=get), exec_prompt=prompt),
        vm=types.SimpleNamespace(UserError=Exception, Return=Return, run_nondet_unsafe=lambda leader, validator: leader()),
        message=types.SimpleNamespace(sender_address=FakeAddress()),
    )
    path = Path(__file__).resolve().parents[2] / "contracts" / "dependency_policy_attestor.py"
    spec = importlib.util.spec_from_file_location("dependency_attestor_local", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"genlayer": fake, spec.name: module}):
        spec.loader.exec_module(module)
    return module


class DependencyAttestorTests(unittest.TestCase):
    def setUp(self):
        self.module = load_contract()
        self.contract = self.module.DependencyPolicyAttestor()
        self.policy = "Manifest must use an approved license and pin the reviewed dependency set."

    def create(self):
        return self.contract.create_audit("acme", "dependency-demo", "main", "manifest.json", self.policy, 7)

    def test_bounded_source_and_policy(self):
        self.assertEqual(self.create(), "0")
        self.assertEqual(self.contract.get_audit_count(), 1)
        self.assertIn("raw.githubusercontent.com/acme/dependency-demo/main/manifest.json", self.contract.get_evidence_urls("0")["manifest"])
        with self.assertRaisesRegex(Exception, "unsupported character"):
            self.contract.create_audit("acme", "dependency/demo", "main", "manifest.json", self.policy, 7)
        with self.assertRaisesRegex(Exception, "20 to 700"):
            self.contract.create_audit("acme", "dependency-demo", "main", "manifest.json", "short", 7)

    def test_assess_and_finalize(self):
        audit_id = self.create()
        self.contract.assess_audit(audit_id)
        audit = self.contract.get_audit(audit_id)
        self.assertEqual((audit.status, audit.decision), ("ASSESSED", "COMPLIANT"))
        self.assertEqual(len(audit.manifest_digest), 64)
        self.contract.finalize_audit(audit_id)
        self.assertEqual(self.contract.get_audit(audit_id).status, "FINAL")

    def test_challenge_is_separate_from_evidence_issue(self):
        audit_id = self.create()
        self.contract.assess_audit(audit_id)
        with self.assertRaisesRegex(Exception, "must differ"):
            self.contract.challenge_audit(audit_id, 7)
        self.contract.challenge_audit(audit_id, 8)
        self.assertEqual(self.contract.get_audit(audit_id).status, "CHALLENGED")


if __name__ == "__main__":
    unittest.main()
