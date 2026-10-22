"""Mocked Direct Mode coverage for DependencyPolicyAttestor."""

import json
import pytest


RAW_URL = "https://raw.githubusercontent.com/acme/dependency-demo/main/manifest.json"
ISSUE_URL = "https://api.github.com/repos/acme/dependency-demo/issues/7"
POLICY = "Manifest must use an approved license and pin the reviewed dependency set."


@pytest.fixture
def attestor(direct_vm, direct_deploy):
    direct_vm.strict_mocks = True
    direct_vm.check_pickling = True
    return direct_deploy("contracts/dependency_policy_attestor.py", sdk_version="v0.2.16")


def mock_review(vm, body='{"requests": [{"name": "httpx", "license": "MIT"}]}'):
    vm.mock_web(r"https://raw\.githubusercontent\.com/acme/dependency-demo/main/manifest\.json$", {"status": 200, "body": body})
    vm.mock_web(r"https://api\.github\.com/repos/acme/dependency-demo/issues/7$", {"status": 200, "body": json.dumps({"number": 7, "title": "Policy evidence", "body": "The manifest is reviewed.", "state": "closed"})})
    vm.mock_llm(r"(?s).*audit one public dependency manifest.*", json.dumps({"decision": "COMPLIANT", "rationale": "Mocked policy review."}))


def test_create_and_assess(attestor, direct_vm):
    audit_id = attestor.create_audit("acme", "dependency-demo", "main", "manifest.json", POLICY, 7)
    assert audit_id == "0"
    assert attestor.get_evidence_urls(audit_id)["manifest"] == RAW_URL
    mock_review(direct_vm)
    attestor.assess_audit(audit_id)
    audit = attestor.get_audit(audit_id)
    assert (audit.status, audit.decision) == ("ASSESSED", "COMPLIANT")
    assert len(audit.manifest_digest) == 64


def test_validator_rejects_changed_manifest(attestor, direct_vm):
    audit_id = attestor.create_audit("acme", "dependency-demo", "main", "manifest.json", POLICY, 7)
    mock_review(direct_vm)
    attestor.assess_audit(audit_id)
    direct_vm.clear_mocks()
    mock_review(direct_vm, '{"requests": [{"name": "httpx", "license": "GPL-3.0"}]}')
    assert direct_vm.run_validator(index=0) is False


def test_finalize_requires_assessment(attestor, direct_vm):
    audit_id = attestor.create_audit("acme", "dependency-demo", "main", "manifest.json", POLICY, 7)
    with direct_vm.expect_revert("cannot be finalized"):
        attestor.finalize_audit(audit_id)
