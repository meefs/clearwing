"""Tests for cryptographic commitment log (spec 014)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from clearwing.sourcehunt.commitment import (
    Commitment,
    CommitmentLog,
    CommitmentType,
    generate_commitment,
    verify_commitment,
)


# --- Commitment generation tests ---------------------------------------------


class TestGenerateCommitment:
    def test_sha3_224_digest_length(self):
        c = generate_commitment("f1", "some document text")
        assert len(c.digest) == 56  # SHA-3-224 = 28 bytes = 56 hex chars

    def test_commitment_type_report(self):
        c = generate_commitment("f1", "doc", commitment_type=CommitmentType.REPORT)
        assert c.commitment_type == "report"

    def test_commitment_type_poc(self):
        c = generate_commitment("f1", "doc", commitment_type=CommitmentType.POC)
        assert c.commitment_type == "poc"

    def test_commitment_type_exploit(self):
        c = generate_commitment("f1", "doc", commitment_type=CommitmentType.EXPLOIT)
        assert c.commitment_type == "exploit"

    def test_includes_metadata(self):
        c = generate_commitment(
            "f1", "doc",
            project="https://github.com/test/repo",
            severity="critical",
            cwe="CWE-787",
        )
        assert c.project == "https://github.com/test/repo"
        assert c.severity == "critical"
        assert c.cwe == "CWE-787"

    def test_algorithm_field(self):
        c = generate_commitment("f1", "doc")
        assert c.algorithm == "sha3-224"

    def test_committed_at_populated(self):
        c = generate_commitment("f1", "doc")
        assert c.committed_at
        assert "T" in c.committed_at  # ISO 8601 format


# --- Verification tests ------------------------------------------------------


class TestVerifyCommitment:
    def test_matching_document(self):
        doc = "the exact original document"
        import hashlib
        digest = hashlib.sha3_224(doc.encode()).hexdigest()
        assert verify_commitment(doc, digest) is True

    def test_mismatched_document(self):
        import hashlib
        doc = "original"
        digest = hashlib.sha3_224(doc.encode()).hexdigest()
        assert verify_commitment("different document", digest) is False

    def test_empty_document(self):
        import hashlib
        doc = ""
        digest = hashlib.sha3_224(doc.encode()).hexdigest()
        assert verify_commitment("", digest) is True


# --- CommitmentLog tests -----------------------------------------------------


class TestCommitmentLog:
    def test_commit_and_retrieve(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            c = generate_commitment("f1", "test document")
            log.commit(c)
            results = log.get_commitments()
            assert len(results) == 1
            assert results[0].finding_id == "f1"
            assert results[0].digest == c.digest

    def test_commit_finding_creates_report(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            finding = {
                "id": "f1",
                "file": "test.c",
                "line_number": 42,
                "cwe": "CWE-787",
                "severity": "critical",
                "description": "Heap buffer overflow",
                "evidence_level": "root_cause_explained",
            }
            commitments = log.commit_finding(finding)
            assert len(commitments) == 1
            assert commitments[0].commitment_type == "report"

    def test_commit_finding_with_poc(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            finding = {
                "id": "f2",
                "file": "test.c",
                "description": "overflow",
                "poc": "AAAA" * 100,
            }
            commitments = log.commit_finding(finding)
            assert len(commitments) == 2
            types = {c.commitment_type for c in commitments}
            assert "report" in types
            assert "poc" in types

    def test_commit_finding_with_exploit(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            finding = {
                "id": "f3",
                "file": "test.c",
                "description": "overflow",
                "poc": "crash_input",
                "exploit": "#!/usr/bin/env python3\nimport pwn...",
            }
            commitments = log.commit_finding(finding)
            assert len(commitments) == 3
            types = {c.commitment_type for c in commitments}
            assert types == {"report", "poc", "exploit"}

    def test_get_commitments_filters_by_id(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            log.commit(generate_commitment("f1", "doc1"))
            log.commit(generate_commitment("f2", "doc2"))
            log.commit(generate_commitment("f1", "doc3", commitment_type=CommitmentType.POC))

            results = log.get_commitments(finding_id="f1")
            assert len(results) == 2
            assert all(r.finding_id == "f1" for r in results)

    def test_log_append_only(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            log.commit(generate_commitment("f1", "doc1"))
            log.commit(generate_commitment("f2", "doc2"))
            log.commit(generate_commitment("f3", "doc3"))
            results = log.get_commitments()
            assert len(results) == 3

    def test_empty_log_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            assert log.get_commitments() == []

    def test_commit_finding_passes_project(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            finding = {"id": "f1", "description": "test", "severity": "high"}
            commitments = log.commit_finding(
                finding, project="https://github.com/test/repo",
            )
            assert commitments[0].project == "https://github.com/test/repo"


# --- Public table tests ------------------------------------------------------


class TestFormatPublicTable:
    def test_markdown_table(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            log.commit(generate_commitment(
                "f1", "doc",
                project="https://github.com/test/repo",
                severity="critical", cwe="CWE-787",
            ))
            output = log.format_public_table(fmt="markdown")
            assert "| Date |" in output
            assert "SHA-3-224" in output
            assert "critical" in output
            assert "CWE-787" in output

    def test_json_table(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            log.commit(generate_commitment("f1", "doc", severity="high"))
            output = log.format_public_table(fmt="json")
            data = json.loads(output)
            assert isinstance(data, list)
            assert len(data) == 1
            assert data[0]["severity"] == "high"
            assert "sha3_224" in data[0]

    def test_empty_log_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            output = log.format_public_table()
            assert "No commitments" in output

    def test_empty_log_json(self):
        with tempfile.TemporaryDirectory() as td:
            log = CommitmentLog(log_path=Path(td) / "commitments.jsonl")
            output = log.format_public_table(fmt="json")
            assert output == "[]"


# --- CLI registration tests --------------------------------------------------


class TestCLIRegistration:
    def test_verify_subcommand(self):
        import argparse
        from clearwing.ui.commands import disclose

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        disclose.add_parser(subs)
        args = parser.parse_args(
            ["disclose", "verify", "finding-001", "--document", "report.json"],
        )
        assert args.disclose_action == "verify"
        assert args.finding_id == "finding-001"
        assert args.document == "report.json"

    def test_commitments_subcommand(self):
        import argparse
        from clearwing.ui.commands import disclose

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        disclose.add_parser(subs)
        args = parser.parse_args(["disclose", "commitments"])
        assert args.disclose_action == "commitments"

    def test_commitments_format_flag(self):
        import argparse
        from clearwing.ui.commands import disclose

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        disclose.add_parser(subs)
        args = parser.parse_args(
            ["disclose", "commitments", "--format", "json"],
        )
        assert args.commitment_format == "json"
