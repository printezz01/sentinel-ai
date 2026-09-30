"""Offline regression tests: no provider calls, remote scans, or real email."""
import asyncio
from pathlib import Path
import os
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock, AsyncMock

# Prevent the local .env from enabling external services during tests.
for key in ("SUPABASE_URL", "SUPABASE_SERVICE_KEY", "GROQ_API_KEY", "GOOGLE_API_KEY",
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "VOYAGE_API_KEY", "SMTP_USER", "SMTP_PASS"):
    os.environ[key] = ""

from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import tools, db, engine, agent, scheduler, email_sender
from app.main import app
from app.validation import validate_target


def clean_nikto(command, **kwargs):
    Path(command[command.index("-o") + 1]).write_text('[{"vulnerabilities": []}]', encoding="utf-8")
    return SimpleNamespace(returncode=0, stdout="Nikto console output")


class RegressionTests(unittest.TestCase):
    def setUp(self):
        resolver = patch.object(tools, "scanner_command", side_effect=lambda name: [name])
        resolver.start()
        self.addCleanup(resolver.stop)
        for store in (db._mem_sessions, db._mem_findings, db._mem_chain_edges,
                      db._mem_risk_scores, db._mem_owasp_mappings):
            store.clear()
        self.scan_id = db.new_uuid()
        db.create_scan_session(self.scan_id, "http://localhost:4280", "url")

    def test_target_policy(self):
        for target, kind in [("127.0.0.1", "ip"), ("192.168.1.0/24", "subnet"),
                             ("http://localhost:4280", "url")]:
            validate_target(target, kind)
        for target, kind in [("8.8.8.8", "ip"), ("169.254.169.254", "ip"),
                             ("file://localhost/etc/passwd", "url"),
                             ("http://localhost@evil.example", "url"),
                             ("https://github.com/OWASP/PyGoat/extra", "github")]:
            with self.subTest(target=target), self.assertRaises(HTTPException):
                validate_target(target, kind)

    def test_requested_targets_at_api_boundary(self):
        cases = [
            ("https://banshivaidik.com/", "url", 200),
            ("https://github.com/printezz01/GHOSTCUE", "github", 200),
            ("http://localhost", "url", 200),
            ("192.168.1.0/24", "subnet", 200),
            ("8.8.8.8", "ip", 400),
            ("8.8.8.0/24", "subnet", 400),
        ]
        with patch("app.main._run_scan_background", new_callable=AsyncMock) as run, TestClient(app) as client:
            for target, kind, expected in cases:
                with self.subTest(target=target):
                    run.reset_mock()
                    response = client.post("/scan", json={"target": target, "target_type": kind})
                    self.assertEqual(response.status_code, expected, response.text)
                    if expected == 200:
                        run.assert_awaited_once_with(response.json()["scan_id"], target, kind)
                    else:
                        run.assert_not_called()

    def test_new_public_targets_reach_scanners(self):
        with patch.object(tools.subprocess, "run", side_effect=clean_nikto) as run:
            self.assertEqual(tools.scan_web("https://banshivaidik.com/", self.scan_id), [])
            self.assertTrue(run.called)
        for fn, output in [(tools.scan_code, '{"results": []}'), (tools.scan_secrets, '')]:
            with patch.object(tools.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)) as run:
                self.assertEqual(fn("https://github.com/printezz01/GHOSTCUE", self.scan_id), [])
                self.assertEqual(run.call_args_list[0].args[0][:2], ["git", "clone"])
                self.assertIn("https://github.com/printezz01/GHOSTCUE", run.call_args_list[0].args[0])

    def test_malformed_targets_and_network_boundaries(self):
        for target, kind in [("https://", "url"), ("https://bad host", "url"),
                             ("http://example.com:99999", "url"), ("http://[broken", "url"),
                             ("https://github.com.evil.test/a/b", "github"),
                             ("https://github.com/a", "github"),
                             ("https://github.com/a/b?x=1", "github"),
                             ("172.15.1.1", "ip"), ("192.168.0.0/15", "subnet")]:
            with self.subTest(target=target), self.assertRaises(HTTPException):
                validate_target(target, kind)
        for target, kind in [("localhost", "ip"), ("192.168.1.20", "ip"),
                             ("10.0.0.0/24", "subnet"), ("https://example.com", "url"),
                             ("http://example.com", "url"), ("https://printezz.in", "url"),
                             ("https://github.com/OWASP/NodeGoat", "github"),
                             ("https://github.com/OWASP/PyGoat.git", "github")]:
            with self.subTest(target=target):
                validate_target(target, kind)

    def test_tool_boundary_rejects_before_execution(self):
        with patch.object(tools.subprocess, "run") as run:
            with self.assertRaises(HTTPException):
                tools.scan_web("file:///etc/passwd", self.scan_id)
            run.assert_not_called()

    def test_empty_network_is_clean(self):
        with patch("nmap.PortScanner") as scanner:
            scanner.return_value.all_hosts.return_value = []
            self.assertEqual(tools.scan_network("127.0.0.1", self.scan_id), [])
        self.assertEqual(db.get_findings(self.scan_id), [])

    def test_empty_web_is_clean(self):
        with patch.object(tools.subprocess, "run", side_effect=clean_nikto):
            self.assertEqual(tools.scan_web("http://localhost", self.scan_id), [])
        self.assertEqual(db.get_findings(self.scan_id), [])

    def test_scanner_failure_never_inserts_fixtures(self):
        with patch.object(tools.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(RuntimeError):
                tools.scan_web("http://localhost", self.scan_id)
        self.assertEqual(db.get_findings(self.scan_id), [])

    def test_nonzero_exit_is_failure(self):
        with patch.object(tools.subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout='{}')):
            with self.assertRaises(RuntimeError):
                tools.scan_web("http://localhost", self.scan_id)

    def test_empty_code_and_secrets_are_clean(self):
        for fn, output in [(tools.scan_code, '{"results": []}'), (tools.scan_secrets, '')]:
            with patch.object(tools.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)):
                self.assertEqual(fn("https://github.com/OWASP/PyGoat", self.scan_id), [])

    def test_cve_failure_does_not_invent_cves(self):
        with patch.object(tools, "_get_cached_cves", return_value=None), patch.object(tools.httpx, "get", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                tools.lookup_cve("example", "1")

    def test_camera_brand_is_not_proof_of_vulnerability(self):
        with patch.object(tools.httpx, "get", return_value=SimpleNamespace(headers={}, text="Hikvision")):
            finding = tools.scan_cctv("127.0.0.1", self.scan_id)[0]
        self.assertEqual(finding["severity"], "info")
        self.assertIsNone(finding["cve_id"])
        self.assertEqual(finding["gives"], "")

    def test_empty_graph_is_empty(self):
        self.assertEqual(engine.build_attack_chain(self.scan_id), {"nodes": [], "edges": []})

    def test_graph_rebuild_is_idempotent(self):
        db._mem_findings[self.scan_id] = [
            {"id": "a", "title": "A", "gives": "access", "requires": ""},
            {"id": "b", "title": "B", "gives": "", "requires": "access"}]
        engine.build_attack_chain(self.scan_id)
        engine.build_attack_chain(self.scan_id)
        self.assertEqual(len(db.get_chain_edges(self.scan_id)), 1)

    def test_chain_penalty_requires_connected_simple_path(self):
        for pairs, expected in [([("a", "b"), ("c", "d"), ("e", "f")], 0),
                                ([("a", "b")] * 3, 0),
                                ([("a", "b"), ("b", "a"), ("b", "c")], 0),
                                ([("a", "b"), ("b", "c"), ("c", "d")], 10)]:
            db._mem_chain_edges[self.scan_id] = [{"from_finding": a, "to_finding": b} for a, b in pairs]
            self.assertEqual(engine.calculate_risk_score(self.scan_id)["breakdown"]["chain_deduction"], expected)

    def test_recipient_is_honored(self):
        with patch.object(email_sender, "SMTP_USER", "sender@example.test"), patch.object(email_sender, "SMTP_PASS", "test"), patch.object(email_sender.smtplib, "SMTP_SSL") as smtp:
            self.assertTrue(email_sender.send_report_email(b"pdf", self.scan_id, "localhost", 0, 100, recipient="subscriber@example.test"))
            msg = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
            self.assertEqual(msg["To"], "subscriber@example.test")

    def test_failed_scheduled_scan_sends_no_email(self):
        async def fail(scan_id, *args):
            db.update_scan_status(scan_id, "failed")
        with patch.object(agent, "run_agent", side_effect=fail), patch.object(email_sender, "send_report_email") as send:
            asyncio.run(scheduler._run_scheduled_scan("sub", "localhost", "ip", "subscriber@example.test"))
            send.assert_not_called()

    def test_deterministic_scan_does_not_block_event_loop(self):
        async def run():
            task = asyncio.create_task(agent.run_agent(self.scan_id, "http://localhost", "url"))
            await asyncio.sleep(0.03)
            self.assertFalse(task.done(), "Blocking scanner ran on the event loop")
            await task
        def slow_scan(*args):
            time.sleep(0.15)
            return []
        with patch.object(agent, "scan_web", side_effect=slow_scan):
            asyncio.run(run())
        self.assertEqual(db.get_scan_session(self.scan_id)["status"], "complete")

    def test_api_pipeline_with_controlled_scanner(self):
        with patch.object(tools.subprocess, "run", side_effect=clean_nikto), TestClient(app) as client:
            response = client.post("/scan", json={"target": "http://localhost", "target_type": "url"})
            self.assertEqual(response.status_code, 200)
            scan_id = response.json()["scan_id"]
            self.assertEqual(client.get(f"/scan/{scan_id}/status").json()["status"], "complete")
            self.assertEqual(client.get(f"/scan/{scan_id}/dashboard").json()["findings"], [])
            self.assertEqual(client.get(f"/scan/{scan_id}/chain").json(), {"nodes": [], "edges": []})
            self.assertEqual(client.post("/subscribe", json={"target": "localhost", "target_type": "ip", "interval_minutes": 0}).status_code, 422)

    def test_api_scanner_failure_is_failed(self):
        with patch.object(tools.subprocess, "run", side_effect=FileNotFoundError), TestClient(app) as client:
            scan_id = client.post("/scan", json={"target": "http://localhost", "target_type": "url"}).json()["scan_id"]
            self.assertEqual(client.get(f"/scan/{scan_id}/status").json()["status"], "failed")
            self.assertEqual(client.get(f"/scan/{scan_id}/dashboard").json()["findings"], [])

    def test_agent_tool_errors_are_not_converted_to_success(self):
        from langgraph.prebuilt import ToolNode
        from langchain_core.messages import AIMessage
        node = ToolNode(agent._create_langchain_tools(self.scan_id), handle_tool_errors=False)
        message = AIMessage(content="", tool_calls=[{"name": "tool_scan_web", "args": {"url": "http://localhost"}, "id": "call1", "type": "tool_call"}])
        with patch.object(tools.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(RuntimeError):
                asyncio.run(node.ainvoke({"messages": [message]}))

    def test_report_requires_complete_scan(self):
        with TestClient(app) as client:
            self.assertEqual(client.get(f"/scan/{self.scan_id}/report").status_code, 409)
            db.update_scan_status(self.scan_id, "failed")
            self.assertEqual(client.get(f"/scan/{self.scan_id}/report").status_code, 409)

    def test_completed_scan_report_is_pdf(self):
        db.update_scan_status(self.scan_id, "complete")
        with TestClient(app) as client:
            response = client.get(f"/scan/{self.scan_id}/report")
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.content.startswith(b"%PDF"))

    def test_scheduled_scan_passes_recipient(self):
        async def complete(scan_id, *args):
            db.update_scan_status(scan_id, "complete")
        with patch.object(agent, "run_agent", side_effect=complete), patch.object(email_sender, "send_report_email", return_value=True) as send:
            asyncio.run(scheduler._run_scheduled_scan("sub", "localhost", "ip", "subscriber@example.test"))
            self.assertEqual(send.call_args.kwargs["recipient"], "subscriber@example.test")

    def test_agent_dependencies_import(self):
        from langgraph.prebuilt import create_react_agent
        from langchain_groq import ChatGroq
        from langchain_google_genai import ChatGoogleGenerativeAI
        from langchain_anthropic import ChatAnthropic
        import inspect
        self.assertIn("prompt", inspect.signature(create_react_agent).parameters)


if __name__ == "__main__":
    unittest.main()
