"""
GOJO INFINITY SECURITY ∞ — ATTACK LAB RUNTIME & WEB SIMULATOR
In-memory safe execution sandbox for red team tests and defense validation.
"""

import re
from typing import Dict, Any, List
from laboratory.scenarios import LAB_SCENARIOS
from backend.database import SessionLocal, LaboratoryRun
from core.logger import logger

class AttackLabSimulator:
    """Safe simulation engine executing vulnerability tests without external risk."""

    @classmethod
    def test_sqli_endpoint(cls, user_input: str) -> Dict[str, Any]:
        """
        Simulates an insecure SQL query:
        SELECT * FROM relics WHERE name LIKE '%{user_input}%'
        """
        scenario = LAB_SCENARIOS["sqli_lab"]
        mock_data = scenario["mock_db"]

        # Check for typical SQL injection triggers
        is_sqli = bool(re.search(r"('|\-\-|union\s+select|\bor\b\s+1=1)", user_input, re.IGNORECASE))

        if is_sqli:
            # Simulated SQL injection bypass returns all records
            return {
                "status": "vulnerable",
                "simulated_query": f"SELECT * FROM relics WHERE name LIKE '%{user_input}%'",
                "records_returned": mock_data,
                "proof_of_concept": "SQL syntax alteration succeeded in returning all rows.",
                "scenario": scenario["title"]
            }
        else:
            # Standard sanitized search
            filtered = [r for r in mock_data if user_input.lower() in r["name"].lower()]
            return {
                "status": "normal",
                "simulated_query": f"SELECT * FROM relics WHERE name LIKE '%{user_input}%'",
                "records_returned": filtered,
                "scenario": scenario["title"]
            }

    @classmethod
    def test_xss_endpoint(cls, user_input: str) -> Dict[str, Any]:
        """Simulates reflection of user parameter without encoding."""
        scenario = LAB_SCENARIOS["xss_lab"]
        has_script = bool(re.search(r"<script.*?>|onerror=|javascript:", user_input, re.IGNORECASE))

        raw_output = f"<h1>Welcome, {user_input}!</h1>"

        return {
            "status": "vulnerable" if has_script else "safe",
            "reflected_html": raw_output,
            "vulnerability_detected": has_script,
            "scenario": scenario["title"]
        }

    @classmethod
    def test_auth_endpoint(cls, username: str, password_attempt: str) -> Dict[str, Any]:
        """Simulates authentication endpoint."""
        scenario = LAB_SCENARIOS["auth_lab"]
        accounts = scenario["weak_accounts"]

        if username in accounts and accounts[username] == password_attempt:
            return {
                "authenticated": True,
                "user": username,
                "warning": "Authenticated using weak default credential."
            }
        return {"authenticated": False, "error": "Invalid credentials"}

    @classmethod
    def record_lab_run(cls, scenario_id: str, payload_count: int, findings: Dict[str, Any]):
        """Persists laboratory execution records to SQLite."""
        try:
            with SessionLocal() as db:
                import json
                run = LaboratoryRun(
                    scenario_name=scenario_id,
                    status="completed",
                    simulated_target="localhost_attack_lab",
                    payload_count=payload_count,
                    findings_json=json.dumps(findings)
                )
                db.add(run)
                db.commit()
        except Exception as e:
            logger.error(f"Failed to record laboratory run: {e}")
