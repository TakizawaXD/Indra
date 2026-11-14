"""
GOJO INFINITY SECURITY ∞ — PROTOCOLO DEFINITIVO: HOLLOW PURPLE (虚式「茈」)
Converges BLUE (Reconnaissance) and RED (Offensive Testing) into PURPLE (Correlation & Containment),
governed by INFINITY (Shield) and verified by SIX EYES.
"Nine Ropes. Polarized Light. Crow and Shomyo. The Gap Between Within and Without: Hollow Purple."
"""

import ipaddress
from typing import Dict, Any, Optional

from core.timeutils import utcnow

from core.logger import logger
from core.permissions import TargetAuthorizer
from core.event_engine import event_bus, EventType, SecurityEventPayload
from techniques.blue.recon import blue_recon
from techniques.red.operations import red_operations
from techniques.purple.intelligence import purple_intel
from techniques.infinity.shield import infinity_shield
from core.orchestrator import six_eyes

class HollowPurpleProtocol:
    """
    Automated unified protocol orchestrating Blue, Red, Purple, Infinity, and Six Eyes.
    """

    @classmethod
    async def execute(cls, target: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes the 5-phase Hollow Purple cycle:
        Phase 1: BLUE (Surface Reconnaissance)
        Phase 2: RED (Controlled Validation)
        Phase 3: PURPLE (Correlation & Risk Analysis)
        Phase 4: INFINITY (Shield Reinforcement)
        Phase 5: SIX EYES (Final Cognitive Verification & Report)
        """
        # Strict scope verification
        TargetAuthorizer.assert_authorized(target, project_id=project_id)

        logger.info("================================================================")
        logger.info(f"[*] INITIATING PROTOCOL: HOLLOW PURPLE on target: {target}")
        logger.info("================================================================")

        event_bus.emit(SecurityEventPayload(
            event_type=EventType.HOLLOW_PURPLE_TRIGGERED,
            origin_module="SIX_EYES",
            category="PROTOCOL",
            severity="HIGH",
            description=f"Hollow Purple Protocol initiated on target: {target}",
            target=target
        ))

        results: Dict[str, Any] = {
            "target": target,
            "timestamp": utcnow().isoformat(),
            "phases": {}
        }

        # -------------------------------------------------------------
        # STEP 1: BLUE CORE — Surface Reconnaissance
        # -------------------------------------------------------------
        logger.info("[HOLLOW PURPLE] Phase 1: BLUE CORE (Expanding Reconnaissance)...")
        ports = [21, 22, 80, 443, 8000, 8080]
        blue_results = await blue_recon.scan_target_ports_and_save(target, project_id=project_id, ports=ports)
        web_recon = None
        web_target = None
        open_ports = {p["port"] for p in blue_results}
        host_part = f"[{target}]" if cls._is_ipv6(target) else target
        for port, scheme in ((443, "https"), (80, "http"), (8080, "http"), (8000, "http")):
            if port in open_ports:
                default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
                web_target = f"{scheme}://{host_part}" if default else f"{scheme}://{host_part}:{port}"
                break
        if web_target:
            web_recon = await blue_recon.audit_web_target(web_target, project_id=project_id)

        results["phases"]["blue_recon"] = {
            "open_ports": blue_results,
            "web_recon": web_recon
        }

        # -------------------------------------------------------------
        # STEP 2: RED CORE — Controlled Offensive Validation
        # -------------------------------------------------------------
        logger.info("[HOLLOW PURPLE] Phase 2: RED CORE (Testing Security Controls)...")
        red_results = {}
        if web_target and web_recon and web_recon.get("status_code"):
            http_audit = await red_operations.audit_http_methods(web_target, project_id=project_id)
            red_results["http_methods"] = http_audit

        results["phases"]["red_operations"] = red_results

        # -------------------------------------------------------------
        # STEP 3: CONVERGENCE — PURPLE Correlation & Risk Modeling
        # -------------------------------------------------------------
        logger.info("[HOLLOW PURPLE] Phase 3: CONVERGENCE (Synthesizing Purple Intelligence)...")
        risk_index = purple_intel.calculate_risk_index()
        report_data = purple_intel.generate_unified_security_report(
            project_name=f"Hollow_Purple_{target}",
            report_type="hollow_purple_audit"
        )
        results["phases"]["purple_correlation"] = {
            "risk_index": risk_index,
            "report": report_data
        }

        # -------------------------------------------------------------
        # STEP 4: INFINITY FORTIFICATION — Active Containment
        # -------------------------------------------------------------
        logger.info("[HOLLOW PURPLE] Phase 4: INFINITY SHIELD FORTIFICATION...")
        shield_rules = infinity_shield.get_active_rules()
        results["phases"]["infinity_shield"] = {
            "active_rules_count": len(shield_rules),
            "protection_posture": "REINFORCED"
        }

        # -------------------------------------------------------------
        # STEP 5: SIX EYES VERIFICATION — Final Synthesis
        # -------------------------------------------------------------
        logger.info("[HOLLOW PURPLE] Phase 5: SIX EYES COGNITIVE EVALUATION...")
        correlation = six_eyes.analyze_event_correlation()
        results["phases"]["six_eyes_synthesis"] = correlation

        event_bus.emit(SecurityEventPayload(
            event_type=EventType.HOLLOW_PURPLE_CONVERGENCE,
            origin_module="SIX_EYES",
            category="PROTOCOL",
            severity="INFO",
            description=f"Hollow Purple convergence completed. Target Posture: {correlation['posture_assessment']}",
            target=target,
            evidence={"risk_level": risk_index["risk_level"]}
        ))

        logger.info("================================================================")
        logger.info(f"[+] HOLLOW PURPLE COMPLETE: Risk Level: {risk_index['risk_level']} | Posture: {correlation['posture_assessment']}")
        logger.info("================================================================")

        return results

    @staticmethod
    def _is_ipv6(target: str) -> bool:
        try:
            return ipaddress.ip_address(target).version == 6
        except ValueError:
            return False
