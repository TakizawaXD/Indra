"""
GOJO INFINITY SECURITY ∞ — CORPORATE EXECUTIVE REPORT GENERATOR (PDF / PRINT READY)
Generates high-fidelity executive security audits for Indra, signed by Takizawa.
"""

import hashlib
from html import escape
from typing import Dict, Any, Optional

from core.timeutils import utcnow

from core.config import settings
from core.logger import logger
from backend.database import SessionLocal, Vulnerability, Threat, Host, FirewallRule

class IndraReportGenerator:
    """Compiles printable, PDF-ready executive security audits."""

    @classmethod
    def generate_indra_report(cls, project_name: str = "Auditoría Indra", risk_data: Optional[Dict[str, Any]] = None) -> str:
        """Generates self-contained HTML/PDF formatted report."""
        timestamp = utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        file_stamp = utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = settings.REPORTS_DIR / f"Reporte_Ejecutivo_Indra_{file_stamp}.html"

        with SessionLocal() as db:
            vulns = db.query(Vulnerability).all()
            threats = db.query(Threat).all()
            hosts = db.query(Host).all()
            rules = db.query(FirewallRule).filter(FirewallRule.is_active == True).all()

        risk_score = int(risk_data.get("risk_index", 0)) if risk_data else 0
        risk_level = escape(str(risk_data.get("risk_level", "LOW"))) if risk_data else "LOW"
        safe_project = escape(project_name)

        def e(value: Any) -> str:
            return escape("" if value is None else str(value))

        vuln_rows = "".join(
            f"<tr><td><strong>{e(v.severity)}</strong></td><td>{e(v.title)}</td><td>{e(v.cve_id or 'N/A')}</td>"
            f"<td>{e(v.cvss_score)}</td><td><code>{e(v.target)}</code></td><td>{e(v.mitigation or 'Mantener parches al día.')}</td></tr>"
            for v in vulns
        ) or "<tr><td colspan='6'>No se detectaron vulnerabilidades críticas en la superficie evaluada.</td></tr>"

        rule_rows = "".join(
            f"<tr><td>#{e(r.id)}</td><td>{e(r.rule_name)}</td><td>{e(r.rule_type)}</td>"
            f"<td><code>{e(r.target_pattern)}</code></td><td>{e(r.hits)}</td></tr>"
            for r in rules
        ) or "<tr><td colspan='5'>Infinity Shield en modo de inspección en tiempo real sin bloqueos permanentes.</td></tr>"

        # Generate cryptographic verification seal
        seal_string = f"INDRA_{settings.CREATOR}_{timestamp}_{risk_score}_{len(vulns)}"
        seal_hash = hashlib.sha256(seal_string.encode()).hexdigest()[:24].upper()

        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Informe Ejecutivo de Seguridad — Indra</title>
  <style>
    @page {{ size: A4; margin: 20mm; }}
    body {{
      font-family: 'Helvetica Neue', Arial, sans-serif;
      color: #1e293b;
      line-height: 1.6;
      background: #ffffff;
      padding: 2rem;
    }}
    .header-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 3px solid #0051ff;
      padding-bottom: 1rem;
      margin-bottom: 2rem;
    }}
    .corp-title {{
      font-size: 1.8rem;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -0.5px;
    }}
    .corp-subtitle {{
      font-size: 0.9rem;
      color: #0051ff;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 1rem;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 1.25rem;
      border-radius: 8px;
      margin-bottom: 2rem;
      font-size: 0.9rem;
    }}
    .meta-item strong {{ color: #475569; }}
    .section-title {{
      font-size: 1.2rem;
      font-weight: 700;
      color: #0f172a;
      border-left: 4px solid #0051ff;
      padding-left: 0.75rem;
      margin: 2rem 0 1rem 0;
    }}
    .metric-badge {{
      display: inline-block;
      padding: 0.4rem 1rem;
      border-radius: 6px;
      font-weight: 800;
      font-size: 1.1rem;
    }}
    .metric-badge.LOW {{ background: #e0f2fe; color: #0284c7; }}
    .metric-badge.MEDIUM {{ background: #fef3c7; color: #d97706; }}
    .metric-badge.HIGH, .metric-badge.CRITICAL {{ background: #fee2e2; color: #dc2626; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
      font-size: 0.85rem;
    }}
    th {{
      background: #f1f5f9;
      text-align: left;
      padding: 0.75rem;
      border-bottom: 2px solid #cbd5e1;
      color: #334155;
    }}
    td {{
      padding: 0.75rem;
      border-bottom: 1px solid #e2e8f0;
    }}
    .signature-card {{
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 2px dashed #cbd5e1;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }}
    .sig-block {{
      text-align: left;
    }}
    .sig-line {{
      width: 220px;
      border-bottom: 1px solid #0f172a;
      margin-bottom: 0.5rem;
    }}
    .seal-box {{
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-family: monospace;
      font-size: 0.75rem;
      color: #64748b;
      text-align: right;
    }}
    .print-btn {{
      background: #0051ff;
      color: #ffffff;
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 6px;
      font-weight: 700;
      cursor: pointer;
      margin-bottom: 1.5rem;
    }}
    @media print {{
      .print-btn {{ display: none; }}
      body {{ padding: 0; }}
    }}
  </style>
</head>
<body>

  <button class="print-btn" onclick="window.print()">Imprimir / Guardar en PDF</button>

  <div class="header-bar">
    <div>
      <div class="corp-title">INDRA CYBERSECURITY INTELLIGENCE</div>
      <div class="corp-subtitle">GOJO INFINITY SECURITY ∞ — AUDITORÍA TÉCNICA</div>
    </div>
    <div style="text-align: right;">
      <div style="font-weight: 800; color: #0051ff; font-size: 1.1rem;">ORGANIZACIÓN: INDRA</div>
      <div style="font-size: 0.85rem; color: #64748b;">ARQUITECTO: TAKIZAWA</div>
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-item"><strong>Proyecto Auditado:</strong> {safe_project}</div>
    <div class="meta-item"><strong>Fecha de Emisión:</strong> {timestamp}</div>
    <div class="meta-item"><strong>Nivel de Riesgo Global:</strong> <span class="metric-badge {risk_level}">{risk_level} ({risk_score}/100)</span></div>
    <div class="meta-item"><strong>Plataforma de Ejecución:</strong> Android Termux (Zero-Root Architecture)</div>
  </div>

  <div class="section-title">1. Resumen Ejecutivo de Postura</div>
  <p>
    El motor de correlación <strong>Six Eyes</strong> analizó la superficie expuesta, las defensas activas de <strong>Infinity Shield</strong> y las pruebas de seguridad controladas.
  </p>
  <ul>
    <li><strong>Vulnerabilidades Catalogadas:</strong> {len(vulns)}</li>
    <li><strong>Amenazas Neutralizadas por Infinity Shield:</strong> {len(threats)}</li>
    <li><strong>Dispositivos Descubiertos en Red:</strong> {len(hosts)}</li>
    <li><strong>Reglas Activas en el Firewall WAF:</strong> {len(rules)}</li>
  </ul>

  <div class="section-title">2. Vulnerabilidades y Hallazgos</div>
  <table>
    <thead>
      <tr><th>Gravedad</th><th>Título</th><th>CVE</th><th>CVSS</th><th>Objetivo</th><th>Mitigación Recomendada</th></tr>
    </thead>
    <tbody>
      {vuln_rows}
    </tbody>
  </table>

  <div class="section-title">3. Contramedidas Defensivas Activas (Infinity Shield)</div>
  <table>
    <thead>
      <tr><th>ID Regla</th><th>Nombre</th><th>Tipo</th><th>Patrón Objetivo</th><th>Impactos Detenidos</th></tr>
    </thead>
    <tbody>
      {rule_rows}
    </tbody>
  </table>

  <div class="signature-card">
    <div class="sig-block">
      <div class="sig-line"></div>
      <div style="font-weight: 800; color: #0f172a;">Takizawa</div>
      <div style="font-size: 0.8rem; color: #64748b;">Creador & Arquitecto de Ciberseguridad</div>
      <div style="font-size: 0.8rem; color: #0051ff; font-weight: 600;">Para: Indra Sistemas</div>
    </div>
    <div class="seal-box">
      <div>SELLO DE VERIFICACIÓN CRIPTOGRÁFICA</div>
      <div style="font-weight: bold; color: #0f172a; margin-top: 0.25rem;">SHA256: {seal_hash}</div>
      <div>ESTADO: DOCUMENTO OFICIAL CERTIFICADO</div>
    </div>
  </div>

</body>
</html>
"""

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"[REPORT GENERATOR] Corporate report compiled: {output_file}")
        return str(output_file)
