/**
 * GOJO INFINITY SECURITY ∞ — CONTROLADOR DE INTERFAZ & MOTOR VISUAL
 * Manejo de pestañas, WebSockets en vivo, REST APIs y Animación de Hollow Purple.
 */

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  initWebSocket();
  loadDashboardData();
  initHollowCanvas();
  // Refresco periódico de respaldo (por si el WebSocket no está disponible)
  setInterval(loadDashboardData, 15000);
});

// --- Utilidades ---------------------------------------------------------------

/** Escapa texto para insertarlo de forma segura en HTML (previene XSS). */
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Lee el token opcional de la API (GOJO_API_TOKEN) guardado en este navegador. */
function getApiToken() {
  try {
    return localStorage.getItem("indraApiToken") || "";
  } catch (e) {
    return "";
  }
}

function setApiToken(token) {
  try {
    localStorage.setItem("indraApiToken", token);
  } catch (e) {
    /* almacenamiento no disponible */
  }
}

/**
 * fetch() con token opcional, manejo de 401 y errores HTTP.
 * Devuelve el JSON de la respuesta o lanza un Error con el detalle del servidor.
 */
async function apiFetch(url, options = {}, retried = false) {
  const headers = Object.assign({}, options.headers || {});
  const token = getApiToken();
  if (token) headers["X-API-Key"] = token;

  const res = await fetch(url, Object.assign({}, options, { headers }));

  if (res.status === 401 && !retried) {
    const newToken = window.prompt("Este servidor requiere un token de API (GOJO_API_TOKEN):");
    if (newToken) {
      setApiToken(newToken.trim());
      return apiFetch(url, options, true);
    }
  }

  let data = null;
  try {
    data = await res.json();
  } catch (e) {
    data = null;
  }

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    if (data) {
      if (typeof data.detail === "string") detail = data.detail;
      else if (Array.isArray(data.detail)) detail = data.detail.map(d => d.msg).join("; ");
      else if (data.reason) detail = data.reason;
      else if (data.error) detail = data.error;
    }
    throw new Error(detail);
  }
  return data;
}

function postJson(url, body) {
  return apiFetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

// Descripción intuitiva de cada pestaña para guiar al usuario
const TAB_DESCRIPTIONS = {
  "tab-dashboard": "Monitoreo en tiempo real, defensa activa y acceso rápido a módulos.",
  "tab-hollow": "Convergencia definitiva de las 4 técnicas en un ciclo automatizado de 5 fases.",
  "tab-sixeyes": "Asesor de seguridad cognitivo con base de conocimientos offline y resolución de dudas.",
  "tab-infinity": "Firewall de aplicación (WAF), rate limiting y mitigación de intrusiones en tiempo real.",
  "tab-blue": "Reconocimiento no intrusivo de puertos y servicios en objetivos autorizados.",
  "tab-red": "Auditorías de contraseñas y validación de controles de acceso.",
  "tab-purple": "Cálculo del índice de riesgo, correlación de amenazas y reportes ejecutivos.",
  "tab-network": "Diagnóstico de interfaces de red locales y estado de conectividad en Termux.",
  "tab-ip": "Consulta heurística de IPs e historial de visitas a servicios administrados.",
  "tab-vulnerability": "Inventario de vulnerabilidades encontradas y base de datos CVE local.",
  "tab-lab": "Entorno seguro de práctica para SQL Injection, XSS y pruebas de credenciales.",
  "tab-threats": "Historial de comportamientos anómalos interceptados por el sistema.",
  "tab-incidents": "Gestión y seguimiento de incidentes de seguridad de gravedad alta.",
  "tab-reports": "Archivos ejecutivos generados listos para descarga y auditoría.",
  "tab-settings": "Verificación del estado del entorno y persistencia en Termux."
};

// --- Manejo de Pestañas ---
function setupTabs() {
  const buttons = document.querySelectorAll(".nav-btn");

  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      switchTab(targetTab);
    });
  });
}

function switchTab(targetTab) {
  const buttons = document.querySelectorAll(".nav-btn");
  const panes = document.querySelectorAll(".tab-pane");

  buttons.forEach(b => {
    if (b.getAttribute("data-tab") === targetTab) {
      b.classList.add("active");
      document.getElementById("screenTitle").innerText = b.innerText;
    } else {
      b.classList.remove("active");
    }
  });

  panes.forEach(p => {
    if (p.id === targetTab) {
      p.classList.add("active");
    } else {
      p.classList.remove("active");
    }
  });

  const descEl = document.getElementById("screenDesc");
  if (descEl && TAB_DESCRIPTIONS[targetTab]) {
    descEl.innerText = TAB_DESCRIPTIONS[targetTab];
  }

  // Carga diferida de datos según la pestaña activa
  if (targetTab === "tab-infinity") loadShieldRules();
  if (targetTab === "tab-purple") loadPurpleRisk();
  if (targetTab === "tab-ip") loadIpData();
  if (targetTab === "tab-vulnerability") loadVulns();
  if (targetTab === "tab-network") loadNetworkDiagnostics();
}

// --- Terminal en Vivo (WebSocket) ---
let wsReconnectDelay = 2000;
let dashboardRefreshTimer = null;

/** Agrupa múltiples eventos en un solo refresco (evita tormentas de peticiones). */
function scheduleDashboardRefresh() {
  if (dashboardRefreshTimer) return;
  dashboardRefreshTimer = setTimeout(() => {
    dashboardRefreshTimer = null;
    loadDashboardData();
  }, 2000);
}

function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const token = getApiToken();
  const query = token ? `?token=${encodeURIComponent(token)}` : "";
  const wsUrl = `${protocol}//${window.location.host}/api/ws/telemetry${query}`;
  const terminal = document.getElementById("liveTerminalFeed");

  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (e) {
    console.log("WebSockets no soportados en este navegador.");
    return;
  }

  ws.onopen = () => {
    wsReconnectDelay = 2000;
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "SECURITY_EVENT" && terminal) {
        const e = msg.data;
        const line = document.createElement("div");
        line.className = `log-line ${String(e.severity).replace(/[^A-Z]/g, "")}`;
        line.innerText = `[${e.time}] [${e.module}] [${e.severity}] ${e.description}`;
        terminal.prepend(line);

        while (terminal.children.length > 60) {
          terminal.removeChild(terminal.lastChild);
        }

        scheduleDashboardRefresh();
      }
    } catch (err) {
      console.error("Error al procesar mensaje de WebSocket:", err);
    }
  };

  ws.onclose = () => {
    // Reconexión con retroceso exponencial (máx. 30 s)
    setTimeout(initWebSocket, wsReconnectDelay);
    wsReconnectDelay = Math.min(wsReconnectDelay * 2, 30000);
  };

  ws.onerror = () => {
    console.log("WebSocket en modo fallback; datos por polling REST.");
  };
}

// --- Datos del Panel Principal ---
async function loadDashboardData() {
  try {
    const data = await apiFetch("/api/overview");
    document.getElementById("metricShieldStatus").innerText = data.correlation.infinity_shield_status;
    document.getElementById("metricEventsCount").innerText = data.correlation.total_security_events;
    document.getElementById("metricThreatsCount").innerText = data.correlation.active_threats;
    document.getElementById("metricVulnCount").innerText = data.correlation.total_vulnerabilities;
  } catch (e) {
    console.error("Error al cargar telemetría:", e);
  }
}

// --- Infinity Shield (Defensa) ---
async function loadShieldRules() {
  const table = document.getElementById("shieldRulesTable");
  table.innerHTML = "<tr><td colspan='7'>Consultando reglas en base de datos...</td></tr>";

  try {
    const rules = await apiFetch("/api/infinity/rules");

    if (!rules || rules.length === 0) {
      table.innerHTML = "<tr><td colspan='7' style='color:var(--text-muted);'>No hay bloqueos activos. Infinity Shield está supervisando solicitudes.</td></tr>";
      return;
    }

    table.innerHTML = rules.map(r => `
      <tr>
        <td><strong>#${escapeHtml(r.id)}</strong></td>
        <td><code>${escapeHtml(r.target)}</code></td>
        <td><span class="pill LOW">${escapeHtml(r.type)}</span></td>
        <td><span class="pill CRITICAL">${escapeHtml(r.action)}</span></td>
        <td>${escapeHtml(r.hits)}</td>
        <td>${escapeHtml(r.expires_at)}</td>
        <td><button class="btn btn-red unban-btn" style="padding:0.3rem 0.6rem;font-size:0.75rem;" data-ip="${escapeHtml(r.target)}">Desbloquear</button></td>
      </tr>
    `).join("");

    table.querySelectorAll(".unban-btn").forEach(btn => {
      btn.addEventListener("click", () => handleUnbanIp(btn.getAttribute("data-ip")));
    });
  } catch (e) {
    table.innerHTML = `<tr><td colspan='7' style='color:var(--gojo-red);'>Error al cargar reglas: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function handleBanIp() {
  const input = document.getElementById("banIpInput");
  const ip = input.value.trim();
  if (!ip) return alert("Por favor ingresa una dirección IP válida.");

  try {
    await postJson("/api/infinity/ban", { ip_address: ip, reason: "Bloqueo manual desde el Panel", duration_minutes: 60 });
    input.value = "";
    alert(`La dirección IP ${ip} ha sido bloqueada por 60 minutos.`);
  } catch (e) {
    alert(`No se pudo bloquear la IP: ${e.message}`);
  }
  loadShieldRules();
}

async function handleUnbanIp(ip) {
  try {
    await apiFetch(`/api/infinity/unban/${encodeURIComponent(ip)}`, { method: "POST" });
  } catch (e) {
    alert(`No se pudo desbloquear la IP: ${e.message}`);
  }
  loadShieldRules();
}

// --- Blue Recon (Escaneo) ---
async function handleBlueScan() {
  const target = document.getElementById("blueTargetInput").value.trim() || "127.0.0.1";
  const table = document.getElementById("blueResultsTable");
  table.innerHTML = `<tr><td colspan='5' style='color:var(--gojo-cyan);'>Escaneando puertos TCP en ${escapeHtml(target)} (espera un momento)...</td></tr>`;

  try {
    const data = await postJson("/api/blue/scan", { target: target });

    if (!data.open_ports || data.open_ports.length === 0) {
      table.innerHTML = "<tr><td colspan='5' style='color:var(--text-muted);'>No se detectaron puertos TCP abiertos en este objetivo.</td></tr>";
      return;
    }

    table.innerHTML = data.open_ports.map(p => `
      <tr>
        <td><strong>${escapeHtml(p.port)}</strong></td>
        <td>${escapeHtml(String(p.protocol).toUpperCase())}</td>
        <td><span class="pill OPEN">ABIERTO</span></td>
        <td><strong>${escapeHtml(p.service)}</strong></td>
        <td><code>${escapeHtml(p.banner || "Sin banner")}</code></td>
      </tr>
    `).join("");
  } catch (e) {
    table.innerHTML = `<tr><td colspan='5' style='color:var(--gojo-red);'>Error durante el escaneo: ${escapeHtml(e.message)}</td></tr>`;
  }
}

// --- Red Operations (Auditoría) ---
async function handlePasswordAudit() {
  const pw = document.getElementById("redPasswordInput").value;
  if (!pw) return alert("Por favor introduce una contraseña para evaluar.");

  const out = document.getElementById("passwordAuditResult");
  try {
    const data = await postJson("/api/red/audit-password", { password: pw });
    const isStrong = data.strength === "STRONG" || data.strength === "VERY_STRONG";
    const color = isStrong ? "var(--gojo-green)" : "var(--gojo-red)";

    out.innerHTML = `
      <div style="background:rgba(0,0,0,0.4); padding:1rem 1.25rem; border-radius:8px; border:1px solid ${color};">
        <div style="margin-bottom:0.4rem;">Longitud: <strong>${escapeHtml(data.length)} caracteres</strong> | Entropía Matemática: <strong>${escapeHtml(data.entropy_bits)} bits</strong></div>
        <div style="margin-bottom:0.4rem;">Nivel de Fortaleza: <span class="pill ${isStrong ? "OPEN" : "CRITICAL"}">${escapeHtml(data.strength)}</span></div>
        <div>Apta para Cuentas Administrativas: <strong>${data.is_acceptable_for_admin ? "[APROBADA]" : "[RECHAZADA] (Muy Débil)"}</strong></div>
      </div>
    `;
  } catch (e) {
    out.innerHTML = `<div style="color:var(--gojo-red);">Error: ${escapeHtml(e.message)}</div>`;
  }
}

// --- Purple Intelligence ---
async function loadPurpleRisk() {
  try {
    const data = await apiFetch("/api/purple/risk");
    document.getElementById("purpleRiskScore").innerText = `${data.risk_index} / 100`;
    const levelEl = document.getElementById("purpleRiskLevel");
    levelEl.innerText = `Nivel de Riesgo Global: ${data.risk_level}`;
    levelEl.style.color = (data.risk_level === "CRITICAL" || data.risk_level === "HIGH") ? "var(--gojo-red)" : "var(--gojo-cyan)";
  } catch (e) {
    console.error(e);
  }
}

async function handleGenerateReport() {
  try {
    const data = await apiFetch("/api/purple/report", { method: "POST" });
    alert(`[+] Informe Generado Exitosamente:\n${data.report_title}\nGuardado en: ${data.report_path}`);
    const out = document.getElementById("reportStatusOutput");
    if (out) {
      out.innerHTML = `<div class="guide-box">Último informe: <strong>${escapeHtml(data.report_title)}</strong> listo en el disco local.</div>`;
    }
  } catch (e) {
    alert(`Error al generar informe: ${e.message}`);
  }
}

// --- Six Eyes AI ---
async function handleAskSixEyes() {
  const query = document.getElementById("sixEyesQueryInput").value.trim();
  if (!query) return;

  const box = document.getElementById("sixEyesAnswerBox");
  box.innerText = "Analizando con la sabiduría de Six Eyes (Modo Offline)...";

  try {
    const data = await postJson("/api/sixeyes/ask", { question: query });
    box.innerText = data.answer;
  } catch (e) {
    box.innerText = `Error: ${e.message}`;
  }
}

// --- IP Intelligence ---
async function loadIpData() {
  const table = document.getElementById("ipHistoryTable");
  try {
    const data = await apiFetch("/api/ip/history");

    if (!data || data.length === 0) {
      table.innerHTML = "<tr><td colspan='4' style='color:var(--text-muted);'>No hay visitas registradas aún.</td></tr>";
      return;
    }

    table.innerHTML = data.map(h => `
      <tr>
        <td><code>${escapeHtml(h.ip)}</code></td>
        <td>${escapeHtml(h.path)}</td>
        <td><span class="pill LOW">${escapeHtml(h.consent)}</span></td>
        <td>${escapeHtml(h.timestamp)}</td>
      </tr>
    `).join("");
  } catch (e) {
    table.innerHTML = `<tr><td colspan='4' style='color:var(--gojo-red);'>Error: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function handleIpLookup() {
  const ip = document.getElementById("ipLookupInput").value.trim();
  if (!ip) return alert("Ingresa una dirección IP.");

  const out = document.getElementById("ipLookupOutput");
  out.innerHTML = "<div style='color:var(--gojo-cyan);'>Consultando datos de la IP...</div>";

  try {
    const data = await apiFetch(`/api/ip/lookup?ip=${encodeURIComponent(ip)}`);

    if (data.error) {
      out.innerHTML = `<div style="color:var(--gojo-red);">${escapeHtml(data.error)}</div>`;
      return;
    }

    out.innerHTML = `
      <div style="background:rgba(0,0,0,0.5); padding:1.25rem; border-radius:8px; border:1px solid var(--border-color); font-family:var(--font-mono); font-size:0.88rem; line-height:1.6;">
        <div><strong>IP:</strong> ${escapeHtml(data.ip)} (IPv${escapeHtml(data.version)}) | <strong>Red Privada:</strong> ${data.is_private ? "Sí (Local)" : "No (Pública)"}</div>
        <div><strong>DNS Inverso (PTR):</strong> ${escapeHtml(data.reverse_dns || "Ninguno")}</div>
        <div><strong>Ubicación Aproximada:</strong> ${escapeHtml(data.geolocation.country || "Desconocido")} - ${escapeHtml(data.geolocation.city || "Ciudad Desconocida")}</div>
        <div><strong>ASN / Proveedor:</strong> ${escapeHtml(data.network.asn || "N/A")} (${escapeHtml(data.network.organization || "N/A")})</div>
        <div style="color:var(--text-muted); font-size:0.75rem; margin-top:0.6rem;">* ${escapeHtml(data.geolocation.disclaimer)}</div>
      </div>
    `;
  } catch (e) {
    out.innerText = `Error: ${e.message}`;
  }
}

// --- Vulnerabilidades ---
async function loadVulns() {
  const table = document.getElementById("vulnTable");
  try {
    const vulns = await apiFetch("/api/vulnerabilities");

    if (!vulns || vulns.length === 0) {
      table.innerHTML = "<tr><td colspan='6' style='color:var(--gojo-green); font-weight:600;'>Cero vulnerabilidades pendientes. La postura de seguridad es óptima.</td></tr>";
      return;
    }

    table.innerHTML = vulns.map(v => `
      <tr>
        <td><span class="pill ${escapeHtml(v.severity)}">${escapeHtml(v.severity)}</span></td>
        <td>${escapeHtml(v.title)}</td>
        <td><code>${escapeHtml(v.cve_id || "N/A")}</code></td>
        <td><strong>${escapeHtml(v.cvss_score)}</strong></td>
        <td>${escapeHtml(v.status)}</td>
        <td><code>${escapeHtml(v.target)}</code></td>
      </tr>
    `).join("");
  } catch (e) {
    table.innerHTML = `<tr><td colspan='6' style='color:var(--gojo-red);'>Error al cargar vulnerabilidades: ${escapeHtml(e.message)}</td></tr>`;
  }
}

// --- Laboratorio de Práctica (Attack Lab) ---
function setLabPayload(val) {
  document.getElementById("labPayloadInput").value = val;
}

function updateLabPayloadHelper() {
  const scenario = document.getElementById("labScenarioSelect").value;
  if (scenario === "sqli_lab") {
    setLabPayload("' OR '1'='1");
  } else if (scenario === "xss_lab") {
    setLabPayload("<script>alert('Gojo')</script>");
  } else if (scenario === "auth_lab") {
    setLabPayload("operator");
  }
}

async function handleRunLabSimulation() {
  const scenario = document.getElementById("labScenarioSelect").value;
  const payload = document.getElementById("labPayloadInput").value;
  const out = document.getElementById("labSimulationOutput");

  out.innerHTML = "<div style='color:var(--gojo-yellow);'>Ejecutando simulación en memoria...</div>";

  try {
    const data = await postJson("/api/lab/simulate", {
      scenario_id: scenario,
      input_data: payload,
      password_attempt: scenario === "auth_lab" ? "password123" : null
    });
    // El resultado puede contener payloads XSS: se muestra siempre como texto escapado.
    out.innerHTML = `
      <div style="color:var(--gojo-green); font-weight:700; margin-bottom:0.5rem;">[+] Simulación Completada Exitosamente</div>
      <pre style="white-space:pre-wrap; font-family:var(--font-mono); font-size:0.85rem; color:#f8fafc;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
    `;
  } catch (e) {
    out.innerHTML = `<div style="color:var(--gojo-red);">Fallo en la simulación: ${escapeHtml(e.message)}</div>`;
  }
}

// --- Diagnóstico de Red ---
async function loadNetworkDiagnostics() {
  const out = document.getElementById("networkDiagnosticsOutput");
  out.innerHTML = "<div style='color:var(--gojo-cyan);'>Inspeccionando sockets de red...</div>";

  try {
    const data = await apiFetch("/api/network/diagnostics");
    out.innerHTML = `
      <div style="margin-bottom:1.25rem;">
        <strong>Dirección IP Local de Salida:</strong> <code style="font-size:1.1rem; color:var(--gojo-cyan);">${escapeHtml(data.primary_local_ip)}</code>
      </div>
      <div style="font-weight:600; margin-bottom:0.5rem;">Interfaces Detectadas en el Dispositivo:</div>
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:0.75rem;">
        ${data.interfaces.map(i => `
          <div style="background:rgba(0,0,0,0.4); padding:0.9rem; border-radius:8px; border:1px solid rgba(255,255,255,0.08);">
            <div>Interfaz: <strong style="color:var(--gojo-cyan);">${escapeHtml(i.interface)}</strong> ${i.is_up ? '<span class="pill OPEN">ACTIVA</span>' : '<span class="pill MEDIUM">INACTIVA</span>'}</div>
            <div style="font-size:0.82rem; color:var(--text-muted); margin-top:0.35rem;">IPv4: ${escapeHtml(i.ipv4.map(a => a.address).join(", ") || "Ninguna")}</div>
          </div>
        `).join("")}
      </div>
    `;
  } catch (e) {
    out.innerText = `Error: ${e.message}`;
  }
}

// --- Animación Canvas de Hollow Purple ---
let hollowCtx = null;
let hollowAnimId = null;

function initHollowCanvas() {
  const canvas = document.getElementById("hollowCanvas");
  if (!canvas) return;
  canvas.width = canvas.parentElement.clientWidth || 600;
  canvas.height = 340;
  hollowCtx = canvas.getContext("2d");
  drawIdleOrbs(canvas.width, canvas.height);
}

function drawIdleOrbs(w, h) {
  if (!hollowCtx) return;
  hollowCtx.clearRect(0, 0, w, h);

  // Núcleo Azul (Izquierda - Reconocimiento)
  hollowCtx.beginPath();
  hollowCtx.arc(w * 0.25, h * 0.5, 32, 0, Math.PI * 2);
  hollowCtx.fillStyle = "#0066ff";
  hollowCtx.shadowColor = "#00f0ff";
  hollowCtx.shadowBlur = 25;
  hollowCtx.fill();

  // Núcleo Rojo (Derecha - Validación Ofensiva)
  hollowCtx.beginPath();
  hollowCtx.arc(w * 0.75, h * 0.5, 32, 0, Math.PI * 2);
  hollowCtx.fillStyle = "#ff0055";
  hollowCtx.shadowColor = "#ff0055";
  hollowCtx.shadowBlur = 25;
  hollowCtx.fill();
}

async function triggerHollowPurple() {
  const target = document.getElementById("hollowTargetInput").value.trim() || "127.0.0.1";
  const statusEl = document.getElementById("hollowStatusText");
  const canvas = document.getElementById("hollowCanvas");
  if (!hollowCtx) initHollowCanvas();
  const w = canvas.width;
  const h = canvas.height;

  if (hollowAnimId) cancelAnimationFrame(hollowAnimId);
  statusEl.innerText = "Fase 1: AZUL (Reconocimiento del objetivo)...";

  let progress = 0;
  function animateConvergence() {
    progress += 0.025;
    hollowCtx.clearRect(0, 0, w, h);

    const blueX = (w * 0.25) + ((w * 0.5 - w * 0.25) * Math.min(1, progress));
    const redX = (w * 0.75) - ((w * 0.75 - w * 0.5) * Math.min(1, progress));

    // Orb Azul
    hollowCtx.beginPath();
    hollowCtx.arc(blueX, h * 0.5, 32, 0, Math.PI * 2);
    hollowCtx.fillStyle = "#0066ff";
    hollowCtx.shadowColor = "#00f0ff";
    hollowCtx.shadowBlur = 30;
    hollowCtx.fill();

    // Orb Rojo
    hollowCtx.beginPath();
    hollowCtx.arc(redX, h * 0.5, 32, 0, Math.PI * 2);
    hollowCtx.fillStyle = "#ff0055";
    hollowCtx.shadowColor = "#ff0055";
    hollowCtx.shadowBlur = 30;
    hollowCtx.fill();

    if (progress < 1) {
      hollowAnimId = requestAnimationFrame(animateConvergence);
    } else {
      explodePurple();
    }
  }

  function explodePurple() {
    let radius = 35;
    function pulsePurple() {
      radius += 4;
      hollowCtx.clearRect(0, 0, w, h);

      hollowCtx.beginPath();
      hollowCtx.arc(w * 0.5, h * 0.5, radius, 0, Math.PI * 2);
      hollowCtx.fillStyle = "#a855f7";
      hollowCtx.shadowColor = "#e879f9";
      hollowCtx.shadowBlur = 50;
      hollowCtx.fill();

      if (radius < 130) {
        hollowAnimId = requestAnimationFrame(pulsePurple);
      }
    }
    pulsePurple();
  }

  animateConvergence();

  // Ejecución del API
  try {
    const data = await postJson("/api/hollow-purple/execute", { target: target });
    statusEl.innerText = `[+] HOLLOW PURPLE COMPLETADO — Riesgo: ${data.phases.purple_correlation.risk_index.risk_level} | Postura: ${data.phases.six_eyes_synthesis.posture_assessment}`;
  } catch (e) {
    if (hollowAnimId) cancelAnimationFrame(hollowAnimId);
    drawIdleOrbs(w, h);
    statusEl.innerText = `Error durante la ejecución: ${e.message}`;
  }
}
