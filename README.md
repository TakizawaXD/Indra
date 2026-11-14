# INDRA INFINITY SECURITY (INFINITY)
## PLATAFORMA HIBRIDA DE CIBERSEGURIDAD
### BLUE TEAM + RED TEAM + PURPLE TEAM + INFINITY SHIELD + SIX EYES
**Disenado y Desarrollado Exclusivamente para: Indra**  
**Creador y Arquitecto del Sistema: Takizawa**  
**Repositorio Oficial:** `https://github.com/TakizawaXD/Indra`

```
 ██╗███╗   ██╗██████╗ ██████╗  █████╗ 
 ██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗
 ██║██╔██╗ ██║██║  ██║██████╔╝███████║
 ██║██║╚██╗██║██║  ██║██╔══██╗██╔══██║
 ██║██║ ╚████║██████╔╝██║  ██║██║  ██║
 ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
        INFINITY SECURITY
  "NOTHING GETS THROUGH INFINITY."
```

---

## 1. INSTALACION Y EJECUCION EN UNA SOLA CAJA DE COMANDOS

Copia y pega la caja completa correspondiente a tu sistema operativo directamente en tu terminal.

### A. ANDROID (TERMUX) — COPIAR Y PEGAR EN 1 SOLA CAJA
```bash
pkg update -y && pkg upgrade -y && pkg install -y python git curl wget openssl clang libffi make binutils && git clone https://github.com/TakizawaXD/Indra.git && cd Indra && pip install --upgrade pip setuptools wheel && pip install -r requirements.txt && chmod +x *.sh && bash start.sh
```

*(Una vez iniciado, accede al Dashboard Web en `http://127.0.0.1:8000` o abre la CLI interactiva con `python -m terminal.shell`)*

---

### B. LINUX (DEBIAN / UBUNTU / KALI / ARCH / FEDORA) — COPIAR Y PEGAR EN 1 SOLA CAJA
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git curl wget build-essential libssl-dev libffi-dev || sudo pacman -Sy --noconfirm python python-pip git curl wget base-devel || sudo dnf install -y python3 python3-pip git curl wget gcc && git clone https://github.com/TakizawaXD/Indra.git && cd Indra && python3 -m venv venv && source venv/bin/activate && pip install --upgrade pip setuptools wheel && pip install -r requirements.txt && chmod +x *.sh && bash start.sh
```

*(Una vez iniciado, accede al Dashboard Web en `http://127.0.0.1:8000` o entra a la terminal interactiva con `python3 -m terminal.shell`)*

---

### C. WINDOWS (POWERSHELL / CMD) — COPIAR Y PEGAR EN 1 SOLA CAJA
```powershell
git clone https://github.com/TakizawaXD/Indra.git; cd Indra; python -m pip install --upgrade pip setuptools wheel; python -m pip install -r requirements.txt; .\start.bat
```

---

## 2. MODALIDADES OPERATIVAS Y COLORES DEL SISTEMA

El sistema clasifica sus tecnicas en tres pilares sin ambiguedades:

```
[DEFENSA]: Proteger y mitigar (Azul / Cian)
[ATAQUE]:  Auditar y evaluar autorizadamente (Rojo Carmesi)
[AMBAS]:   Correlacionar, converger y contener (Purpura)
```

- **[DEFENSA] Infinity Shield:** Firewall de aplicacion WAF multicapa, rate limiter, bloqueo de IPs maliciosas y verificacion de integridad.
- **[DEFENSA] Diagnostico de Red e IPs:** Monitoreo pasivo de interfaces y registro de visitas con consentimiento.
- **[ATAQUE] Blue Recon:** Escaneo activo de puertos TCP abiertos y deteccion de huellas de servicio con sockets nativos.
- **[ATAQUE] Red Operations:** Auditoria de fortaleza de contraseñas (entropia de Shannon) y validacion no destructiva de peticiones HTTP.
- **[ATAQUE] Attack Lab:** Entorno aislado de simulacion y aprendizaje seguro en memoria (SQL Injection, XSS reflejado y login bypass).
- **[AMBAS] Purple Intel:** Matriz de correlacion de amenazas, puntuacion global de riesgo (0 a 100) y clasificacion de incidentes.
- **[AMBAS] Hollow Purple:** Protocolo definitivo de convergencia automatizada en 5 fases continuas (Blue -> Red -> Purple -> Infinity -> Six Eyes).
- **[AMBAS] Six Eyes:** Cerebro analitico offline y motor de recomendaciones tecnicas estructuradas.

---

## 3. COMANDOS DE LA TERMINAL INTERACTIVA CLI
Para acceder a la terminal de ciberseguridad en cualquier momento:
```bash
python -m terminal.shell
```

Comandos principales:
- `help` : Despliega la matriz completa de operaciones y tecnicas.
- `status` : Muestra el estado en tiempo real de todos los modulos.
- `infinity status` : Estado del motor de proteccion y lista de IPs bloqueadas.
- `blue scan <IP>` : Escaneo no intrusivo de puertos TCP autorizados.
- `red audit pass <password>` : Auditoria de entropia y fortaleza de credenciales.
- `purple risk` : Calculo de indice de riesgo actual del sistema.
- `hollow-purple <IP>` : Ejecucion del protocolo de convergencia definitiva.
- `report generate` : Compilacion de reporte de auditoria ejecutivo y corporativo para Indra.
- `exit` : Cierra la sesion de la terminal de forma segura.

---

## 4. VERIFICACION DE PRUEBAS DE CALIDAD
Para corroborar la estabilidad y operatividad de todos los subsistemas:
```bash
python -m unittest discover tests
```
Resultado verificado: `Ran 15 tests in 2.090s - OK` con 100% de aprobacion.

---

## 5. CREDITOS Y LICENCIA
- **Organizacion:** Indra
- **Creador y Arquitecto:** Takizawa
- **Sistema:** INDRA INFINITY SECURITY
- **Lema:** *"Nothing gets through Infinity."*
