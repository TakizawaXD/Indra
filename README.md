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
pkg update -y
pkg upgrade -y
pkg install -y python git curl wget openssl clang libffi make binutils
git clone https://github.com/TakizawaXD/Indra.git
cd Indra
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
chmod +x *.sh
bash start.sh
```

*(Una vez iniciado, accede al Dashboard Web en `http://127.0.0.1:8000` o abre la CLI interactiva con `python -m terminal.shell`)*

---

### B. LINUX (DEBIAN / UBUNTU / KALI) — COPIAR Y PEGAR EN 1 SOLA CAJA
```bash
sudo apt update -y
sudo apt install -y python3 python3-pip python3-venv git curl wget build-essential libssl-dev libffi-dev
git clone https://github.com/TakizawaXD/Indra.git
cd Indra
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
chmod +x *.sh
bash start.sh
```

*(Una vez iniciado, accede al Dashboard Web en `http://127.0.0.1:8000` o entra a la terminal interactiva con `python3 -m terminal.shell`)*

---

### C. WINDOWS (POWERSHELL / CMD) — COPIAR Y PEGAR EN 1 SOLA CAJA
```powershell
git clone https://github.com/TakizawaXD/Indra.git
cd Indra
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
.\start.bat
```

---

## 2. MATRIZ COMPLETA DE DEPENDENCIAS DEL SISTEMA

### A. Dependencias Nativas por Sistema Operativo

| Sistema Operativo | Paquetes del Sistema Requeridos | Comando de Instalacion Directa |
|---|---|---|
| **Android (Termux)** | `python`, `git`, `curl`, `wget`, `openssl`, `clang`, `libffi`, `make`, `binutils` *(Opcional: `termux-api`)* | `pkg install -y python git curl wget openssl clang libffi make binutils` |
| **Linux (Debian / Ubuntu / Kali)** | `python3`, `python3-pip`, `python3-venv`, `git`, `curl`, `wget`, `build-essential`, `libssl-dev`, `libffi-dev` | `sudo apt install -y python3 python3-pip python3-venv git curl wget build-essential libssl-dev libffi-dev` |
| **Linux (Arch Linux / Manjaro)** | `python`, `python-pip`, `git`, `curl`, `wget`, `base-devel`, `openssl`, `libffi` | `sudo pacman -Sy --noconfirm python python-pip git curl wget base-devel openssl libffi` |
| **Linux (Fedora / RHEL)** | `python3`, `python3-pip`, `git`, `curl`, `wget`, `gcc`, `openssl-devel`, `libffi-devel` | `sudo dnf install -y python3 python3-pip git curl wget gcc openssl-devel libffi-devel` |
| **Microsoft Windows** | `Python 3.10+` (con pip y agregado al PATH), `Git for Windows` | Descargar desde python.org y git-scm.com |

### B. Dependencias de Python (requirements.txt)

| Paquete | Version Requerida | Categoria | Proposito Tecnico en Indra Infinity |
|---|---|---|---|
| `fastapi` | `>=0.110.0,<1.0.0` | Framework Web | Core de la API REST, enrutamiento y WebSockets de eventos |
| `uvicorn[standard]` | `>=0.29.0,<1.0.0` | Servidor ASGI | Servidor asincrono de alto rendimiento para el Dashboard Web |
| `pydantic` | `>=2.6.0,<3.0.0` | Validacion | Validacion estricta de esquemas, tipos y payloads de entrada |
| `pydantic-settings` | `>=2.2.0,<3.0.0` | Configuracion | Carga tipada de variables de entorno y archivos `.env` |
| `sqlalchemy` | `>=2.0.28,<3.0.0` | Persistencia | Capa ORM para gestion de los 21 modelos de base de datos |
| `httpx` | `>=0.27.0,<1.0.0` | Red Asincrona | Cliente HTTP para auditorias web no intrusivas y lookups de IP/CVE |
| `dnspython` | `>=2.6.0,<3.0.0` | Red & DNS | Resolucion DNS de registros A, AAAA, MX, NS, TXT y Reverse PTR |
| `rich` | `>=13.7.1` | Terminal UI | Formato estetico, tablas, paneles y colores para la CLI |
| `prompt-toolkit` | `>=3.0.43,<4.0.0` | Terminal CLI | Shell interactiva con autocompletado y gestion de historial |
| `psutil` | `>=5.9.8` | Monitoreo | Diagnostico de hardware, memoria, interfaces y sockets del SO |

---

## 3. MODALIDADES OPERATIVAS Y COLORES DEL SISTEMA

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

## 4. COMANDOS DE LA TERMINAL INTERACTIVA CLI
Para acceder a la terminal de ciberseguridad en cualquier momento:
```bash
python -m terminal.shell
```

Comandos principales:
- `insertar llave` : Opcion inicial al abrir el sistema para pegar la llave y desbloquear la plataforma.
- `help` : Despliega la matriz completa de operaciones y tecnicas.
- `status` : Muestra el estado en tiempo real de todos los modulos.
- `infinity status` : Estado del motor de proteccion y lista de IPs bloqueadas.
- `blue scan <IP>` : Escaneo no intrusivo de puertos TCP autorizados.
- `red audit pass <password>` : Auditoria de entropia y fortaleza de credenciales.
- `red audit-methods <url>` : Deteccion de metodos HTTP peligrosos (TRACE/PUT/DELETE) en objetivos autorizados.
- `vulnerability cve <componente>` : Consulta de la base CVE offline.
- `lab [list|sqli|xss|auth]` : Laboratorio de practica seguro en memoria.
- `purple risk` : Calculo de indice de riesgo actual del sistema.
- `hollow-purple <IP>` : Ejecucion del protocolo de convergencia definitiva.
- `report generate` / `report list` : Compilacion y listado de reportes ejecutivos (Markdown + HTML imprimible).
- `exit` : Cierra la sesion de la terminal de forma segura.

---

## 5. VERIFICACION DE PRUEBAS DE CALIDAD
Para corroborar la estabilidad y operatividad de todos los subsistemas:
```bash
python -m unittest discover tests
```
Las pruebas usan un directorio temporal aislado (no modifican la base de datos ni los reportes reales).
Resultado verificado: `Ran 25 tests - OK` con 100% de aprobacion.

---

## 6. CONFIGURACION PARA PRODUCCION

1. **Licencia:** coloca la llave en `config/license.key` o define `INDRA_LICENSE_KEY`. La llave nunca se guarda en el codigo (solo su hash SHA-256) ni se sube al repositorio.
2. **Variables de entorno:** copia `.env.example` a `.env` y ajustalo. `.env` esta excluido de git.
3. **Exposicion en red:** por defecto el servidor escucha solo en `127.0.0.1`. Si cambias `GOJO_HOST` a `0.0.0.0` (acceso desde la LAN) define **obligatoriamente** `GOJO_API_TOKEN`; el panel lo pedira una vez y lo recordara en el navegador.
4. **Protecciones activas:** cabecera Host validada (anti DNS-rebinding), sin CORS abierto, CSP en el panel, rate limiting por IP y escape de todo contenido externo (banners, PTR, rutas) en el panel y los reportes. La IP local (`127.0.0.1`) nunca se bloquea automaticamente.
5. **Datos en tiempo de ejecucion** (`database/`, `logs/`, `reports/`, `backups/`, `quarantine/`) estan excluidos de git. Usa `bash backup.sh` para respaldarlos. `GOJO_DATA_DIR` permite moverlos a otra ruta.
6. **Salud del servicio:** `GET /health` devuelve el estado del motor.

---

## 7. CREDITOS Y LICENCIA
- **Organizacion:** Indra
- **Creador y Arquitecto:** Takizawa
- **Sistema:** INDRA INFINITY SECURITY
- **Lema:** *"Nothing gets through Infinity."*
