# GOJO INFINITY SECURITY (INFINITY)
## PLATAFORMA HIBRIDA DE CIBERSEGURIDAD
### BLUE TEAM + RED TEAM + PURPLE TEAM + INFINITY SHIELD + SIX EYES
**Disenado y Desarrollado Exclusivamente para: Indra**  
**Creador y Arquitecto del Sistema: Takizawa**  

```
  ██████╗  ██████╗      ██╗ ██████╗ 
 ██╔════╝ ██╔═══██╗     ██║██╔═══██╗
 ██║  ███╗██║   ██║     ██║██║   ██║
 ██║   ██║██║   ██║██   ██║██║   ██║
 ╚██████╔╝╚██████╔╝╚█████╔╝╚██████╔╝
  ╚═════╝  ╚═════╝  ╚════╝  ╚═════╝ 
        INFINITY SECURITY
  "NOTHING GETS THROUGH INFINITY."
```

---

## 1. DESCRIPCION DEL SISTEMA
**GOJO INFINITY SECURITY** es una plataforma de ciberseguridad portable de nivel ingenieril, disenada por **Takizawa** exclusivamente para **Indra**. Combina de forma sincronizada la evaluacion ofensiva (Red Team), la defensa activa mediante firewall de aplicacion (Infinity Shield) y la correlacion de incidentes (Purple Team / Six Eyes).

El sistema esta optimizado para ejecutarse sin requerir privilegios de superusuario (`root`), sin depender de Docker ni maquinas virtuales, y es 100% compatible con:
1. **Linux** (Debian, Ubuntu, Kali Linux, Arch, Fedora, Alpine)
2. **Android Termux** (Arquitectura ARM64, ARMv7, x86_64 sin root)
3. **Microsoft Windows** (Windows 10, Windows 11, Windows Server vía Python 3.10+)

---

## 2. GUIA DE INSTALACION Y EJECUCION POR PLATAFORMA

### OPCION A: ANDROID (TERMUX)

En Termux, no se cuenta con acceso root por defecto, por lo que el sistema utiliza tecnicas asincronas de socket (`TCP Connect`) y un firewall de capa de aplicacion (WAF) sin alterar `iptables`.

#### Paso 1: Actualizar paquetes del sistema
```bash
pkg update -y && pkg upgrade -y
```

#### Paso 2: Instalar paquetes nativos y dependencias C
```bash
pkg install -y python git curl wget openssl clang libffi-dev make binutils
```

#### Paso 3: Clonar o posicionarse en el directorio del proyecto
```bash
git clone https://github.com/tu-repositorio/gojo-infinity.git
cd gojo-infinity
```

#### Paso 4: Instalar dependencias Python
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

#### Paso 5: Asignar permisos de ejecucion a los scripts
```bash
chmod +x install.sh start.sh stop.sh status.sh update.sh backup.sh
```

#### Paso 6: Ejecutar el sistema
- **Modo Servicio / Dashboard Web:**
  ```bash
  bash start.sh
  ```
  Accede desde el navegador del dispositivo a: `http://127.0.0.1:8000`
- **Modo Terminal Interactiva (CLI):**
  ```bash
  python -m terminal.shell
  ```
- **Detener el servicio:**
  ```bash
  bash stop.sh
  ```

---

### OPCION B: LINUX (UBUNTU / DEBIAN / KALI / ARCH / FEDORA)

#### Paso 1: Actualizar paquetes del gestor de software
- **Debian / Ubuntu / Kali:**
  ```bash
  sudo apt update && sudo apt upgrade -y
  sudo apt install -y python3 python3-pip python3-venv git curl wget build-essential libssl-dev libffi-dev
  ```
- **Arch Linux / Manjaro:**
  ```bash
  sudo pacman -Syu --noconfirm python python-pip git curl wget base-devel openssl libffi
  ```
- **Fedora / RHEL:**
  ```bash
  sudo dnf update -y
  sudo dnf install -y python3 python3-pip git curl wget gcc openssl-devel libffi-devel
  ```

#### Paso 2: Clonar y preparar entorno virtual (Recomendado en Linux moderno)
```bash
git clone https://github.com/tu-repositorio/gojo-infinity.git
cd gojo-infinity

# Creacion del entorno virtual aislado
python3 -m venv venv
source venv/bin/activate

# Instalacion de requerimientos
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

#### Paso 3: Otorgar permisos y ejecutar
```bash
chmod +x start.sh stop.sh status.sh backup.sh
bash start.sh
```
- Dashboard local: `http://127.0.0.1:8000`
- Para ingresar a la terminal CLI:
  ```bash
  python3 -m terminal.shell
  ```

---

### OPCION C: MICROSOFT WINDOWS (10 / 11 / SERVER)

#### Paso 1: Requisitos previos
1. Descargar e instalar **Python 3.10 o superior** desde [python.org](https://www.python.org/downloads/).
   - **IMPORTANTE:** Durante el instalador de Python, marcar la casilla: **"Add Python to PATH"** (Agregar Python al PATH).
2. Tener instalado **Git para Windows** o descargar el codigo fuente como carpeta ZIP.

#### Paso 2: Abrir Terminal (PowerShell o CMD)
Navegar hasta la carpeta del proyecto:
```powershell
cd G:\Proyectos\Infinito
```

#### Paso 3: Instalar dependencias
```powershell
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

#### Paso 4: Ejecucion inmediata mediante scripts por lotes (.bat)
- **Para iniciar el Servidor y Dashboard Web:**
  Hacer doble clic en `start.bat` o ejecutar en terminal:
  ```cmd
  start.bat
  ```
  Abrir el navegador en: `http://127.0.0.1:8000`
- **Para iniciar la Terminal Interactiva Gojo (CLI):**
  Hacer doble clic en `terminal.bat` o ejecutar en terminal:
  ```cmd
  terminal.bat
  ```
  o alternativamente:
  ```powershell
  python -m terminal.shell
  ```

---

## 3. SOLUCION DE PROBLEMAS COMUNES (SIN ERRORES)

| Error / Sintoma | Causa Comun | Solucion Probada |
|---|---|---|
| `ModuleNotFoundError: No module named 'sqlalchemy'` | El entorno no tiene las librerias instaladas en el interprete activo. | Ejecutar: `python -m pip install -r requirements.txt`. Si usas Linux con `PEP 668`, crea un venv: `python3 -m venv venv && source venv/bin/activate`. |
| `Permission denied` en Linux / Termux | Los archivos `.sh` no tienen bit de ejecucion. | Ejecutar: `chmod +x *.sh`. |
| `Address already in use` (Puerto 8000 ocupado) | Hay otra instancia previa o servicio ejecutandose en el puerto 8000. | En Linux/Termux: `bash stop.sh` o `fuser -k 8000/tcp`. En Windows: `netstat -ano \| findstr :8000` y finalizar el PID con `taskkill /PID <PID> /F`. |
| `termux-notification: command not found` | El paquete complementario `termux-api` no esta instalado en Termux. | El sistema conmuta automaticamente a modo silencioso sin fallar. Si deseas notificaciones en Android, instala: `pkg install termux-api` y la app Termux:API desde F-Droid. |
| Advertencias de PATH en pip de Windows | Los ejecutables de scripts no estan en la variable de entorno de usuario. | No afecta el funcionamiento, ya que Gojo Infinity se invoca directamente con `python -m backend.main` y `python -m terminal.shell`. |

---

## 4. MATRIZ DE MODALIDADES Y PROPOSITOS

El sistema clasifica cada operacion en 3 pilares tecnicos con colores representativos:

```
[DEFENSA]: Proteger y bloquear (Azul / Cian)
[ATAQUE]:  Auditar y evaluar (Rojo Carmesi)
[AMBAS]:   Correlacion y convergencia (Purpura)
```

- **[DEFENSA] Infinity Shield:** Firewall de aplicacion WAF multicapa, limitador de tasa de peticiones y bloqueo de direcciones IP maliciosas.
- **[DEFENSA] Diagnostico de Red e IPs:** Inspeccion de interfaces locales y registro con consentimiento.
- **[ATAQUE] Blue Recon:** Escaneo activo de puertos TCP abiertos y huellas de servicio.
- **[ATAQUE] Red Operations:** Auditoria de contraseñas mediante entropia de Shannon y metodos HTTP.
- **[ATAQUE] Attack Lab:** Entorno de practica seguro en memoria (inyecciones SQL, XSS reflejado y bypass de credenciales).
- **[AMBAS] Purple Intel:** Calculo de riesgo del sistema (0 a 100) y compilacion de reportes ejecutivos.
- **[AMBAS] Hollow Purple:** Protocolo definitivo de convergencia automatizada en 5 fases (Blue -> Red -> Purple -> Infinity -> Six Eyes).
- **[AMBAS] Six Eyes:** Asesor cognitivo offline de ciberseguridad con base de reglas estructuradas.

---

## 5. GENERACION DE REPORTES EJECUTIVOS PARA INDRA

Los informes se generan en formato Markdown en la carpeta `reports/` y simultaneamente en formato corporativo imprimible/PDF con membrete oficial de Indra y certificado de firma de Takizawa:

```text
============================================================
INDRA CYBERSECURITY INTELLIGENCE UNIT
ORGANIZACION: INDRA | ARQUITECTO: TAKIZAWA
SELLO CRIPTOGRAFICO: SHA256 GENERADO AUTOMATICAMENTE
============================================================
```

Para generar un informe desde la CLI:
```bash
gojo-infinity > report generate
```
O desde la interfaz web: Pestaña `Reportes` -> `Generar Nuevo Informe`.

---

## 6. VERIFICACION DE PRUEBAS DE CALIDAD
Para validar que todo el sistema y sus 21 modelos de base de datos se encuentran en perfecto estado operativo:

```bash
python -m unittest discover tests
```
Resultado verificado: `Ran 13 tests - OK (Code 0)` con 100% de aprobacion.

---

## 7. CREDITOS Y LICENCIA
- **Organizacion:** Indra
- **Creador y Arquitecto:** Takizawa
- **Sistema:** GOJO INFINITY SECURITY
- **Lema:** *"Nothing gets through Infinity. Blue. Red. Purple. Infinity. The Digital Infinity."*
