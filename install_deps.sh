#!/usr/bin/env bash
# ==============================================================================
#  INDRA INFINITY SECURITY — PYTHON DEPENDENCY INSTALLER (shared by install/update)
#  On Termux, packages with Rust/C extensions (pydantic-core) cannot be built by
#  pip because rustup does not support aarch64-linux-android. We install them
#  from Termux's precompiled repo and pin pip to those exact versions so it
#  never tries to rebuild them from source.
# ==============================================================================

PY_BIN="${PY_BIN:-$(command -v python3 || command -v python)}"
UPGRADE_FLAG="${1:-}"   # pass --upgrade to refresh pure-python packages

IS_TERMUX=false
if [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=true
fi

if [ "$IS_TERMUX" != true ]; then
    "$PY_BIN" -m pip install $UPGRADE_FLAG -r requirements.txt
    exit $?
fi

echo "[*] Termux: installing precompiled native Python packages..."
# Install one by one: a single unknown package name would abort the whole apt transaction.
for p in python-pydantic-core python-pydantic python-cryptography; do
    pkg install -y "$p" >/dev/null 2>&1 && echo "    [+] $p" || echo "    [!] $p not available in repo"
done

# Pin every already-installed native package to its current version so pip
# never upgrades it (which would trigger a source build needing Rust).
CONSTRAINTS="$(mktemp)"
"$PY_BIN" - > "$CONSTRAINTS" <<'EOF'
from importlib import metadata
for name in ("pydantic", "pydantic-core", "cryptography"):
    try:
        print(f"{name}=={metadata.version(name)}")
    except metadata.PackageNotFoundError:
        pass
EOF
echo "[*] Pinned native packages:"; sed 's/^/    /' "$CONSTRAINTS"

if ! grep -q '^pydantic-core==' "$CONSTRAINTS"; then
    echo "[!] pydantic-core is not installed from Termux. Falling back to building it"
    echo "    with Termux's Rust toolchain (slow, several minutes)..."
    pkg install -y rust binutils >/dev/null 2>&1 || true
    # maturin needs the Android API level to target aarch64-linux-android with Termux's rustc
    export ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-$(getprop ro.build.version.sdk 2>/dev/null || echo 24)}"
    export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
fi

# 1) Terminal UI first, independently, so the CLI works even if the web stack fails.
"$PY_BIN" -m pip install $UPGRADE_FLAG --prefer-binary -c "$CONSTRAINTS" "rich>=13.7.1" "prompt-toolkit>=3.0.43,<4.0.0"

# 2) Full requirements, respecting the pins.
"$PY_BIN" -m pip install $UPGRADE_FLAG --prefer-binary -c "$CONSTRAINTS" -r requirements.txt
STATUS=$?
rm -f "$CONSTRAINTS"
exit $STATUS
