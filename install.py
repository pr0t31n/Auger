#!/usr/bin/env python3
"""Auger installer — multi-platform database security auditor."""
import subprocess, sys, os, shutil
from pathlib import Path


def _pip_installed(pkg_spec):
    """Return True if a pip package is already importable."""
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "psycopg2-binary": "psycopg2", "cassandra-driver": "cassandra",
        "influxdb-client": "influxdb_client", "PyMySQL": "pymysql",
        "Pillow": "PIL", "pyyaml": "yaml",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None

TOOL_NAME   = "Auger"
MIN_PYTHON  = (3, 10)
INSTALL_DIR = Path("/opt/pr0t31n/Auger")

def _run(cmd, check=True, capture=False):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(
        cmd, shell=isinstance(cmd, str), check=check,
        capture_output=capture
    )

def _has(binary):
    return shutil.which(binary) is not None

# ─── system dependencies ────────────────────────────────────────────────────

BREW_PKGS    = ["libpq", "openssl", "freetds"]
APT_PKGS     = ["libpq-dev", "libssl-dev", "freetds-dev", "freetds-bin",
                 "unixodbc-dev", "python3-dev", "build-essential", "libev-dev"]
CHOCO_PKGS   = []                        # Windows: most things via pip

def _real_user() -> str:
    """Best-effort: find the non-root user to run brew as."""
    for var in ("SUDO_USER", "LOGNAME", "USER"):
        u = os.environ.get(var, "")
        if u and u != "root":
            return u
    try:
        r = subprocess.run(["logname"], capture_output=True, text=True)
        u = r.stdout.strip()
        if u and u != "root":
            return u
    except Exception:
        pass
    return ""

_BREW_ENV = {**os.environ, "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_INSTALL_UPGRADE": "1"}

def _brew_cmd(args: list):
    """Return brew command list, or None if brew cannot be run (root with no real user found)."""
    brew_path = shutil.which("brew") or "brew"
    if os.geteuid() == 0:
        ru = _real_user()
        if ru:
            return ["sudo", "-u", ru, "-E", brew_path] + args
        return None  # can't determine real user — caller must skip
    return [brew_path] + args

def _run_brew(args: list) -> bool:
    """Run a brew command with auto-update suppressed. Returns True on success."""
    cmd = _brew_cmd(args)
    if cmd is None:
        return False
    print(f"  → {' '.join(cmd)}")
    r = subprocess.run(cmd, env=_BREW_ENV, check=False)
    return r.returncode == 0

def install_system_deps():
    if sys.platform == "darwin" and _has("brew"):
        print("\n[system] Installing macOS dependencies via Homebrew...")
        if _brew_cmd([]) is None:
            print("  [skip] Running as root with no login user detected.")
            print("         Run manually as your normal user:")
            for p in BREW_PKGS:
                print(f"           brew install {p}")
        else:
            for pkg in BREW_PKGS:
                if _run_brew(["list", "--formula", pkg]):
                    print(f"  ✓ {pkg} already installed")
                else:
                    ok = _run_brew(["install", pkg])
                    if not ok:
                        print(f"  [warn] brew install {pkg} failed — pip may still succeed with pre-built wheels.")
    elif sys.platform.startswith("linux") and _has("apt-get"):
        print("\n[system] Installing Linux dependencies via apt-get...")
        _run(["apt-get", "update", "-qq"])
        for pkg in APT_PKGS:
            r = _run(["dpkg", "-s", pkg], check=False, capture=True)
            if r.returncode == 0:
                print(f"  ✓ {pkg} already installed")
            else:
                _run(["apt-get", "install", "-y", pkg])
    elif _has("choco"):
        print("\n[system] Installing Windows dependencies via Chocolatey...")
        for pkg in CHOCO_PKGS:
            _run(["choco", "install", "-y", pkg])
    else:
        print("\n[system] No supported package manager found — skipping system deps.")
        print("         You may need to manually install: libpq, openssl, FreeTDS")

# ─── pip dependencies ───────────────────────────────────────────────────────

def install_pip_deps():
    print("\n[pip] Installing Python dependencies...")
    req = Path(__file__).parent / "requirements.txt"
    if not req.exists():
        print("  ! requirements.txt not found — skipping pip install")
        return
    with open(req) as f:
        pkgs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    _to_install = []
    for pkg in pkgs:
        if _pip_installed(pkg):
            print(f"  ✓ {pkg} already installed")
        else:
            _to_install.append(pkg)
    if _to_install:
        print(f"  Installing {len(_to_install)} package(s)…")
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages"] + _to_install)
    else:
        print("  All pip packages already installed.")

# ─── catalogue dir ──────────────────────────────────────────────────────────

def ensure_catalogue_dir():
    cat = Path(__file__).parent / "catalogue"
    cat.mkdir(exist_ok=True)
    cat_file = cat / "auger_catalogue.json"
    if not cat_file.exists():
        print(f"\n[warn] catalogue/auger_catalogue.json not found at {cat_file}")
        print("       Make sure the file is present before running auger.py")
    else:
        print(f"\n[catalogue] {cat_file} — OK")

# ─── production install ──────────────────────────────────────────────────────

def ensure_opt_dir():
    if INSTALL_DIR.exists():
        print(f"\n[install] Production path {INSTALL_DIR} already exists")
    else:
        print(f"\n[install] Production path {INSTALL_DIR} does not exist.")
        print(f"          Run the deploy script to copy files to {INSTALL_DIR}")

# ─── main ────────────────────────────────────────────────────────────────────

def _check_prereqs():
    """Verify required system tools are present before attempting install."""
    REQUIRED = [
        ("pip3", "pip3 — required for Python packages (apt: python3-pip)"),
    ]
    missing = []
    for binary, desc in REQUIRED:
        if not shutil.which(binary):
            missing.append(f"  ✗ {binary}  ({desc})")
    if missing:
        print(f"\nERROR: Missing required prerequisites:\n")
        for m in missing:
            print(m)
        print(f"\nInstall them first, then re-run install.py.\n")
        sys.exit(1)


def main():
    if sys.version_info < MIN_PYTHON:
        v = ".".join(map(str, MIN_PYTHON))
        print(f"ERROR: Python {v}+ required (got {sys.version_info.major}.{sys.version_info.minor})")
        sys.exit(1)

    _check_prereqs()

    print(f"\n{'='*60}")
    print(f"  {TOOL_NAME} — Database Security Auditor — Installation")
    print(f"{'='*60}")

    install_system_deps()
    install_pip_deps()
    ensure_catalogue_dir()
    ensure_opt_dir()

    print(f"\n{'='*60}")
    print(f"  {TOOL_NAME} installed successfully.")
    print(f"  Start with: python3 auger.py --help")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
