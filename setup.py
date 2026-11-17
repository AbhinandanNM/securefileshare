"""
setup.py — Automated setup script for Secure Cloud File Sharing System
Run: python setup.py
"""

import os
import sys
import subprocess
import shutil

# ANSI color codes
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

ROOT = os.path.dirname(os.path.abspath(__file__))


def step(msg: str) -> None:
    print(f"\n{CYAN}{BOLD}==> {msg}{RESET}")


def ok(msg: str) -> None:
    print(f"{GREEN}  ✔  {msg}{RESET}")


def warn(msg: str) -> None:
    print(f"{YELLOW}  ⚠  {msg}{RESET}")


def err(msg: str) -> None:
    print(f"{RED}  ✘  {msg}{RESET}")


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, **kwargs)


def main() -> None:
    print(f"\n{BOLD}{'='*60}")
    print("  Secure Cloud File Sharing System — Setup")
    print(f"{'='*60}{RESET}")

    # ------------------------------------------------------------------ #
    # 1. Virtual environment
    # ------------------------------------------------------------------ #
    step("Creating virtual environment (venv) …")
    venv_dir = os.path.join(ROOT, "venv")
    if os.path.isdir(venv_dir):
        warn("venv/ already exists — skipping creation.")
    else:
        run([sys.executable, "-m", "venv", venv_dir])
        ok("Virtual environment created at venv/")

    # Determine pip / python inside the venv
    if sys.platform == "win32":
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
        venv_pip    = os.path.join(venv_dir, "Scripts", "pip.exe")
    else:
        venv_python = os.path.join(venv_dir, "bin", "python")
        venv_pip    = os.path.join(venv_dir, "bin", "pip")

    # ------------------------------------------------------------------ #
    # 2. Install requirements
    # ------------------------------------------------------------------ #
    step("Installing Python dependencies from requirements.txt …")
    req_file = os.path.join(ROOT, "requirements.txt")
    if not os.path.isfile(req_file):
        err("requirements.txt not found — cannot install dependencies.")
        sys.exit(1)
    run([venv_pip, "install", "-r", req_file])
    ok("Dependencies installed.")

    # ------------------------------------------------------------------ #
    # 3. Create uploads/ directory
    # ------------------------------------------------------------------ #
    step("Creating uploads/ directory …")
    uploads_dir = os.path.join(ROOT, "uploads")
    if os.path.isdir(uploads_dir):
        warn("uploads/ already exists — skipping.")
    else:
        os.makedirs(uploads_dir, exist_ok=True)
        ok("uploads/ directory created.")

    # ------------------------------------------------------------------ #
    # 4. Copy .env.example → .env (if not already present)
    # ------------------------------------------------------------------ #
    step("Checking .env configuration …")
    env_file     = os.path.join(ROOT, ".env")
    env_example  = os.path.join(ROOT, ".env.example")
    if os.path.isfile(env_file):
        warn(".env already exists — not overwriting. Review it manually.")
    elif os.path.isfile(env_example):
        shutil.copy(env_example, env_file)
        ok(".env created from .env.example — PLEASE update SECRET_KEY and JWT_SECRET_KEY!")
    else:
        warn(".env.example not found; skipping .env creation.")

    # ------------------------------------------------------------------ #
    # 5. Initialize the SQLite database
    # ------------------------------------------------------------------ #
    step("Initializing SQLite database …")
    db_init_code = (
        "from app import create_app, db; "
        "app = create_app(); "
        "ctx = app.app_context(); "
        "ctx.push(); "
        "db.create_all(); "
        "print('Database tables created successfully.')"
    )
    try:
        run([venv_python, "-c", db_init_code], cwd=ROOT)
        ok("Database initialized (instance/secure_cloud.db).")
    except subprocess.CalledProcessError:
        err("Database initialization failed — check that app/ is complete and importable.")
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # Done
    # ------------------------------------------------------------------ #
    print(f"\n{GREEN}{BOLD}{'='*60}")
    print("  Setup complete!")
    print(f"{'='*60}{RESET}")
    if sys.platform == "win32":
        print(f"  Run the app:  {CYAN}venv\\Scripts\\python run.py{RESET}")
    else:
        print(f"  Run the app:  {CYAN}venv/bin/python run.py{RESET}")
    print(f"  Then open:    {CYAN}https://localhost:5000{RESET}")
    print()


if __name__ == "__main__":
    main()
