#!/usr/bin/env bash
# Bring up Tool Tracker on a fresh machine.
#
# Prereqs (the script will tell you if any are missing):
#   • Python 3.11 or newer
#   • Postgres 14 or newer running on localhost:5432
#   • An empty database called `aikit` (the script will create it if missing)
#
# Then:
#   bash run_locally.sh
#
# The app comes up at http://localhost:8000

set -euo pipefail

cyan()  { printf '\033[0;36m%s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
warn()  { printf '\033[0;33m%s\033[0m\n' "$*"; }

# ── 1. Check Python ──────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
  red "Python 3 not found. Install from https://www.python.org/downloads/ (need 3.11+)."
  exit 1
fi
PYV=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if ! python3 -c 'import sys; assert sys.version_info >= (3, 11)' 2>/dev/null; then
  red "Python 3.11+ required (you have $PYV). Install a newer version."
  exit 1
fi
cyan "Python $PYV ✓"

# ── 2. Check Postgres ────────────────────────────────────────────────────────
if ! command -v psql >/dev/null 2>&1; then
  red "Postgres client (psql) not found. Install Postgres 14+:"
  red "  macOS:  brew install postgresql@15 && brew services start postgresql@15"
  red "  Ubuntu: sudo apt install postgresql"
  exit 1
fi
if ! pg_isready -h localhost -q 2>/dev/null; then
  red "Postgres is not accepting connections on localhost:5432."
  red "Start it (macOS: 'brew services start postgresql@15')."
  exit 1
fi
cyan "Postgres reachable ✓"

# ── 3. Create the database if it doesn't exist ───────────────────────────────
if ! psql -lqt | cut -d \| -f 1 | grep -qw aikit; then
  cyan "Creating database 'aikit'…"
  createdb aikit || { red "createdb failed — make sure your local Postgres user has CREATEDB."; exit 1; }
fi

# ── 4. Build / refresh the venv ──────────────────────────────────────────────
if [[ ! -d venv ]]; then
  cyan "Creating Python virtual environment in ./venv…"
  python3 -m venv venv
fi
# shellcheck source=/dev/null
. venv/bin/activate

if [[ -f requirements.txt ]]; then
  cyan "Installing dependencies (first run is slow; cached afterwards)…"
  pip install --quiet --upgrade pip
  pip install --quiet -r requirements.txt
fi

# ── 5. .env ──────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  cyan "Creating .env from .env.example (review and edit if needed)…"
  cp .env.example .env
  # Try to set DATABASE_URL to the local Postgres if not already pointing there.
  if grep -q '^DATABASE_URL=' .env; then
    PGUSER=${PGUSER:-$(whoami)}
    sed -i.bak "s|^DATABASE_URL=.*|DATABASE_URL=postgresql://${PGUSER}@localhost:5432/aikit|" .env
    rm -f .env.bak
  fi
  warn "Some features (AI assistant, embeddings) need API keys in .env — they will be disabled until you set them."
fi

# ── 6. Run alembic migrations ────────────────────────────────────────────────
if [[ -f alembic.ini ]]; then
  cyan "Applying database migrations…"
  alembic upgrade head || warn "Migrations failed — check DATABASE_URL in .env"
fi

# ── 7. Start the server ──────────────────────────────────────────────────────
cyan ""
cyan "──────────────────────────────────────────────"
cyan " Tool Tracker is starting at http://localhost:8000"
cyan " Press Ctrl-C to stop."
cyan "──────────────────────────────────────────────"
cyan ""

# Open the browser tab on macOS / Linux (best-effort)
( sleep 2 && (open http://localhost:8000 2>/dev/null || xdg-open http://localhost:8000 2>/dev/null || true) ) &

# uvicorn picks up app.main:app from the FastAPI project layout
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
