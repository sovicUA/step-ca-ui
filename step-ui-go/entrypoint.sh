#!/bin/sh
set -e

echo "======================================="
echo "  Step-CA UI (Go) — starting up"
echo "======================================="

# Wait for PostgreSQL
echo "[*] Waiting for PostgreSQL..."
until nc -z postgres 5432 2>/dev/null; do
  sleep 1
done
echo "[*] PostgreSQL is ready!"

# Wait for Step-CA (bundled mode only)
CA_MODE="${CA_MODE:-bundled}"
if [ "$CA_MODE" = "bundled" ]; then
  echo "[*] Bundled mode: waiting for Step-CA at ${CA_URL}..."
  until curl -sk "${CA_URL}/health" >/dev/null 2>&1; do
    sleep 2
  done
  echo "[*] Step-CA is ready!"
else
  echo "[*] External CA mode: skipping Step-CA container wait."
fi

# SSL certificate for the UI
if [ ! -f /opt/step-ui/ssl/server.crt ]; then
  echo "[*] Generating self-signed SSL certificate..."
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048     -keyout /opt/step-ui/ssl/server.key     -out /opt/step-ui/ssl/server.crt     -subj "/CN=${HOST_IP:-localhost}"     -addext "subjectAltName=IP:${HOST_IP:-127.0.0.1},DNS:localhost" 2>/dev/null
fi

PASSWORD_FILE="${PASSWORD_FILE:-/opt/step-ui/data/provisioner_password}"
if [ -f "$PASSWORD_FILE" ]; then
  echo "[*] Provisioner password file found"
elif [ -n "${PROVISIONER_PASSWORD:-}" ]; then
  echo "[*] Writing provisioner password file"
  mkdir -p "$(dirname "$PASSWORD_FILE")"
  printf "%s" "$PROVISIONER_PASSWORD" > "$PASSWORD_FILE"
  chmod 600 "$PASSWORD_FILE"
else
  if [ "$CA_MODE" = "bundled" ]; then
    echo "[!] Provisioner password file not found: $PASSWORD_FILE"
    echo "[!] Set CA_PASSWORD in .env or create this file with the step-ca provisioner password."
  else
    echo "[*] External mode: provisioner password can be configured via Admin UI (/admin/ca)"
  fi
fi
export PASSWORD_FILE

echo "[*] Starting Step-CA UI on port ${PORT:-8443}"
# Seed initial admin password from STEPUI_ADMIN_PASSWORD if provided.
# The Go app reads this on first boot when no admin user exists.
if [ -n "${STEPUI_ADMIN_PASSWORD:-}" ]; then
  echo "[*] STEPUI_ADMIN_PASSWORD detected — will seed first admin with it"
  export STEPUI_ADMIN_PASSWORD
fi


exec /opt/step-ui/step-ui
