#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '[ERROR] %s\n' "$1" >&2
  exit 1
}

for tool in git gitleaks python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "Falta la herramienta requerida: $tool."
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel)"
cd "$repo_root"

expected_version="8.30.0"
actual_version="$(gitleaks version)"
[[ "$actual_version" == "$expected_version" ]] || fail "Se requiere Gitleaks $expected_version."
printf '[OK] Gitleaks %s instalado.\n' "$expected_version"

[[ -s .gitleaks.toml ]] || fail "Falta .gitleaks.toml o está vacío."
workflow=".github/workflows/cicd.yml"
[[ -s "$workflow" ]] || fail "Falta el workflow cicd.yml o está vacío."

python3 - <<'PY'
import sys

try:
    import tomllib
    import yaml

    with open(".gitleaks.toml", "rb") as source:
        config = tomllib.load(source)
    if config.get("extend", {}).get("useDefault") is not True:
        raise ValueError("Reglas por defecto deshabilitadas")
    with open(".github/workflows/cicd.yml", encoding="utf-8") as source:
        workflow = yaml.safe_load(source)
    jobs = workflow["jobs"]
    for name in ("gitleaks-andon-cord", "gitleaks-audit-report"):
        if not isinstance(jobs[name], dict):
            raise ValueError("Job inválido")
except Exception:
    print(
        "[ERROR] No se pudo validar TOML/YAML y ambos jobs. "
        "Se requiere Python 3.11+ con PyYAML.",
        file=sys.stderr,
    )
    sys.exit(1)
print("[OK] Configuración TOML, reglas por defecto, workflow YAML y ambos jobs.")
PY

hook=".git/hooks/pre-commit"
[[ -f "$hook" ]] || fail "Falta el hook local .git/hooks/pre-commit."
[[ -x "$hook" ]] || fail "El hook local no es ejecutable."
if bash -n "$hook" >/dev/null 2>&1; then
  printf '[OK] Hook local presente, ejecutable y con sintaxis Bash válida.\n'
else
  fail "Sintaxis Bash inválida en el hook local."
fi

[[ "$(git rev-parse --is-shallow-repository)" == "false" ]] \
  || fail "El clon es superficial: se necesita el historial completo."
printf '[OK] Clon completo; se analizarán todos los refs locales (--all).\n'

# No imprimir la salida del escáner: incluso los mensajes pueden contener
# texto sensible. El archivo temporal es privado y se elimina al salir.
umask 077
scan_log="$(mktemp "$repo_root/.git/tp17-gitleaks-check.XXXXXX")"
trap 'rm -f -- "$scan_log"' EXIT

printf '[INFO] Analizando el historial Git completo con redacción del 100%%.\n'
if gitleaks git . --config .gitleaks.toml --redact=100 \
  --log-opts=--all --exit-code=1 --no-banner >"$scan_log" 2>&1; then
  printf '[OK] Historial: 0 hallazgos no exceptuados.\n'
  printf '[RESUMEN] Todas las verificaciones completadas correctamente.\n'
else
  scan_status=$?
  printf '[ERROR] Escaneo bloqueante: hallazgos no exceptuados o error operativo (código %s).\n' \
    "$scan_status" >&2
  printf '[RESUMEN] Verificación fallida; no se muestran secretos ni salida del escáner.\n' >&2
  exit "$scan_status"
fi
