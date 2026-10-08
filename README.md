# TP15 — Semgrep como SAST sobre el proyecto de TP12

## Objetivo

En esta guía vas a agregar análisis estático de seguridad (SAST) al repositorio integrado de TP12. Semgrep revisará en una misma ejecución Python/Flask, los Dockerfiles, Terraform, Kubernetes y Helm.

También vas a generar un reporte JSON, publicarlo como artefacto de GitHub Actions, escribir un resumen, integrar opcionalmente SARIF con la pestaña **Security** y agregar un control estricto tipo **Andon Cord**.

## Punto de partida incluido

Este repositorio ya contiene la base necesaria hasta TP12:

```text
.
├── .github/workflows/cicd.yml       # pipeline anterior; no hay que borrarlo
├── devops-tp12/                     # aplicación integrada que se audita
│   ├── app/backend/                 # Python y Dockerfile
│   ├── app/frontend/                # Nginx y Dockerfile
│   ├── chart/                       # Helm
│   └── monitoring-k8s-manifests.yaml
├── guia-11/                         # Terraform
└── guia-06/ ... guia-12/            # antecedentes completos
```

El trabajo se hace desde la raíz del repositorio. No hace falta reconstruir los TP anteriores ni crear otra aplicación.

## Requisitos

- Git y una cuenta/repositorio en GitHub.
- Python 3 y soporte para entornos virtuales.
- Conexión a Internet para instalar Semgrep y descargar sus reglas.
- Helm, porque el workflow renderiza el chart antes de analizarlo.
- `jq` y `yamllint` para las comprobaciones locales.
- Docker y Terraform son recomendables para comprobar la base completa, pero no son necesarios para ejecutar Semgrep.

Comprobá el punto de partida:

```bash
pwd
test -f devops-tp12/app/backend/app.py
test -f devops-tp12/app/backend/Dockerfile
test -f devops-tp12/app/frontend/Dockerfile
test -d devops-tp12/chart/templates
test -f guia-11/main.tf
test -f .github/workflows/cicd.yml
```

## Paso 1 — Probar Semgrep localmente

Instalá Semgrep dentro de un entorno virtual para no mezclar sus dependencias con las del sistema:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install semgrep
semgrep --version
```

Ejecutá el análisis automático desde la raíz:

```bash
semgrep scan --config=auto --exclude=.venv --exclude='**/.terraform/**' .
```

Semgrep descarga reglas del Registry la primera vez. Un hallazgo debe analizarse y documentarse; un error de análisis indica que algún archivo o regla no se pudo procesar.

## Paso 2 — Crear el workflow

Creá `.github/workflows/semgrep.yml` sin modificar ni eliminar `cicd.yml`:

```yaml
name: DevSecOps - Semgrep SAST Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  semgrep-scan:
    name: SAST Scan Multilenguaje
    runs-on: ubuntu-latest

    steps:
      - name: Checkout del código
        uses: actions/checkout@v4

      - name: Preparar Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Instalar Semgrep
        run: python3 -m pip install semgrep

      - name: Renderizar Helm para el análisis
        run: |
          mkdir -p .semgrep-tmp
          helm template tp15 devops-tp12/chart \
            -f devops-tp12/values-local.yaml \
            > .semgrep-tmp/helm-rendered.yaml

      - name: Ejecutar Semgrep y generar JSON
        run: |
          semgrep scan \
            --config=p/owasp-top-ten \
            --config=p/python \
            --config=p/dockerfile \
            --config=p/terraform \
            --config=p/kubernetes \
            --json --output=semgrep-results.json \
            devops-tp12/app \
            devops-tp12/monitoring-k8s-manifests.yaml \
            guia-11 .semgrep-tmp || true

      - name: Resumen de Auditoría SAST
        if: always()
        shell: bash
        run: |
          test -s semgrep-results.json || printf '{"results":[],"errors":[]}' > semgrep-results.json
          total=$(jq '.results | length' semgrep-results.json)
          errores=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' semgrep-results.json)
          warnings=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' semgrep-results.json)
          errores_scan=$(jq '.errors | length' semgrep-results.json)
          {
            echo "### Reporte de Análisis Estático SAST (Semgrep)"
            echo
            echo "| Capa auditada | Reglas aplicadas | Estado |"
            echo "|---|---|---|"
            echo "| Backend Python | OWASP Top 10 + Python | Completado |"
            echo "| Contenedores | Dockerfile | Completado |"
            echo "| IaC | Terraform | Completado |"
            echo "| Orquestación | Kubernetes + Helm/YAML | Completado |"
            echo
            echo "Hallazgos: **${total}**; ERROR: **${errores}**; WARNING: **${warnings}**."
            echo "Incidencias del analizador: **${errores_scan}**."
          } >> "$GITHUB_STEP_SUMMARY"

      - name: Subir artefacto de resultados
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: semgrep-report
          path: semgrep-results.json
          retention-days: 7

      - name: Generar reporte SARIF
        run: |
          semgrep scan --config=auto \
            --sarif --output=semgrep.sarif \
            devops-tp12/app \
            devops-tp12/monitoring-k8s-manifests.yaml \
            guia-11 .semgrep-tmp || true

      - name: Cargar resultados a GitHub Code Scanning
        if: always() && hashFiles('semgrep.sarif') != ''
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif

      - name: Guard estricto de seguridad (Andon Cord)
        run: |
          semgrep scan --config=p/owasp-top-ten \
            --severity=ERROR --error \
            devops-tp12/app \
            devops-tp12/chart \
            devops-tp12/monitoring-k8s-manifests.yaml \
            guia-11
```

El workflow usa reglas para OWASP Top 10, Python, Dockerfile, Terraform y Kubernetes. Antes del análisis renderiza el chart de Helm para convertir sus templates en manifiestos YAML válidos.

## Paso 3 — Entender los dos niveles de exigencia

- El análisis informativo termina en `|| true`: genera evidencia aunque encuentre vulnerabilidades.
- El último paso no usa `|| true` y combina `--severity=ERROR --error`: si existe un hallazgo grave, el job falla y detiene la integración.

No agregues `continue-on-error` al Andon Cord. Si el guard falla, corregí el código o justificá un ajuste de regla; no ocultes el código de salida.

## Paso 4 — Validar antes de subir

```bash
yamllint -d relaxed .github/workflows/semgrep.yml

mkdir -p .semgrep-tmp
helm template tp15 devops-tp12/chart \
  -f devops-tp12/values-local.yaml \
  > .semgrep-tmp/helm-rendered.yaml

semgrep scan \
  --config=p/owasp-top-ten \
  --config=p/python \
  --config=p/dockerfile \
  --config=p/terraform \
  --config=p/kubernetes \
  --json --output=semgrep-results.json \
  devops-tp12/app \
  devops-tp12/monitoring-k8s-manifests.yaml \
  guia-11 .semgrep-tmp

python3 -m json.tool semgrep-results.json >/dev/null
jq '.results | length' semgrep-results.json
jq -r '.results[] | [.extra.severity, .check_id, .path] | @tsv' semgrep-results.json
```

El reporte local es generado y no se versiona.

## Paso 5 — Ejecutar en GitHub

```bash
git add .github/workflows/semgrep.yml
git commit -m "Agregar Semgrep SAST al pipeline"
git push origin develop
```

En GitHub verificá:

1. **Actions** → `DevSecOps - Semgrep SAST Scan`.
2. En el resumen, la tabla de las cuatro capas y la cantidad de hallazgos.
3. En **Artifacts**, `semgrep-report`, con retención de 7 días.
4. Si Code Scanning está habilitado, **Security** → **Code scanning alerts**.
5. Que el Andon Cord quede verde sin hallazgos `ERROR` y rojo si se introduce deliberadamente uno.

La carga SARIF puede no estar disponible en algunos repositorios privados. Por eso ese paso admite error; el JSON, el resumen, el artefacto y el Andon Cord siguen siendo obligatorios.

## Entrega sugerida

- `.github/workflows/semgrep.yml` versionado.
- Captura o enlace del run exitoso.
- `semgrep-report` descargado desde el run.
- Captura del `$GITHUB_STEP_SUMMARY`.
- Si se prueba el Andon Cord, evidencia del fallo controlado y luego un commit que retire la vulnerabilidad de prueba.

## Problemas frecuentes

| Problema | Causa probable | Solución |
|---|---|---|
| `semgrep: command not found` | El entorno virtual no está activo | Ejecutá `. .venv/bin/activate` |
| No se descargan reglas | Falta de red/proxy | Comprobá conectividad y repetí el scan |
| No aparece el artefacto | El JSON no se creó | Conservá `if: always()` y el JSON vacío de respaldo |
| SARIF falla | Code Scanning no habilitado/permisos | Revisá `security-events: write`; la carga es opcional |
| El workflow falla en el guard | Hay un hallazgo `ERROR` | Leé ruta/regla, corregí y volvé a ejecutar |
| Se analizaron miles de archivos | Se incluyó `.venv` o `.terraform` | Conservá ambos `--exclude` |

## Limpieza local

```bash
deactivate 2>/dev/null || true
rm -f semgrep-results.json semgrep.sarif
```

No borres el entorno virtual si pensás repetir la práctica; `.venv/` está ignorado por Git.

# TP16 — Escaneo de Seguridad de Contenedores, Dependencias e IaC con Trivy

## Objetivo y alcance

Trivy agrega controles SCA, de imagen de contenedor e IaC antes del despliegue. La aplicación objetivo es `devops-tp12/app/backend`; el pipeline conserva los workflows previos, incluido Semgrep (`.github/workflows/semgrep.yml`). El directorio `devops-TP06/` se mantiene como antecedente histórico y ya no se usa para construir la imagen TP16.

## Arquitectura y Render First

Se usa el chart real `devops-tp12/chart/`. `devops-tp12/values-prod.yaml` selecciona `tp16-postgres-credentials` como Secret externo y no contiene una contraseña. El chart conserva sus defaults de laboratorio; `createSecret: false` omite el Secret renderizado de producción. Antes del análisis IaC:

```bash
helm lint devops-tp12/chart -f devops-tp12/values-prod.yaml
helm template tp16 devops-tp12/chart -f devops-tp12/values-prod.yaml > manifests-rendered-prod.yaml
python3 -c 'import yaml; print(sum(d is not None for d in yaml.safe_load_all(open("manifests-rendered-prod.yaml"))))'
trivy config manifests-rendered-prod.yaml
```

No se analiza `chart/templates/` directamente: Helm debe resolver primero las plantillas Go. El manifiesto renderizado se conserva en el repositorio como evidencia reproducible de la auditoría y no incluye objetos Secret.

## SCA, Container Scan e IaC

```bash
bash scripts/preparar-trivy-sca.sh
trivy fs --scanners vuln --severity HIGH,CRITICAL .trivy-sca
trivy fs --scanners secret --severity HIGH,CRITICAL devops-tp12/app/backend
trivy fs --scanners vuln --format json --output trivy-fs-report.json .trivy-sca

docker build -t tp16-notes-backend:local devops-tp12/app/backend
trivy image --severity HIGH,CRITICAL tp16-notes-backend:local
trivy config manifests-rendered-prod.yaml
trivy config --misconfig-scanners terraform guia-11/
```

El inventario SCA combina requirements.txt y requirements-dev.txt en una ruta temporal porque Trivy reconoce requirements.txt, pero no descubre el archivo requirements-dev.txt directamente. El escaneo de secretos corre aparte sobre el backend fuente. El archivo temporal está excluido de Git. El escaneo de Terraform se ejecuta y se documenta con sus hallazgos. El alcance obligatorio de imagen en esta entrega es el backend. Como V2 conviene escanear también frontend y todas las imágenes efectivamente desplegadas.

## Pipeline, Andon Cord y artifacts

1. `build-and-package` construye una vez el backend TP12, lo guarda como tarball Docker con SHA-256 y publica un artifact con retención de un día.
2. `trivy-andon-cord` descarga y carga esa imagen, renderiza Helm y falla con exit code 1 ante HIGH/CRITICAL en SCA, imagen o YAML renderizado. Los reportes se adjuntan como artifacts cuando se generan.
3. `trivy-audit-report` analiza LOW/MEDIUM de forma informativa, exit code 0 y reportes JSON retenidos siete días.
4. `deploy-k8s-helm` sólo corre para `main`, depende de ambos jobs Trivy y reutiliza el mismo tarball. Requiere `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `KUBECONFIG_B64`, `POSTGRES_USER`, `POSTGRES_PASSWORD` y `POSTGRES_DB`. Sin Docker Hub o kubeconfig, no declara un despliegue exitoso; el resumen indica el paso omitido.

La Action de Trivy se fija a un commit SHA y a una versión concreta de Trivy para reducir el riesgo de supply chain. Las demás Actions existentes no se actualizaron por este TP.

## Lectura del exit code

- `0`: el comando terminó sin findings que cumplan el filtro de severidad aplicado; no significa ausencia absoluta de riesgo.
- `1`: se encontraron issues que cumplen el umbral bloqueante o falló un paso configurado como gate. Se debe revisar el detalle de Trivy, corregir la causa y volver a ejecutar.
- Los reportes LOW/MEDIUM son informativos y usan `exit-code 0`; requieren triage, pero no bloquean el build.

Una vulnerabilidad HIGH/CRITICAL en una dependencia transitiva o paquete del sistema puede existir aunque el código propio esté correcto. SCA, SAST (Semgrep), DAST (ZAP), escaneo de contenedor, IaC y observabilidad/runtime cubren riesgos distintos.

## Verificación local

```bash
bash scripts/verificar-trivy.sh
bash -n scripts/*.sh devops-tp12/scripts/*.sh
helm lint devops-tp12/chart -f devops-tp12/values-prod.yaml
helm template tp16 devops-tp12/chart -f devops-tp12/values-prod.yaml > manifests-rendered-prod.yaml
python3 -c 'import yaml; list(yaml.safe_load_all(open("manifests-rendered-prod.yaml")))'
yamllint -d relaxed .github/workflows/cicd.yml devops-tp12/values-prod.yaml
```

## Matriz de controles

| Fase / Job | Dominio | Severidades | Exit code | Acción | Evidencia |
|---|---|---|---|---|---|
| build-and-package | Build único | — | No aplica | Guarda la imagen etiquetada con `github.sha` | Artifact Docker, 1 día |
| trivy-andon-cord | SCA, imagen e IaC renderizado | HIGH, CRITICAL | 1 si hay findings | Bloquea las dependencias posteriores | Tablas de findings y YAML renderizado |
| trivy-audit-report | SCA, imagen e IaC renderizado | LOW, MEDIUM | 0 | Informa sin bloquear | Artifacts JSON, 7 días |
| deploy-k8s-helm | Publicación y despliegue | — | Fallo real de deploy; omisión explícita si faltan credenciales | Publica/despliega la imagen ya construida | Resumen del job |

V2: exigir los checks de estado mediante branch protection; fijar todas las Actions a SHA; mantener DB de Trivy cacheada; generar SBOM; hacer findings informativos accionables; versionar la imagen frontend; evaluar runner reproducible y agregar kube-state-metrics/autenticación instrumentada para completar las alertas TP12C.

# TP17 — Detección de secretos con Gitleaks

Gitleaks 8.30.0 se integra en el mismo pipeline con la configuración explícita
`.gitleaks.toml`. Se conservan sus reglas por defecto y las dos excepciones
específicas existentes; no se agrega baseline JSON ni nuevas excepciones.

- `gitleaks-andon-cord` no depende del build ni de Trivy. Hace checkout con
  `fetch-depth: 0`, usa `gitleaks/gitleaks-action@v3` y bloquea al detectar un
  secreto o un error operativo. La Action escanea los commits del evento en
  push/PR; un paso obligatorio con CLI y `--log-opts=--all` verifica además todo
  el historial disponible. Se fija `GITLEAKS_VERSION: 8.30.0`.
- `gitleaks-audit-report` depende sólo del Andon Gitleaks y usa `always()`.
  Instala la misma CLI desde su release oficial y verifica el checksum SHA-256.
  Escanea todo el historial con `.gitleaks.toml`, `--redact=100` y reporte JSON.
  No descarga ni utiliza el artifact Docker.
- La CLI usa normalmente el código 1 tanto para findings como para algunos
  errores operativos. El reporte reserva `--exit-code=10` para findings y lo
  normaliza a **1 informativo**; acepta únicamente 0/10 con JSON válido y conteo
  coherente. Cualquier otro código, configuración inválida, descarga o checksum
  fallido, o reporte inválido hace fallar el job. No se usa `continue-on-error`
  ni `|| true` para tolerar errores.
- La Action tiene comentarios, resumen y artifact automático desactivados, y
  aplica redacción. El reporte publica sólo regla, ubicación, commit,
  fingerprint y `Secret: REDACTED`; omite Match, Message y Fragment, que pueden
  incluir texto sensible. El resumen muestra sólo el número de hallazgos y su
  estado informativo. El JSON se publica como
  `tp17-gitleaks-audit-${{ github.sha }}`, con retención de siete días.
- `deploy-k8s-helm` exige éxito de build, ambos jobs Trivy y ambos jobs Gitleaks,
  además de la comprobación existente de rama `main`. Sus comprobaciones de
  credenciales y Kubernetes se mantienen.

## Historial Git y hook local

El hook observado ejecuta `gitleaks git --pre-commit --staged --config
.gitleaks.toml --redact --verbose .`: examina el diff preparado en el índice
antes de crear un commit. No audita por sí mismo todos los commits anteriores y
se instala localmente; clonar el repositorio no instala automáticamente el hook.

El análisis CI hace checkout completo y la comprobación CLI histórica recorre
los commits de todos los refs disponibles (`--all`). Por eso también detecta un
secreto agregado y borrado en commits diferentes, aunque ya no aparezca en el
árbol actual. Las excepciones se evalúan mediante la misma configuración.

## Comportamiento del pipeline

| Estado | Reporte Gitleaks | Reporte Trivy | Publicación/deploy |
|---|---|---|---|
| Ambos Andon pasan | Se genera | Se genera si build pasó | Sólo en main y con ambos reportes exitosos |
| Andon Gitleaks falla | Se ejecuta; findings informativos | Sigue su condición TP16 | Bloqueado |
| Andon Trivy falla | Se ejecuta independientemente | Se genera si build pasó | Bloqueado |
| Ambos Andon fallan | Se ejecuta | Se genera si build pasó | Bloqueado |
| Build falla o se omite | Gitleaks sigue analizando Git | Se omite, según TP16 | Bloqueado |
| Auditoría Gitleaks tiene error operativo | Job rojo; no publica JSON inválido | Independiente | Bloqueado |

Los findings del reporte son informativos, pero el Andon Gitleaks sigue siendo
bloqueante. Una ejecución verde del reporte no revierte un Andon rojo.
Para repositorios de una organización, la Action requiere configurar el secret
`GITLEAKS_LICENSE`; en una cuenta personal no se necesita. La Action recibe un
token con permisos de lectura de contenido y PR para consultar los commits, sin
habilitar comentarios.

Referencias: [Gitleaks Action v3](https://github.com/gitleaks/gitleaks-action/tree/v3)
y [Gitleaks CLI 8.30.0](https://github.com/gitleaks/gitleaks/tree/v8.30.0).
