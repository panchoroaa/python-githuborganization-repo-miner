# Python Miner

[English](README.md) | **[Español](README.es.md)**

Un miner de vulnerabilidades para organizaciones de GitHub que usa CodeQL para realizar análisis de seguridad automatizado sobre todos los repositorios de una organización, y [Syft](https://github.com/anchore/syft) para generar un Software Bill of Materials (SBOM) por cada repositorio.

## Resumen

Esta herramienta automatiza el proceso de:

1. Obtener todos los repositorios de una organización de GitHub mediante la API REST de GitHub
2. Clonar cada repositorio localmente
3. Ejecutar el análisis de seguridad de CodeQL
4. Generar un SBOM en formato CycloneDX JSON por repositorio con Syft (ya sea durante el scan o de forma independiente, reutilizando los clones existentes)
5. Consolidar todos los resultados en un único reporte JSON estructurado

## Requisitos previos

- Python 3.10 o superior
- [CodeQL CLI](https://codeql.github.com/docs/codeql-cli/) instalado y disponible en tu PATH
- [Syft](https://github.com/anchore/syft) instalado y disponible en tu PATH (ver [Instalación de Syft](#instalación-de-syft)); solo es necesario para la generación de SBOM
- Git instalado
- Un personal access token de GitHub

## Instalación

```powershell
# Clonar el repositorio
git clone <repository-url>
cd python-miner

# Crear y activar el entorno virtual
python -m venv .venv
.venv\Scripts\activate        # Windows PowerShell
# source .venv/bin/activate   # macOS/Linux

# Instalar el proyecto en modo de desarrollo
pip install -e ".[dev]"
```

## Instalación de Syft

Syft es una CLI externa (binario de Go) de [Anchore](https://github.com/anchore/syft). El miner la invoca mediante `subprocess`, exactamente igual que CodeQL, por lo que debe estar instalada y disponible en tu `PATH`.

**Windows (winget):**

```powershell
winget install anchore.syft
```

**Windows/macOS/Linux (Scoop):**

```powershell
scoop install syft
```

**macOS (Homebrew):**

```bash
brew install syft
```

**Linux/macOS (script de instalación oficial, ver la [documentación de Syft](https://github.com/anchore/syft#installation)):**

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

Verificar la instalación:

```powershell
syft version
```

> **Nota:** Solo es necesario para la generación de SBOM. `miner scan` igualmente ejecuta el análisis de CodeQL si Syft no está instalado, pero omite los SBOM con una advertencia.

## Configuración

### Token de GitHub

El miner requiere un personal access token de GitHub para autenticar las solicitudes a la API.

Crea un archivo `.env` en la raíz del proyecto (no lo subas al control de versiones):

```
GITHUB_TOKEN=ghp_your_token_here
```

El token se **carga automáticamente** desde el archivo `.env` — no es necesario configurar variables de entorno manualmente. También puedes definirlo como variable de entorno si lo prefieres:

```powershell
# Windows PowerShell
$env:GITHUB_TOKEN = "ghp_your_token_here"

# macOS/Linux
export GITHUB_TOKEN="ghp_your_token_here"
```

> **Scopes requeridos para el token:** `public_repo` (solo repos públicos) o `repo` (repos públicos + privados).

**Importante:** Nunca subas tu token al control de versiones. El `.gitignore` ya excluye los archivos `.env`.

### Packs de consultas de CodeQL

El miner necesita los query packs de CodeQL para ejecutar los análisis de seguridad. Hay dos formas de proveerlos:

**Opción A — Repositorio local de consultas (recomendada):**

El miner puede **auto-descargar** los packs automáticamente. Si no encuentra packs locales, `miner scan` clona [github/codeql](https://github.com/github/codeql) (shallow, `--depth 1`) en `~/cybersec/codeql-repo` y lo utiliza. Desactívalo con `--no-fetch-packs`, o clónalo manualmente:

```powershell
git clone https://github.com/github/codeql ~/cybersec/codeql-repo
```

Si el destino ya existe pero no es un packs root válido, el miner reporta el error y cae al fallback de packs del registry en lugar de borrar nada.

El miner **detecta** los packs en estas ubicaciones (en orden):

1. Variable de entorno `CODEQL_PACK_ROOT`
2. `~/cybersec/codeql-repo`
3. `~/codeql-repo`
4. `./codeql-repo` (directorio actual)

También puedes pasar la ruta explícitamente con `--packs-root` (cuando se pasa explícitamente, el miner nunca auto-descarga):

```powershell
miner scan --organization example-org -O results.json --packs-root C:\path\to\codeql-repo
```

**Opción B — Packs del registry:**

Descarga los packs desde el GitHub Container Registry (requiere un token con scope `read:packages`):

```powershell
codeql pack download codeql/python-security-extended
codeql pack download codeql/java-security-extended
codeql pack download codeql/javascript-security-extended
# ... y otros lenguajes según sea necesario
```

### Lenguajes soportados

El miner analiza repositorios cuyos lenguajes (según los reporta la API de GitHub) incluyen al menos uno de los lenguajes soportados por CodeQL:

```
python, java, javascript, typescript, csharp, cpp, c, go, ruby, swift, rust
```

- `typescript` y `c` reutilizan las suites de consultas de `javascript` y `cpp` respectivamente.
- C#/C++/C/Go/Swift/Rust normalmente requieren que el proyecto se compile correctamente para poder crear la base de datos de CodeQL; Python/JavaScript/TypeScript se analizan "buildless" (sin compilación).
- Los repositorios sin ningún lenguaje soportado reciben el estado `unsupported_language` y se omiten (aun así se generan los SBOM cuando Syft está disponible).

## Uso

La CLI tiene dos comandos:

- `miner scan ...` — Análisis de seguridad con CodeQL (y generación de SBOM, si Syft está instalado)
- `miner sbom ...` — Generación de SBOM solo, sobre repositorios ya clonados (sin CodeQL)

> **Nota:** Con más de un comando registrado, Typer exige el nombre del subcomando (`miner scan ...`, `miner sbom ...`). Las versiones anteriores de este proyecto «aplanaban» el único comando como `miner --organization ...`; esa invocación ya no funciona.

### Escanear toda una organización

```powershell
miner scan --organization <org-name> -O results.json
```

### Escanear un solo repositorio

```powershell
miner scan --repo <org>/<repo> -O results.json
```

### Generar solo SBOMs (reutilizar repositorios clonados)

`miner sbom` ejecuta Syft sobre repositorios que **ya están clonados** en un directorio de trabajo, sin repetir el análisis de CodeQL. Escribe un archivo CycloneDX JSON por repositorio más un reporte JSON general:

```powershell
miner sbom --organization <org-name> --workdir repos --output-dir sbom-output
```

Para reutilizar los clones producidos por `miner scan`, ejecuta `scan` con un `--workdir` persistente (los clones se conservan ahí y no se borran después del scan). Luego:

```powershell
# 1) Scan + CodeQL + SBOMs; los clones se guardan en ./repos
miner scan --organization <org-name> --workdir repos -O results.json

# 2) Después, regenerar solo los SBOM reutilizando los clones
miner sbom --organization <org-name> --workdir repos --output-dir sbom-output
```

También se puede procesar un solo repositorio con `--repo`:

```powershell
miner sbom --repo OWASP/NodeGoat --workdir repos --output-dir sbom-output
```

Los repositorios que no fueron clonados (no existen en `--workdir`) se reportan con estado `failed` ("Repository not cloned ...") y el proceso continúa con el resto.

> **Nota:** Re-ejecutar `scan` contra el mismo `--workdir` funciona bien — cada repositorio se re-clona desde cero antes del análisis.

### Opciones — `miner scan`

| Opción | Corta | Descripción | Valor por defecto |
|--------|-------|-------------|-------------------|
| `--organization` | `-o` | Nombre de la organización de GitHub | - |
| `--repo` | `-r` | Repositorio único a escanear (ej. `OWASP/NodeGoat`) | - |
| `--output` | `-O` | Ruta del archivo JSON de salida | `results.json` |
| `--workdir` | `-w` | Directorio de trabajo para clones y bases de datos. Los clones se **conservan** cuando se indica, se borran si se omite (temp dir) | Directorio temporal del sistema |
| `--packs-root` | `-p` | Ruta a los query packs locales de CodeQL | Auto-detectada |
| `--fetch-packs/--no-fetch-packs` | | Auto-clonar `github/codeql` cuando no se encuentran packs locales | Activado |
| `--sbom-dir` | | Directorio donde se escriben los SBOM por repositorio | `sboms` |

### Opciones — `miner sbom`

| Opción | Corta | Descripción | Valor por defecto |
|--------|-------|-------------|-------------------|
| `--organization` | `-o` | Nombre de la organización de GitHub | - |
| `--repo` | `-r` | Repositorio único (ej. `OWASP/NodeGoat`) | - |
| `--workdir` | `-w` | Directorio que contiene los repositorios ya clonados | `repos` |
| `--output-dir` | `-O` | Directorio de salida para los archivos SBOM y el reporte | `sbom-output` |

> Para ambos comandos se requiere al menos uno de `--organization` o `--repo`.

### Ejemplos

```powershell
# (1) Escanear todos los repos de una organización (CodeQL + SBOMs)
miner scan --organization pallets -O results.json

# (2) Escanear un solo repositorio
miner scan --repo OWASP/NodeGoat -O nodegoat.json

# (3) Repo único con organización explícita, conservando los clones para reutilizarlos después
miner scan --organization OWASP --repo NodeGoat -O nodegoat.json -w repos --sbom-dir sboms

# (4) Generación de SBOMs solamente, reutilizando los clones de (3)
miner sbom --organization OWASP --repo NodeGoat --workdir repos --output-dir sbom-output

# (5) Generación de SBOMs solamente para toda una organización, reutilizando clones existentes
miner sbom --organization pallets --workdir repos --output-dir sbom-output

# (6) Con un directorio de trabajo y packs root específicos
miner scan --organization expressjs -O results.json -w C:\work\miner-temp --packs-root C:\codeql-repo
```

> **Rutas de Windows con espacios:** Encierra entre comillas las rutas que contengan espacios:
> ```powershell
> miner scan --organization pallets -O results.json -w "C:\Users\John Doe\work"
> ```

La herramienta mostrará el progreso en la terminal, indicando qué repositorio se está procesando y su estado de análisis.

### Ejemplo de salida en terminal

**Scan de organización (`miner scan`):**
```
Using CodeQL packs from: C:\Users\you\codeql-repo
SBOMs will be written to: sboms
Found 17 repositories.
  flask: analyzed
  flask-sqlalchemy: analyzed
  jinja: analyzed
  click: analyzed
  ...
Results written to results.json
```

**Scan de un solo repositorio:**
```
Using CodeQL packs from: C:\Users\you\codeql-repo
SBOMs will be written to: sboms
Scanning single repository: OWASP/NodeGoat
  NodeGoat: analyzed
Results written to nodegoat.json
```

**Ejecución de SBOMs solamente (`miner sbom`):**
```
Generating SBOM for repository: OWASP/NodeGoat
  OWASP/NodeGoat: success
SBOM report written to sbom-output\sbom-report.json
```

## Formato de salida

### Resultados del scan (`miner scan`)

El JSON de salida (`-O results.json`) contiene:

- **organization**: El nombre de la organización analizada
- **summary**: Estadísticas agregadas (total de repos, analizados, fallidos, cantidad de findings)
- **repositories**: Arreglo de resultados por repositorio, cada uno con:
  - `name`, `url`, `status`, `languages`
  - `findings`: Arreglo de vulnerabilidades con `rule_id`, `severity`, `message`, `file`, `start_line`
  - `sbom`: Metadatos del SBOM del repositorio (cuando Syft está instalado), con `full_name`, `commit`, `generated_at`, `syft_version`, `status`, `components`, `sbom_path`
  - `error_message`: Presente cuando el estado indica una falla

Los repositorios se ordenan alfabéticamente. Los findings dentro de cada repositorio se ordenan por archivo, línea e ID de regla.

### Ejemplo de estructura JSON (scan)

```json
{
  "organization": "pallets",
  "summary": {
    "repositories": 17,
    "analyzed": 13,
    "clone_failed": 0,
    "unsupported": 4,
    "database_failed": 0,
    "analysis_failed": 0,
    "findings": 42
  },
  "repositories": [
    {
      "name": "flask",
      "url": "https://github.com/pallets/flask",
      "status": "analyzed",
      "languages": ["Python"],
      "findings": [
        {
          "rule_id": "py/sql-injection",
          "severity": "warning",
          "message": "Constructed SQL query from user input",
          "file": "src/flask/app.py",
          "start_line": 123,
          "end_line": null,
          "code_snippet": "cursor.execute(query)"
        }
      ],
      "sbom": {
        "full_name": "pallets/flask",
        "commit": "d73fa1cdcbd8b1465c151db8924ba58b1dd14e35",
        "generated_at": "2026-09-24T14:45:26.096207Z",
        "syft_version": "1.51.0",
        "status": "success",
        "components": 122,
        "sbom_path": "C:\\path\\to\\sboms\\flask.cdx.json",
        "error_message": null
      }
    }
  ]
}
```

### Estados de repositorio (scan)

| Estado | Significado |
|--------|-------------|
| `analyzed` | Analizado correctamente con CodeQL |
| `clone_failed` | No se pudo clonar el repositorio (error de red, autenticación requerida, etc.) |
| `unsupported_language` | No se encontraron lenguajes soportados por CodeQL en el repositorio |
| `database_failed` | CodeQL no pudo crear una base de datos para este repositorio |
| `analysis_failed` | El análisis de CodeQL falló o produjo un error |

### Archivos de salida de SBOM (`miner scan --sbom-dir` / `miner sbom --output-dir`)

Cada repositorio con un clon funcional obtiene su propio archivo CycloneDX JSON independiente:

```
sbom-output/
├── sbom-report.json            # Reporte SBOM general (agregado)
└── sboms/
    ├── NodeGoat.cdx.json       # SBOM en CycloneDX JSON, uno por repositorio
    └── flask.cdx.json
```

- **`<name>.cdx.json`** — el SBOM original de Syft en formato CycloneDX JSON (spec `1.5+`). Contiene `metadata.component` (el propio repositorio) y un arreglo `components` con los paquetes identificados (nombre, versión, `purl`, licencias cuando se pueden resolver).
- **`sbom-report.json`** — el JSON general de resultados. Por repositorio registra: `full_name` (org/repo), `commit` analizado (HEAD del clon), `generated_at`, `syft_version`, `status`, `components` (cantidad) y `sbom_path`. El archivo SBOM original se conserva independiente; solo los metadatos se incrustan en el reporte.

### Ejemplo de estructura JSON (reporte SBOM)

```json
{
  "organization": "OWASP",
  "generated_at": "2026-09-24T14:43:55.787222+00:00",
  "syft_version": "1.51.0",
  "summary": {
    "repositories": 1,
    "success": 1,
    "no_components": 0,
    "failed": 0,
    "components": 419
  },
  "repositories": [
    {
      "full_name": "OWASP/NodeGoat",
      "commit": "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
      "generated_at": "2026-09-24T14:43:54.188461Z",
      "syft_version": "1.51.0",
      "status": "success",
      "components": 419,
      "sbom_path": "C:\\Users\\you\\sbom-output\\sboms\\NodeGoat.cdx.json",
      "error_message": null
    }
  ]
}
```

### Estados de SBOM

| Estado | Significado |
|--------|-------------|
| `success` | Syft se ejecutó correctamente e identificó al menos un componente |
| `no_components` | Syft se ejecutó correctamente pero no identificó componentes (un resultado válido, **no** es una falla) |
| `failed` | El repositorio no fue clonado, Syft no está disponible, o Syft falló; los detalles están en `error_message` |

> Un repositorio cuyo clon falta se reporta como `failed` con `"Repository not cloned at ..."` y la ejecución continúa con los repositorios restantes.

## Ejemplo de uso completo

```powershell
# 1. Verificar los requisitos previos
syft version          # ej. 1.51.0
codeql version        # ej. 2.26.4
git version

# 2. Escanear una organización: CodeQL + SBOMs, clones conservados en ./repos
miner scan --organization OWASP --repo NodeGoat -w repos -O nodegoat.json --sbom-dir sboms

# 3. Inspeccionar las salidas
#    - nodegoat.json                 : findings de CodeQL + metadatos del SBOM
#    - sboms\NodeGoat.cdx.json       : SBOM en CycloneDX JSON (archivo independiente)
#    - (buscar "components" para ver la cantidad de componentes)

# 4. Después, regenerar solo los SBOM — sin CodeQL, reutilizando ./repos
miner sbom --organization OWASP --repo NodeGoat --workdir repos --output-dir sbom-output

# 5. Inspeccionar el reporte de SBOMs
#    - sbom-output\sbom-report.json  : reporte agregado (commit, versión de syft, estado, cantidad, ruta)
#    - sbom-output\sboms\NodeGoat.cdx.json : el nuevo SBOM en CycloneDX JSON
```

## Notas de verificación (diferencias observadas)

El inventario depende de los archivos disponibles en el repositorio y de lo que Syft pueda identificar. Verificamos la herramienta contra:

- **OWASP/NodeGoat** (JavaScript, tiene `package.json` + `package-lock.json`): el SBOM listó **419 componentes** y **las 16 dependencias directas** de `package.json` (ej. `express@4.16.4`, `mongodb@2.2.36`) con versiones que coinciden con el lockfile. Syft también catalogó las referencias de GitHub Actions de `.github/workflows/*` (ej. `actions/checkout@v2`). De las 658 entradas de nivel superior del lockfile, 301 terminaron como componentes npm; la mayoría de las entradas omitidas son herramientas de dev/test (ej. `@types/*`, paquetes relacionados con cypress, entradas transitivas de `ajv`/`lodash`). El conteo no coincide con la cantidad de entradas del lockfile: Syft cataloga lo que su catalogador de npm puede resolver y deduplica.
- **pallets/flask** (Python, `pyproject.toml`, sin lockfile): el SBOM listó **122 componentes** (105 de PyPI) y **las 6 dependencias directas** (`blinker`, `click`, `itsdangerous`, `jinja2`, `markupsafe`, `werkzeug`). Como no hay lockfile, las versiones provienen de las restricciones declaradas en distintos archivos, lo que puede producir **múltiples entradas de versión por paquete** (ej. `werkzeug` apareció como 2.3.3 y 3.1.8) en lugar de una única versión resuelta.

En resumen: con lockfiles el SBOM es preciso para lo que el catalogador puede resolver; sin ellos, las versiones reflejan las restricciones declaradas y pueden estar duplicadas o no ser específicas. Archivos como binarios vendored, o dependencias declaradas solo en documentación/CI, pueden no quedar incluidos.

## Por qué no funciona sin configuración previa

Instalar solo las dependencias (`pip install -e ".[dev]"`) **no alcanza**. El miner solo orquesta herramientas externas, así que un clon reciente fallará hasta que configures todos los requisitos previos.

| Pieza faltante | Síntoma |
|----------------|---------|
| `GITHUB_TOKEN` no definido (sin archivo `.env`) | `RuntimeError: GITHUB_TOKEN environment variable is not set.` |
| CodeQL CLI no instalado o no en `PATH` | `FileNotFoundError` o `codeql: command not found` |
| Sin query packs disponibles | `Query suite not found at .../codeql-suites/python-security-extended.qls` |
| Syft no instalado o no en `PATH` | `miner sbom` termina con `Syft not found in PATH`; `miner scan` omite los SBOM con una advertencia |
| Git no instalado | Todos los repos se reportan como `clone_failed` |

**Checklist completo antes de ejecutar un scan:**

1. El archivo `.env` existe con `GITHUB_TOKEN=ghp_...` (ver [Token de GitHub](#token-de-github)).
2. `codeql version` funciona desde tu terminal.
3. Los query packs están disponibles — normalmente se **auto-descargan** en el primer `scan` (ver [Packs de consultas de CodeQL](#packs-de-consultas-de-codeql)); o desactivalo con `--no-fetch-packs` y provéelos tú mismo.
4. `syft version` funciona desde tu terminal (solo si quieres SBOMs).
5. `git version` funciona desde tu terminal.

Si todo esto se cumple, `miner scan --organization <org-name> -O results.json` o `miner scan --repo <org>/<repo> -O results.json` deberían producir un reporte JSON válido, y `miner sbom --organization <org-name> --workdir repos --output-dir sbom-output` debería producir el reporte de SBOM.

## Ejecutar tests

```powershell
pytest
```

## Estructura del proyecto

```
python-miner/
├── pyproject.toml
├── .gitignore
├── .env.example
├── README.md
├── README.es.md
├── src/
│   └── miner/
│       ├── __init__.py
│       ├── cli.py          # Interfaz CLI de Typer (comandos scan + sbom)
│       ├── models.py       # Modelos de datos Pydantic
│       ├── github.py       # Interacción con la API de GitHub
│       ├── git_ops.py      # Operaciones de clonado con Git
│       ├── codeql.py       # Wrapper de la CLI de CodeQL
│       ├── syft.py         # Wrapper de la CLI de Syft (generación de SBOM)
│       └── sarif.py        # Parseo de archivos SARIF
└── tests/
    ├── test_models.py
    ├── test_sarif.py
    ├── test_syft.py
    ├── test_sbom_helpers.py
    └── test_github.py
```

## Licencia

MIT