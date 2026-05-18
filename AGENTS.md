# Project Context

**Tech Stack:** Kotlin/JVM, Gradle multi-module, Java 25

This repository is a compact Kotlin/Gradle OPC UA ECC interoperability demo toolkit. It contains two
runnable applications that exercise Eclipse Milo's ECC, RSA-DH, anonymous, and username-token
behavior.

**Primary dependencies:**

- **Eclipse Milo `1.1.4-SNAPSHOT`**: OPC UA client/server runtime. The build resolves this from
  `mavenLocal()` before Maven Central.
- **Bouncy Castle**: certificate and cryptography support.
- **Clikt**: command-line parsing for both apps.
- **Mordant**: terminal rendering for startup and probe summaries.
- **Shadow**: shaded runnable jars for the server and client.

**Architecture:**

- **server**: Starts a Milo OPC UA server, generates/persists local application certificates,
  advertises the selected endpoint matrix, registers the demo namespace, and prints startup
  diagnostics.
- **client**: Discovers a target OPC UA server, generates/persists local application certificates,
  selects endpoint/user-token probe attempts, reads standard server values, and prints probe results.

**Key separation:** There is no shared/common module. Keep small duplicated defaults close to the
server and client until real shared behavior justifies another module.

**Dependency graph:**

```text
root Gradle project
  |-- server (application, Milo server, demo namespace)
  `-- client (application, Milo client probe)
```

## Runtime Behavior Guidelines

- Keep this toolkit terminal-first. The rich console output is the evidence surface; do not add file
  reports, JSONL writers, or persistent result formats unless the user explicitly asks for them.
- Both apps deliberately auto-trust remote certificates using Milo's insecure certificate validator.
  Keep that behavior visible in terminal output when changing security flows.
- Persist only each app's own local application identities under `<data-dir>/own/application.p12`.
  Do not add remote trust-list or rejected-certificate directory management without a new requirement.
- Preserve the default security profile unless asked otherwise: ECC/RSA-DH policies,
  `None`/`Sign`/`SignAndEncrypt` modes, and anonymous plus username tokens.
- Keep the current compact structure. Prefer top-level Kotlin functions and small data classes over
  new framework layers.
- If Milo snapshot artifacts are missing, run `mise exec -- ./scripts/bootstrap-milo.sh` to install
  the required Milo snapshot artifacts into `mavenLocal()`.

## KDoc Guidelines

KDoc should help someone **reading the code** understand what something is and how to use it. It
should not explain how something was built, why it was designed that way internally, or refer to
project history.

### Class-Level KDoc

State **what** the class is and **when** you'd use it. If it has a non-obvious lifecycle or usage
pattern, describe that.

**Include:**

- What the class represents or does (one or two sentences)
- How a caller interacts with it, if non-obvious
- Important constraints (thread-safety, lifecycle, ownership)
- For public API classes: a short code example if usage is not obvious from the signature

**Omit:**

- How it works internally ("uses a ConcurrentHashMap to...", "delegates to...")
- Design rationale ("we chose this approach because...")
- References to project history

### Method/Function-Level KDoc

State **what** the method does from the caller's perspective.

**Include:**

- What it does and what it returns
- Parameter semantics when the name alone is not enough
- Notable behavior: suspension, side effects, exceptions, nullability contract
- For public API methods: a short code example when the method has non-obvious usage patterns,
  required call sequences, or interacts with other API surfaces in ways the signature does not convey

**Omit:**

- Step-by-step description of the implementation
- Internal algorithms or data structures used
- Assumptions that are only meaningful to someone editing the method body

### KDoc Tag Formatting

Descriptions for KDoc block tags such as `@property`, `@param`, and `@return` must begin with a
lowercase letter and end with a period.

### Code Examples in KDoc

When a class or method is part of the public API, consider whether a code example would help a user
understand how to use it. Good candidates for examples:

- Builder patterns or multistep construction
- Methods that participate in a larger call sequence
- Non-obvious parameter combinations or return value interpretation

Keep examples minimal: show the common case, not every option. If the usage is clear from the
signature and parameter names alone, skip the example.

### Rule of Thumb

If a sentence is only useful to someone **modifying the implementation**, it belongs in a code
comment inside the body, not in KDoc. KDoc is for **callers**.

## Kotlin Naming Conventions

- Use `PascalCase` for types and `object` declarations.
- Use `lowerCamelCase` for properties, including properties declared inside `object` and
  `companion object`.
- Use `UPPER_SNAKE_CASE` for compile-time constants and other properties that are effectively
  immutable, deeply stable constants.
- Do not use `PascalCase` for properties such as codecs, singleton accessors, or reusable factories.

## Key Entry Points

- Root build: `settings.gradle.kts`, `build.gradle.kts`, `gradle.properties`
- Milo bootstrap: `scripts/bootstrap-milo.sh`
- Docker usage: `docker/README.md`, `docker-compose.yml`
- Server CLI: `server/src/main/kotlin/com/digitalpetri/eccdemo/server/ServerMain.kt`
- Server runtime/certificates/endpoints: `server/src/main/kotlin/com/digitalpetri/eccdemo/server/ServerSecurity.kt`
- Server namespace: `server/src/main/kotlin/com/digitalpetri/eccdemo/server/DemoNamespace.kt`
- Server terminal output: `server/src/main/kotlin/com/digitalpetri/eccdemo/server/ServerTerminal.kt`
- Client CLI: `client/src/main/kotlin/com/digitalpetri/eccdemo/client/ClientMain.kt`
- Client runtime/certificates: `client/src/main/kotlin/com/digitalpetri/eccdemo/client/ClientSecurity.kt`
- Client discovery/probing: `client/src/main/kotlin/com/digitalpetri/eccdemo/client/Probe.kt`
- Client terminal output: `client/src/main/kotlin/com/digitalpetri/eccdemo/client/ClientTerminal.kt`

## Toolchain

This project uses `mise.toml` to pin Java 25. When running Gradle or Java commands from an agent or
other non-interactive shell, prefer `mise exec -- ...` so the expected JDK is on `PATH` and
`JAVA_HOME` is set. If a shell already has mise activated, the shorter commands can work, but agent
instructions should use the explicit `mise exec --` form.

## Building and Testing

| Command | Purpose |
| --- | --- |
| `mise exec -- ./scripts/bootstrap-milo.sh` | Build/install the required Milo snapshot artifacts into `mavenLocal()` |
| `mise exec -- ./gradlew build` | Compile and package both apps |
| `mise exec -- ./gradlew clean build` | Clean, compile, and package both apps |
| `mise exec -- ./gradlew :server:compileKotlin` | Compile only the server module |
| `mise exec -- ./gradlew :client:compileKotlin` | Compile only the client module |
| `mise exec -- ./gradlew :server:run --args="--help"` | Show server CLI options |
| `mise exec -- ./gradlew :client:run --args="--help"` | Show client CLI options |
| `mise exec -- ./gradlew :server:shadowJar :client:shadowJar` | Build runnable shaded jars |
| `mise exec -- ./gradlew build -x test` | Compile/package without running tests |

**Note:** This project currently has no Kotlin test sources and no JUnit dependencies. Verification
is compile/package plus local runtime checks unless the user asks to add tests.

## Application Commands

Start a local server from Gradle:

```bash
mise exec -- ./gradlew :server:run --args="--data-dir build/run-data/server --endpoint-address localhost"
```

Probe the local server from Gradle:

```bash
mise exec -- ./gradlew :client:run --args="opc.tcp://localhost:4840 --data-dir build/run-data/client --username user --password password"
```

Build shaded jars:

```bash
mise exec -- ./gradlew :server:shadowJar :client:shadowJar
```

Run the shaded server jar:

```bash
mise exec -- java -jar server/build/libs/ecc-demo-server-0.1.0-SNAPSHOT-all.jar --data-dir build/run-data/server --endpoint-address localhost
```

Run the shaded client jar:

```bash
mise exec -- java -jar client/build/libs/ecc-demo-client-0.1.0-SNAPSHOT-all.jar opc.tcp://localhost:4840 --data-dir build/run-data/client --username user --password password
```

## CLI Defaults and Filters

Server defaults:

- `--bind-address 0.0.0.0`
- `--endpoint-address localhost`
- `--port 4840`
- `--data-dir /data/server`
- `--username user`
- `--password password`

Client defaults:

- `--data-dir /data/client`
- Username attempts are only made when both `--username` and `--password` are supplied.

Both apps accept repeatable or comma-separated filters:

- `--policy`
- `--mode`
- `--token`

Use exact Milo enum/security policy names from the defaults in `ServerMain.kt` and `ClientMain.kt`.
Invalid names should fail early with clear Clikt usage errors.

## Docker

Build images:

```bash
docker build -f docker/server.Dockerfile -t ecc-demo-server .
docker build -f docker/client.Dockerfile -t ecc-demo-client .
```

Run the server for host access on port 4840:

```bash
docker run --rm -p 4840:4840 -v "$PWD/data/server:/data/server" \
  ecc-demo-server --data-dir /data/server --endpoint-address localhost
```

Run the full compose interoperability probe between containers:

```bash
docker compose --profile interop up --build --abort-on-container-exit --exit-code-from client client
```

## Verification

Use these steps to verify completed runtime or build changes:

1. **Compile/package:**
   - `mise exec -- ./gradlew clean build`
2. **Build shaded jars:**
   - `mise exec -- ./gradlew :server:shadowJar :client:shadowJar`
3. **Run locally when behavior changes:**
   - Start the server with a temporary `build/run-data/...` data directory.
   - Run the client against `opc.tcp://localhost:4840` with anonymous and username attempts.
   - Confirm terminal output clearly reports endpoint counts, auto-trust status, selected policies,
     success/failure summaries, and standard server read values.
4. **Full Docker interoperability probe when packaging or container files change:**
   - `docker compose --profile interop up --build --abort-on-container-exit --exit-code-from client client`

Before committing, ensure relevant verification passes and note any skipped runtime checks.
