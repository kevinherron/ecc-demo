# Eclipse Milo ECC Demo

This is a compact OPC UA interoperability demo for exercising Eclipse Milo ECC and RSA-DH,
anonymous and username-token profiles. It ships two Docker-first tools: a server that advertises
the demo endpoint matrix, and a client that probes an OPC UA server and prints the results in the
terminal.

Ready-to-use images are published on Docker Hub — no build step is required:

- `digitalpetri/ecc-demo-server:latest`
- `digitalpetri/ecc-demo-client:latest`

Pull and run them directly. See [Build From Source](#build-from-source) only if you need to modify
the demo.

## Run The Server Container

```bash
docker run --rm -p 4840:4840 -v "$PWD/data/server:/data/server" \
  digitalpetri/ecc-demo-server:latest --endpoint-address localhost
```

Connect OPC UA clients to:

```text
opc.tcp://localhost:4840
```

The mounted `/data/server` directory persists the server's local application certificate and key
between runs. If clients connect through a hostname or address other than `localhost`, pass
that value with `--endpoint-address`.

## Run The Client Container

Point the client at any OPC UA discovery URL reachable from inside the container.

Anonymous probe:

```bash
docker run --rm -v "$PWD/data/client:/data/client" \
  digitalpetri/ecc-demo-client:latest opc.tcp://host.docker.internal:4840
```

Username/password probe:

```bash
docker run --rm -v "$PWD/data/client:/data/client" \
  digitalpetri/ecc-demo-client:latest opc.tcp://host.docker.internal:4840 \
  --username user --password password
```

On Docker Desktop, `host.docker.internal` reaches a server running on the host. For a remote server,
use its real hostname or IP address, for example `opc.tcp://192.0.2.10:4840`.

The mounted `/data/client` directory persists the client's local application certificate and key
between runs. The client auto-trusts remote certificates for interoperability probing and reports
that behavior in the terminal output.

## Run The Built-In Interop Probe

This starts the server and then runs the client against it inside the Docker Compose network.
The Compose interop server does not publish port `4840` on the host, so the probe can run while
another local OPC UA server is already using that port.

```bash
docker compose --profile interop up --build --abort-on-container-exit --exit-code-from client client
```

If the images are already built locally, replace `--build` with `--no-build`.

To run a host-accessible server through Compose instead, use:

```bash
docker compose --profile host up --build server-host
```

## Useful Options

Both containers accept the application CLI directly after the image name.

```bash
docker run --rm digitalpetri/ecc-demo-server:latest --help
docker run --rm digitalpetri/ecc-demo-client:latest --help
```

The server publishes endpoints with these options:

| Option               | Default                            | Purpose                                                                              |
|----------------------|------------------------------------|--------------------------------------------------------------------------------------|
| `--bind-address`     | `0.0.0.0`                          | Address to bind. Repeat to bind more than one address.                               |
| `--endpoint-address` | `localhost`                        | Host name or address advertised in endpoint URLs. Repeat to advertise more than one. |
| `--port`             | `4840`                             | TCP port for OPC UA endpoints.                                                       |
| `--data-dir`         | `/data/server`                     | Directory for the server's local application certificate and key.                    |
| `--application-uri`  | `urn:eclipse:milo:ecc-demo:server` | Application URI placed in generated certificates.                                    |
| `--application-name` | `ECC Demo Server`                  | Application name shown to clients.                                                   |
| `--dns-name`         | `localhost`                        | DNS subject alternative name for generated certificates. Repeat to add more.         |
| `--ip-address`       | `127.0.0.1`                        | IP subject alternative name for generated certificates. Repeat to add more.          |
| `--username`         | `user`                             | Username accepted by the demo username identity validator.                           |
| `--password`         | `password`                         | Password accepted by the demo username identity validator.                           |
| `--policy`           | all default policies               | Security policy inclusion filter. Repeat or pass comma-separated values.             |
| `--mode`             | `None`, `Sign`, `SignAndEncrypt`   | Message security mode inclusion filter. Repeat or pass comma-separated values.       |
| `--token`            | `Anonymous`, `UserName`            | User token inclusion filter. Repeat or pass comma-separated values.                  |

The client probes a discovery URL with these options:

| Option       | Default                          | Purpose                                                                        |
|--------------|----------------------------------|--------------------------------------------------------------------------------|
| `TARGET_URL` | required                         | OPC UA discovery URL to probe.                                                 |
| `--data-dir` | `/data/client`                   | Directory for the client's local application certificate and key.              |
| `--username` | omitted                          | Username to use for username-token attempts. Requires `--password`.            |
| `--password` | omitted                          | Password to use for username-token attempts.                                   |
| `--policy`   | all default policies             | Security policy inclusion filter. Repeat or pass comma-separated values.       |
| `--mode`     | `None`, `Sign`, `SignAndEncrypt` | Message security mode inclusion filter. Repeat or pass comma-separated values. |
| `--token`    | `Anonymous`, `UserName`          | User token inclusion filter. Repeat or pass comma-separated values.            |

Policy, mode, and token filters are allowlists. Omitting a filter selects the full default list;
supplying one narrows the server endpoints or client attempts to the named values. There is no
separate exclude flag, so to omit a policy, pass the policies you do want.

```bash
--policy ECC_nistP256_AesGcm --mode SignAndEncrypt --token UserName
```

Repeatable and comma-separated forms can be mixed:

```bash
--policy ECC_nistP256_AesGcm,ECC_nistP384_AesGcm --policy RSA_DH_AesGcm
```

Filter names are matched case-insensitively, deduplicated in first-seen order, and invalid names
fail fast with a usage error.

Default security policies:

- `None`
- `Basic256Sha256`
- `Aes128_Sha256_RsaOaep`
- `Aes256_Sha256_RsaPss`
- `ECC_nistP256_AesGcm`
- `ECC_nistP256_ChaChaPoly`
- `ECC_nistP384_AesGcm`
- `ECC_nistP384_ChaChaPoly`
- `ECC_brainpoolP256r1_AesGcm`
- `ECC_brainpoolP256r1_ChaChaPoly`
- `ECC_brainpoolP384r1_AesGcm`
- `ECC_brainpoolP384r1_ChaChaPoly`
- `ECC_curve25519_AesGcm`
- `ECC_curve25519_ChaChaPoly`
- `ECC_curve448_AesGcm`
- `ECC_curve448_ChaChaPoly`
- `RSA_DH_AesGcm`
- `RSA_DH_ChaChaPoly`

## Build From Source

Building locally is only needed when modifying the demo. The published
`digitalpetri/ecc-demo-server:latest` and `digitalpetri/ecc-demo-client:latest` images are the
recommended path for everything else.

The pinned Milo source lives in a git submodule under `vendor/milo`. Initialize it before building:

```bash
git submodule update --init --recursive
```

Fresh clones can fetch it in one step with `git clone --recurse-submodules <url>`.

```bash
docker build -f docker/server.Dockerfile -t ecc-demo-server:latest .
docker build -f docker/client.Dockerfile -t ecc-demo-client:latest .
```

The Docker builds install the Milo ECC snapshot from the submodule before packaging the runnable
jars. Local builds use the unprefixed `ecc-demo-server:latest` / `ecc-demo-client:latest` tags so
they do not overwrite a previously pulled `digitalpetri/...` image.
