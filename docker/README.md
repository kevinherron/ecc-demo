# Docker

Build the images:

```bash
docker build -f docker/server.Dockerfile -t ecc-demo-server:latest .
docker build -f docker/client.Dockerfile -t ecc-demo-client:latest .
```

Run the server for host access on port 4840:

```bash
docker run --rm -p 4840:4840 -v "$PWD/data/server:/data/server" \
  ecc-demo-server:latest --endpoint-address localhost
```

The example above persists generated OPC UA certificates and keys under
`./data/server` on the host by mounting it into the container at `/data/server`.
The compose probe does the same for the client with `./data/client` mounted at
`/data/client`.

Run the full compose interoperability probe between containers:

```bash
docker compose --profile interop up --build --abort-on-container-exit --exit-code-from client client
```

The interop server is only exposed inside the Compose network, so this command does not need host
port 4840 to be free.

If the images are already built locally, replace `--build` with `--no-build`.

To run a host-accessible server through Compose instead, use:

```bash
docker compose --profile host up --build server-host
```
