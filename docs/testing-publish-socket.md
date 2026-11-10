# Testing the publish-ingest socket & downlink routing (scaffold)

Local test notes for the `avocado-conn` event-bus scaffold added for ENG-2476
(logging) / ENG-2477 (metrics). **This file and the scaffold are local only — nothing
is pushed.**

What was added:
- **`publish_socket`** (`src/publish.rs`): a local Unix socket where on-device
  extensions write newline-delimited JSON objects; each valid object (`{"type":…}`)
  is forwarded to the MQTT **outbox → `event/{id}`**. Default
  `/run/avocado-conn/publish.sock`; set `publish_socket = ""` to disable.
- **`[downlink]` routing** (`src/mqtt.rs`): any `cmd/{id}` message whose `type` starts
  with `log_` / `metrics_` is forwarded verbatim to the matching local agent socket
  (`downlink.log_socket` / `downlink.metrics_socket`).

## 1. Automated tests (no broker needed)

```bash
cd ~/dev/avocado-conn
cargo test          # 37 tests incl. publish::tests (5 unit + 2 in-process socket)
cargo clippy --all-targets
```

`publish::tests::socket_forwards_valid_line_to_outbox` binds the socket, writes a
line, and asserts the normalized payload lands on the outbox with an `{"ok":true}`
ack — the full ingest path, broker-free.

## 2. Manual end-to-end (real broker via Docker)

Exercises both directions against a live MQTT broker. Uses `eclipse-mosquitto`
(anonymous) for the smoke test; **prod uses EMQX** — behavior is identical for this
path (persistent session + LWT work the same).

### Setup

```bash
mkdir -p /tmp/avocado-conn-test/data

# Broker config: listen on all interfaces, allow anonymous (dev only).
cat > /tmp/avocado-conn-test/mosquitto.conf <<'EOF'
listener 1883 0.0.0.0
allow_anonymous true
EOF

docker run -d --name avo-mqtt -p 1883:1883 \
  -v /tmp/avocado-conn-test/mosquitto.conf:/mosquitto/config/mosquitto.conf \
  eclipse-mosquitto

# avocado-conn config: static MQTT creds (no claim), custom socket paths.
cat > /tmp/avocado-conn-test/config.toml <<'EOF'
data_dir = "/tmp/avocado-conn-test/data"
api_url  = "http://127.0.0.1:9"          # unused in static-mqtt mode
publish_socket = "/tmp/avocado-conn-test/publish.sock"

[intervals]
keepalive_secs = 30

[downlink]
log_socket     = "/tmp/avocado-logd.sock"
metrics_socket = "/tmp/avocado-metricsd.sock"

[mqtt]
host      = "127.0.0.1"
port      = 1883
username  = "dev-device-1"               # device_id = username → topics below
password  = "test"
client_id = "device-dev-device-1"
tls       = false
EOF
```

Topics for this device: `cmd/dev-device-1`, `event/dev-device-1`,
`presence/dev-device-1`.

### Run the daemon

```bash
cd ~/dev/avocado-conn
AVOCADO_CONN_CONFIG=/tmp/avocado-conn-test/config.toml RUST_LOG=info \
  cargo run -- run
# (varlink/rat probes to avocadoctl/rat will warn "not reachable" — expected in this
#  standalone test; the daemon continues and connects to MQTT.)
```

### Test A — uplink: publish socket → `event/{id}`

Shell 2 (subscribe to everything this device emits):

```bash
docker run --rm --network host eclipse-mosquitto \
  mosquitto_sub -h 127.0.0.1 -t 'event/#' -t 'presence/#' -v
# On daemon connect you'll immediately see the shadow:
#   event/dev-device-1 {"type":"shadow","tunnels":false,"keepalive_secs":30}
```

Shell 3 (write a metrics-style event to the ingest socket):

```bash
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/avocado-conn-test/publish.sock")
s.sendall(b'{"type":"metrics","cpu":7,"mem_pct":41}\n')
print("reply:", s.recv(256).decode().strip())   # -> reply: {"ok":true}
PY
```

**Expect** in shell 2:
`event/dev-device-1 {"type":"metrics","cpu":7,"mem_pct":41}`

Negative check (should NOT be forwarded, returns a nack):

```bash
printf '{"no":"type"}\n' | socat - UNIX-CONNECT:/tmp/avocado-conn-test/publish.sock
# -> {"ok":false,"error":"missing string field \"type\""}
```

### Test B — downlink: `cmd/{id}` → local agent socket

Shell 4 (fake `avocado-logd` listening on its control socket):

```bash
rm -f /tmp/avocado-logd.sock
socat -u UNIX-LISTEN:/tmp/avocado-logd.sock,fork -
# prints whatever avocado-conn forwards
```

Shell 3 (backend sends a log command):

```bash
docker run --rm --network host eclipse-mosquitto \
  mosquitto_pub -h 127.0.0.1 -t 'cmd/dev-device-1' \
  -m '{"type":"log_enable","filters":{"level":"debug"}}'
```

**Expect** in shell 4:
`{"type":"log_enable","filters":{"level":"debug"}}`
and the daemon logs `forwarded command to local agent kind=log`.

A `metrics_*` type routes to `metrics_socket` the same way. A `log_*`/`metrics_*`
message with no configured socket logs `no downlink socket configured; dropping`.

### Teardown

```bash
docker rm -f avo-mqtt
rm -rf /tmp/avocado-conn-test /tmp/avocado-logd.sock
```

## Notes / gotchas

- **mosquitto 2.x** denies anonymous + binds localhost-only by default — the
  `mosquitto.conf` above is required; don't run the bare image.
- **EMQX (prod):** substitute an EMQX container and real device credentials; the
  daemon path is unchanged. Anonymous access may need enabling in the EMQX dashboard
  for a quick test.
- **Permissions:** the default `publish_socket` is `/run/avocado-conn/publish.sock`
  (needs root to create `/run/avocado-conn`); the test uses a `/tmp` path so it runs
  unprivileged. On-device the daemon runs as root (see `avocado-conn.service`) and the
  socket is created `0660`. Group access for non-root agents is a TODO in `publish.rs`.
- This is scaffolding for the two RFCs
  (`avocado-cli/docs/features/{logging,observability-metrics}-extension.md`); the
  real `avocado-logd` / `avocado-metricsd` clients don't exist yet — the fake sockets
  above stand in for them.
