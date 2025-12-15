

# Word of Wisdom TCP Server (PoW-protected)

This repository implements a simple TCP server that returns a “word of wisdom” quote, protected from basic DoS/DDoS patterns using a Proof-of-Work (PoW) challenge–response protocol.

Key goals:
- **Cheap for the server to verify** (server-side work stays small and predictable).
- **Costly for clients to spam** (clients must spend CPU before getting a quote).
- **Stateless verification** for issued challenges (no server-side challenge storage).
- **Operational hardening** (timeouts, strict input size limits, and minimal attack surface container).

---

## Protocol

The server uses a simple two-step text protocol to avoid holding connections open while the client solves PoW.

### 1) Request a challenge
Client opens a TCP connection and sends:

```
CHALLENGE
```

Server responds with a single JSON object (`signedChallenge`) and closes the connection.

### 2) Request a quote
Client solves PoW locally, opens a new TCP connection and sends:

```
QUOTE
```

Then the client sends two JSON objects (back-to-back):
1) the exact `signedChallenge` previously received
2) the `solution`

Server verifies and responds with a single-line quote.

### Payloads

`signedChallenge` (server → client; client → server):
- `challenge`: PoW challenge parameters
- `expires_at`: unix seconds
- `sig`: `hex(HMAC-SHA256(secret, payload(challenge, expires_at)))`

`solution` (client → server):
- `nonce`: string

---

## Stateless challenge integrity (HMAC)

The server does **not** store challenges. Instead, it signs every issued challenge with an HMAC so the client cannot modify:
- `target`
- `params`
- `challenge id`

When the client returns the challenge, the server recomputes the signature and compares it in constant time.

**Important note (replay):**
- In stateless mode, the same `signedChallenge + solution` can be replayed until `expires_at`.
- This is an explicit trade-off to keep the server stateless.
- To prevent replay completely, store per-challenge state (e.g., one-time IDs or a short TTL cache / bloom filter).

---

## Proof-of-Work algorithm

### Selected approach: Hashcash-style PoW (hash-based)
The implementation supports hash-based PoW with a **target threshold**:

- Client finds a `nonce` such that `Hash(challenge || ":" || nonce) < target`.
- Server recomputes the hash once and compares to `target`.

### Why target-based difficulty (instead of “leading zeros”)
A target threshold:
- makes difficulty **continuous** (easy to adapt under load)
- avoids off-by-one style “bit counting” pitfalls
- aligns with common PoW designs (threshold comparisons)

### Why hash-based PoW for this task
Hash-based PoW gives the best operational trade-off for a public TCP server:
- server-side verification remains **sub-microsecond** scale
- client-side solve cost is tunable to be materially larger

Memory-hard PoW (e.g., Argon2id/Scrypt) was implemented/benchmarked as well, but verification becomes significantly more expensive, which is undesirable for a server defending against volumetric traffic.

---

## Difficulty & load calibration

The server calibrates difficulty based on a simple load signal:
- `activeConns` (active connections inside `handleConn`)

A convex-ish function maps load → `difficulty` (interpreted as **“percent harder than base target”**) with a clamp.

Notes:
- Difficulty is **fixed at challenge issuance** (it does not change while the client is solving).
- This is designed to prevent “moving target” issues for legitimate clients.

---

## Hardening / DoS considerations

Implemented defenses:
- **No long-lived sockets during solve**: two-step protocol prevents “idle connection” exhaustion.
- **Strict command length limit**: reads the command with a hard size cap.
- **Strict JSON payload size limit**: QUOTE path uses `io.LimitedReader`.
- **Unknown JSON fields rejected**: `DisallowUnknownFields()`.
- **Time limits**: connection-level deadline.
- **HMAC signature**: prevents client-controlled weakening of PoW parameters.

---

## Configuration

Environment variables:
- `WOW_SERVER_ADDR` — server listen address (default in Docker: `0.0.0.0:4000`)
- `WOW_HMAC_SECRET` — HMAC secret for signing challenges (**must be overridden in real deployments**)
- `WOW_SERVER_ADDR` for client — address of the server (e.g., `server:4000` inside docker-compose)

---

## Run locally

### Server

```bash
go run ./cmd/server
```

### Client

```bash
go run ./cmd/client
```

---

## Tests

```bash
go test ./...
```

Server tests cover:
- happy path
- malformed commands / malformed JSON
- signature tampering
- expired challenges
- invalid solutions
- documentation of stateless replay behavior

---

## Benchmarks

### Algorithm benchmarks

```bash
go test ./... -run '^$' -bench BenchmarkHashPoW
```

### Server throughput benchmarks

```bash
go test ./cmd/server -run '^$' -bench BenchmarkServer_ -benchtime=3s
```

Benchmarks include:
- `BenchmarkServer_CHALLENGE` — CHALLENGE req/s
- `BenchmarkServer_QUOTE` — QUOTE verify req/s

On Apple M3 Pro, the server handles ~35k CHALLENGE req/s and ~3k QUOTE verifications per second.

---

## Docker

### Build & run (compose)

```bash
docker compose up --build server
```

Run the client once:

```bash
docker compose run --rm client
```

---

## Project structure

- `cmd/server/` — TCP server
- `cmd/client/` — reference client
- `internal/pow/` — common PoW interfaces + helpers
- `internal/pow/algo/` — PoW algorithm implementations
- `internal/quotes/` — quote provider
- `pow-research/` — algorithm comparison & benchmarking notes

---

## Trade-offs / future improvements

- Prevent replay in stateless mode (short TTL store / bloom filter / nonce cache)
- Use a better load signal (EMA of requests/sec, in-flight QUOTE verifies, accept backlog)
- Backpressure limits (max concurrent QUOTE verifies)
- Structured error responses (optional, keep default behavior “fail-closed” for DoS resilience)