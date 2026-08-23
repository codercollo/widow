# widow

**A distributed, replay-resistant session and token store for Go services. No Redis required.**

```go
import "github.com/yourname/widow"
```

Widow is a session/token store built in the spirit of `alexedwards/scs` — same idea (issue a token, validate it on every request, expire it, invalidate it on logout) — but designed for services that run as a cluster rather than a single instance, and without requiring Redis or Postgres as a dependency just to share session state. Session data replicates directly between nodes, and every token carries replay protection so a captured or leaked token can't be silently reused from a different node.

> Built on ideas from _Let's Go Further_ (Alex Edwards), _Distributed Services with Go_ (Travis Jeffery), and _Black Hat Go_ (Steele, Patten, Kottmann).

---

## The problem

`scs` and similar libraries solve session management well, but every store they ship with — memory, Redis, Postgres — is either single-node or requires standing up a separate stateful service. For a small cluster, that's often disproportionate: you don't want to operate Redis just so five API nodes agree on who's logged in.

Separately, most token implementations validate a signature and an expiry and stop there. They don't check whether a _specific token_ has already been used in a way that shouldn't repeat — so a token sniffed off the wire (or leaked in a log) stays valid for anyone who has it until it naturally expires.

Widow addresses both: session state gossips between nodes directly, and every token includes a monotonic per-session counter so replay across nodes is detectable instead of invisible.

---

## How the three books map onto this package

| Source                         | Concept                                             | Where it shows up in Widow                                                                                                                                                  |
| ------------------------------ | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| _Let's Go Further_             | Stateful token authentication                       | Token issuance, hashing, and lookup conventions — `token.go`                                                                                                                |
| _LGF_                          | Activation / expiry patterns                        | TTL and explicit invalidation ("log out everywhere")                                                                                                                        |
| _LGF_                          | Permission-scoped middleware                        | `widow.RequirePermission("...")` middleware, same shape as the book's `requirePermission`                                                                                   |
| _Distributed Services with Go_ | Serf gossip membership                              | Session records propagate between nodes without a central store — `internal/gossip`                                                                                         |
| _DSwG_                         | mTLS between services                               | All inter-node session replication is mutually authenticated — `internal/transport`                                                                                         |
| _DSwG_                         | Raft (optional strong-consistency mode)             | For deployments that need linearizable "invalidate everywhere, immediately" instead of eventual convergence — `internal/consensus`                                          |
| _Black Hat Go_                 | Secure token/nonce generation, signature validation | Hardened random token generation and HMAC verification — `internal/crypto`                                                                                                  |
| _BHG_                          | Replay-attack analysis                              | Applied defensively: a monotonic per-session counter embedded in each token, checked on validation, so a duplicated/replayed token is detected instead of silently accepted |

---

## Usage

```go
store, err := widow.New(widow.Config{
    ClusterKey:  os.Getenv("WIDOW_CLUSTER_KEY"),
    GossipAddrs: []string{"node-1:7946", "node-2:7946"},
    TLS:         widow.LoadTLSConfig("certs/widow.pem", "certs/widow-key.pem"),
    TTL:         24 * time.Hour,
})
if err != nil {
    log.Fatal(err)
}
defer store.Close()

sm := widow.NewSessionManager(store)

mux.Handle("/dashboard", sm.Authenticate(dashboardHandler))
mux.Handle("/admin", sm.Authenticate(sm.RequirePermission("admin:access", adminHandler)))
```

Issuing and revoking:

```go
token, err := sm.Issue(ctx, userID, widow.WithScopes("read", "write"))
...
sm.InvalidateAll(ctx, userID) // logs the user out on every node
```

---

## Project structure

```
widow/
├── cmd/
│   └── widow-demo/
│       ├── main.go              # starts a node: --gossip-addr, --peers, --tls-cert flags
│       ├── handlers.go          # toy /login, /dashboard, /logout routes
│       ├── docker-compose.yml   # spins up 3 nodes to see replication happen locally
│       └── README.md
├── internal/
│   ├── gossip/
│   │   ├── gossip.go          # wraps memberlist/serf: Join(), Leave(), Members()
│   │   ├── delegate.go        # memberlist.Delegate: NodeMeta, NotifyMsg, state merge hooks
│   │   ├── broadcast.go       # queues session events for gossip dissemination
│   │   ├── events.go          # SessionCreated / SessionTouched / SessionRevoked + encoding
│   │   ├── state.go           # in-memory session table + conflict-merge logic
│   │   ├── state_test.go
│   │   └── gossip_test.go     # two-node convergence test
│   ├── transport/
│   │   ├── tls.go             # LoadTLSConfig(certPath, keyPath, caPath)
│   │   ├── mtls.go            # client-cert verification, shared by gossip + consensus
│   │   └── tls_test.go
│   ├── consensus/
│   │   ├── raft.go            # sets up hashicorp/raft, bootstraps/joins cluster
│   │   ├── fsm.go             # raft.FSM: Apply(), Snapshot(), Restore()
│   │   ├── commands.go        # IssueSession / InvalidateSession log commands
│   │   ├── store.go           # log/stable store (raft-boltdb, or in-memory for tests)
│   │   ├── transport.go       # raft.NetworkTransport over internal/transport's mTLS
│   │   └── fsm_test.go
│   └── crypto/
│       ├── token.go           # secure random token/ID generation (crypto/rand)
│       ├── hmac.go            # Sign()/Verify() with HMAC-SHA256
│       ├── counter.go         # per-session monotonic counter: Next(), Validate()
│       ├── hash.go            # one-way hash of tokens for storage/lookup
│       ├── crypto_test.go
│       └── replay_test.go     # proves a replayed counter value is rejected
├── test/
│   ├── cluster_test.go        # N real nodes, asserts replication within X ms
│   ├── partition_test.go      # kills gossip between two nodes, checks local fallback
│   ├── consensus_test.go      # same as cluster_test with Raft mode on, checks linearizability
│   └── fixtures/
│       ├── ca.pem
│       ├── node-1.pem / node-1-key.pem
│       └── node-2.pem / node-2-key.pem
├── docs/
│   ├── architecture.md        # gossip vs. consensus mode, when to pick which
│   ├── getting-started.md     # walkthrough of widow-demo
│   └── consistency-modes.md   # eventual vs. linearizable tradeoff, expanded
├── widow.go        # Store type, New(), Close() — package entrypoint
├── config.go       # Config struct, defaults, validation
├── token.go        # Token type, Issue(), Verify(), scopes/claims encoding
├── session.go      # Session type, SessionManager, Authenticate(), InvalidateAll()
├── middleware.go   # Authenticate, RequirePermission http.Handler wrappers
├── options.go      # functional options: WithScopes(), WithTTL(), ...
├── errors.go       # ErrExpired, ErrReplayed, ErrRevoked, ErrNotFound
├── doc.go          # package-level godoc
├── go.mod / go.sum
├── Makefile        # make test, make certs, make demo-up
├── .golangci.yml
└── LICENSE
```

**Suggested build order:** `internal/crypto` → `token.go` / `session.go` (single-node, no networking) → `internal/transport` (mTLS) → `internal/gossip` (replication) → `middleware.go` → `cmd/widow-demo` (prove multi-node works end to end) → `internal/consensus` last, since it's the optional advanced mode.

---

## Design notes

- **Two consistency modes.** Default is gossip-based, eventually consistent — fine for "is this token valid," which tolerates a few hundred milliseconds of propagation lag. Optional Raft mode trades availability for linearizable invalidation, for cases like forced logout on account compromise.
- **Replay detection, not replay prevention at the network layer.** Widow doesn't inspect traffic or intercept requests outside its own middleware — it only tracks whether a token's counter has already been seen, and flags/rejects accordingly.
- **Drop-in for existing `scs`-style code.** The `SessionManager` API is intentionally close to `scs` so migrating an existing single-node app is mostly a constructor change.

## License

MIT
