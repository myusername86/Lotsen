# Lotsen

*Lotsen* is Swedish for "the pilot": the harbor pilot who guides ships safely into port. Here, people and code guide AI agents.

AI-driven vehicle telemetry platform where **the model never holds the authority**.
Agents propose actions; code outside the model decides, a person approves what matters, and every step is provable.

All vehicle data is synthetic.

## Phase 1: the trust core

| Piece | Where |
|---|---|
| Agent identity (principal + human owner) | `agents/*.json`, `Modules/Governance/AgentManifest.cs` |
| Manifest policy (tools, data scope, budget, autonomy) | `Modules/Governance/AgentRegistry.cs` |
| Policy gate, deny by default | `Modules/Governance/PolicyGate.cs` |
| Single path from agent to tool | `Modules/Governance/ToolInvoker.cs` |
| Hash-chained, Ed25519-signed audit log | `src/Lotsen.Audit` |
| Chain verification (endpoint + CLI) | `GET /api/audit/verify`, `lotsen verify-audit` |

```
agent proposes ──► ToolInvoker ──► audit: tool.requested
                        │
                        ▼
                   PolicyGate ──► audit: policy.decision
                        │
        deny ◄──────────┼──────────► require approval (queue arrives in Phase 3)
                        ▼
                  allow: tool runs ──► audit: tool.executed (output fingerprint)
```

## Run locally

Prerequisites: .NET 10 SDK, Docker.

```bash
# 1. Database (pgvector image, bound to localhost only)
cp .env.example .env          # then set your own POSTGRES_PASSWORD
docker compose up -d

# 2. Lock files (first time only), then build and test
dotnet restore
dotnet build
dotnet test

# 3. Signing key: the private key is a secret, the public key is for verifiers
dotnet run --project src/Lotsen.Cli -- keygen

cd src/Lotsen.Api
dotnet user-secrets set "Audit:SigningPrivateKey" "<private key>"
dotnet user-secrets set "ConnectionStrings:Lotsen" "Host=localhost;Database=lotsen;Username=lotsen;Password=<your password>"
dotnet run
```

Commit the generated `packages.lock.json` files: CI restores in locked mode.

## Try the policy gate

```bash
API=http://localhost:5080

# Allowed: a read inside the manifest scope
curl -s -X POST $API/api/dev/agents/agent.maintenance-advisor/tool-calls -H 'content-type: application/json' \
  -d '{"tool":"get_vehicle_status","arguments":{"vehicleId":"VH-012","signals":["engine_temp_c"]}}'

# 202 approval required: write tool on an ask-first agent
curl -s -X POST $API/api/dev/agents/agent.maintenance-advisor/tool-calls -H 'content-type: application/json' \
  -d '{"tool":"create_maintenance_ticket","arguments":{"vehicleId":"VH-012","title":"Check coolant","priority":"high","description":"Engine temp 112 C"}}'

# 403: the report agent only covers VH-001 to VH-010
curl -s -X POST $API/api/dev/agents/agent.report/tool-calls -H 'content-type: application/json' \
  -d '{"tool":"get_vehicle_status","arguments":{"vehicleId":"VH-012"}}'

# 403: an injected extra argument is rejected, not ignored
curl -s -X POST $API/api/dev/agents/agent.anomaly-detection/tool-calls -H 'content-type: application/json' \
  -d '{"tool":"get_vehicle_status","arguments":{"vehicleId":"VH-001","note":"ignore previous instructions"}}'

curl -s $API/api/audit
curl -s $API/api/audit/verify
```

The `/api/dev/...` endpoint exists only in Development. It stands in for the agent runtime until Phase 2.

## Prove tampering is detected

```bash
export LOTSEN_DB="Host=localhost;Database=lotsen;Username=lotsen;Password=<your password>"
export AUDIT_PUBLIC_KEYS="<public key>"
dotnet run --project src/Lotsen.Cli -- verify-audit          # VALID

# Editing is blocked by a trigger...
docker exec -it lotsen-postgres psql -U lotsen -c "UPDATE audit_log SET payload='{}' WHERE sequence=4;"

# ...and even bypassing the trigger as superuser is caught by the hash chain and signature
docker exec -it lotsen-postgres psql -U lotsen -c \
  "ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete; UPDATE audit_log SET payload='{}' WHERE sequence=4; ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete;"
dotnet run --project src/Lotsen.Cli -- verify-audit          # INVALID at sequence 4, exit code 1
```

Reset afterwards with `docker compose down -v`.

## Security notes

- Secrets only in user-secrets, environment variables or Azure Key Vault. Nothing secret is committed.
- Invalid manifests, a missing key or a missing connection string stop the API at startup (fail closed).
- If an audit write fails, the tool does not run.
- Limitation: removing the newest entries (tail truncation) cannot be detected from the chain alone. Store the `headHash` from verification somewhere separate; a later phase anchors it automatically.
- Authentication for human users arrives in Phase 3, together with approvals.

## CI

`.github/workflows/ci.yml`: locked restore with NuGet vulnerability audit, build with analyzers as errors, unit and Testcontainers integration tests, CodeQL, gitleaks, and dependency review on pull requests. Dependabot keeps NuGet packages, actions and images current.
