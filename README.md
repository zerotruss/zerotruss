# zerotruss

An audit and boundary checkpoint for the tool calls an AI agent makes over MCP. It runs as an
external guardrail for [agentgateway](https://agentgateway.dev): the gateway asks this service
before and after every tool call. The service allows or denies each call against a boundary
file (allowed tools, allowed folders, expiry) and writes every decision to a hash-chained log,
so the log shows if it was edited.

## Setup

Needs Python 3.12.

    scripts/setup.sh                       # virtual environment and locked dependencies
    cp boundary.example.json boundary.json # then edit the folder and the expiry date
    .venv/bin/python -m zerotruss.sign init  # once: makes the signing key (kept in the macOS Keychain)
    .venv/bin/python -m zerotruss.sign sign  # every time boundary.json changes

Dependencies are pinned to exact versions with hashes (`requirements.txt`,
`requirements-dev.txt`) and installed wheels-only. See `requirements.in` for the rules.

## The boundary

`boundary.json` has three fields: `allowed_tools` (exact tool names), `allowed_folders`
(absolute paths) and `expires_at` (a date and time with a timezone, for example
`2030-01-01T00:00:00Z`). Anything not allowed is denied. Your own `boundary.json`, its signature
and your public key are not committed.

### Signing

The service only starts with a boundary that carries a valid Ed25519 signature, so anything that
can edit `boundary.json` cannot widen it without the private key.

- `zerotruss.sign init` makes the key. The private half stays in the macOS Keychain (it is never
  written to a file or printed); the public half is written to `boundary.pub`, which is not secret.
- `zerotruss.sign sign` signs the exact bytes of `boundary.json` and writes `boundary.json.sig`.
  It refuses a boundary the service would refuse. Sign again after every edit, then restart.
- The service reads `boundary.json`, `boundary.json.sig` and `boundary.pub` from the folder it runs
  in, checks the signature first, and only then parses the boundary. A missing file, a changed
  boundary or a signature from another key stops it from starting, before the log is opened.
- Keep `boundary.pub` and the service out of the agent's reach (for example with a sandbox), or the
  agent could swap in its own key.

## Run

    .venv/bin/python -m zerotruss.server   # listens on 127.0.0.1:9001, needs the signed boundary
    .venv/bin/python -m zerotruss.verify chain.jsonl    # check the audit log

Point agentgateway at the service. The `metadata` block is required: it is how the gateway hands
each call's id back with the response, and the service denies every call without it.

    mcp:
      policies:
        mcpGuardrails:
          processors:
            - kind: remote
              host: localhost:9001
              failureMode: failClosed
              metadata:
                cid: mcpGuardrails.cid
              methods:
                tools/call: full

Your gateway config may hold a session key. Keep it out of git (`config.yaml` is ignored).

## Test and check

    .venv/bin/python -m pytest
    .venv/bin/python scripts/check_lock.py          # every locked version at least 14 days old
    .venv/bin/python -m pip_audit -r requirements.txt --disable-pip --no-deps   # known vulnerabilities

## Pipeline

GitHub Actions runs on every push, pull request and once a week: tests, a check that the
generated gRPC code matches the proto file, the 14-day rule, `pip-audit` on every lock file, a
TruffleHog scan of the whole history, a build of the wheel and source package, and a CycloneDX
SBOM that is validated against the schema. Every Action is pinned to an exact commit. On a public
repository it also adds CodeQL, a dependency review on pull requests, and signed provenance for
the build and the SBOM.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
