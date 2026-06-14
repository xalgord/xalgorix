# CLAUDE.md — Xalgorix Agent Harness

> Read this file first. It is a routing document, not a manual.
> For deep project facts, read `docs/ARCHITECTURE.md` and the package-level
> doc-comments under `internal/`.

## What this project is

`xalgorix` is a self-hosted AI security-testing agent. A single Go binary
that serves an embedded React dashboard (`webui/`) and runs autonomous
scans. It has **terminal execution, browser automation, and network
egress** — these are safety-critical surfaces.

Module path: `github.com/xalgord/xalgorix/v4` · Go 1.24+ · Node 20+ for webui.

## Layout (one-liner per top-level dir)

| Path                 | What lives there                                          |
| -------------------- | --------------------------------------------------------- |
| `cmd/xalgorix/`      | CLI entrypoint, service lifecycle, OS-specific exec stubs |
| `internal/agent/`    | The autonomous agent loop                                 |
| `internal/llm/`      | LLM client abstraction                                    |
| `internal/providers/`| Concrete LLM provider implementations                     |
| `internal/tools/`    | Tool registry the agent invokes                           |
| `internal/scanctx/`  | Scan context / state passed through the loop              |
| `internal/scopeguard/`| **Target/scope authorization checks** — never bypass      |
| `internal/sandbox/`  | **Execution policy for terminal/network tools**           |
| `internal/safe/`     | Panic recovery + process-wide stability counters          |
| `internal/web/`      | HTTP server, dashboard API, **embedded** static assets    |
| `internal/proxy/`, `internal/ratelimit/`, `internal/reporting/`, `internal/auth/`, `internal/storage/`, `internal/tui/`, `internal/config/`, `internal/resources/` | Cross-cutting subsystems |
| `webui/`             | React + Vite + TS dashboard sources (build → `internal/web/static`) |
| `docs/`              | Architecture, testing checklist, proxy support            |

## How to run the verification loop

The agent **must** be able to run all of these before claiming a change is done:

```bash
make test          # go test ./... -v
make test-race     # go test ./... -race    (run for any change touching concurrency)
make lint          # gofmt + go vet
make build         # webui bundle + go build → ./build/xalgorix
```

A one-shot `init.sh` is provided at the repo root that runs the whole stack.
**`init.sh` exit code 0 is a prerequisite for marking any feature done.**

## Spec-driven workflow (project convention)

`CONTRIBUTING.md` requires larger features to go through specs:

```
.kiro/specs/<feature-id>/
  requirements.md   # user story, scope, out-of-scope, acceptance
  design.md         # data flow, interfaces touched, alternatives considered
  tasks.md          # ordered checklist of implementation steps
```

For a new feature, **write the spec first**, then code against `tasks.md`.
For small fixes / one-line changes, `feature_list.json` + `progress.md` is
enough — no spec required.

## Conventions (do not violate silently)

- Go: keep `gofmt` clean, `golangci-lint` clean (CI gate).
- Webui: any change under `webui/` **must** be followed by `make webui`
  (or `make build`) so `internal/web/static` stays in sync with the
  embedded bundle. A stale static bundle is a build-time-only failure
  that catches everyone in CI.
- Branching: never push to `main` directly. Work on
  `feature/<short-name>` or `fix/<short-name>` branches.
- Commits: small, scoped, one concern per commit. Reference the spec
  id (`spec: <id> …`) when applicable.

## Safety rules (standard bars)

These are non-negotiable. If a task seems to require breaking one, stop
and ask the user.

1. **Never** delete, weaken, or wrap a `scopeguard` check. Scope
   authorization is the load-bearing wall of the product.
2. **Never** extend the terminal/network sandbox by adding new
   shell-exec entry points that bypass `internal/sandbox/policy.go`.
3. **Never** edit the LLM prompt strings to disable the model's own
   refusal / scope checks. The model is the second wall; do not
   collapse it.
4. **Never** weaken `internal/safe` (panic recovery, counter
   monotonicity). The stability counters are user-visible in the
   health endpoint.
5. **Always** run `make test-race` for changes touching goroutines,
   channels, or shared state. Race-only bugs are the dominant class
   in this codebase.
6. **Always** read the relevant package's `doc.go` / top-of-file
   comment before editing. The packages under `internal/safe`,
   `internal/scopeguard`, and `internal/sandbox` carry policy
   contracts in their prose — read before you change shape.
7. **Never** commit secrets. The agent may read `~/.xalgorix.env` to
   understand config shape, but must never write its contents into
   code, logs, or commits.

## Definition of done

A feature is done **only** when **all** of these are true:

- [ ] Spec files exist under `.kiro/specs/<id>/` (when required)
- [ ] `feature_list.json` entry status is `"done"`
- [ ] `progress.md` shows the evidence (commit SHA, test output snippet)
- [ ] `init.sh` exits 0 from a clean tree
- [ ] Manual smoke: `make run -- --web` starts, dashboard responds at
      `http://127.0.0.1:9137`, the changed surface is exercised
- [ ] No new linter / vet / race warnings introduced
- [ ] No file under `webui/` is left unbuilt (if webui was touched)

## Startup Workflow (read first, every session)

Before writing code, an agent session on this project **must** do all of
the following in order:

1. Read `progress.md` top to bottom.
2. If a handoff exists at `session-handoff.md`, read it before anything
   else.
3. Read the `requirements.md` / `design.md` / `tasks.md` for the
   active feature under `.kiro/specs/<id>/` (when `spec_required: true`).
4. Skim the package doc-comments for any package this session will
   touch (especially `internal/safe`, `internal/scopeguard`,
   `internal/sandbox`).
5. Run `./init.sh` from a clean tree to confirm the baseline is green
   before making any changes.
6. State the active feature and the next concrete step in plain text
   to the user, then proceed.

## Stay in scope

- **One feature at a time.** Only one entry in `feature_list.json`
  has `status: "in_progress"` at any moment. Marking a second feature
  in progress without finishing the first is a scope violation.
- The active feature id is the value of `active_feature_id` in
  `feature_list.json`. The agent sets this when starting work and
  clears it when done.
- Hard scope walls: do not edit `internal/scopeguard`, `internal/safe`,
  `internal/sandbox`, or the LLM refusal prompt strings as part of a
  feature whose `touches_safety_critical` is `false`. If a feature
  really does require touching them, mark it `true` in the feature
  entry and surface that fact in the spec's `design.md` before coding.

## End of Session (Before ending)

When the session is about to end, the agent must:

1. Run `./init.sh` one more time; commit only if it exits 0.
2. Update `feature_list.json` (status, evidence).
3. Update `progress.md` (status, evidence log line, current step).
4. Overwrite `session-handoff.md` with the next-session resume notes
   (template at the top of that file). Cover: where we are, what is
   not done, open questions, the first 3 actions for the next session.
5. Commit the working tree on the feature branch with a scoped message
   referencing the feature id (`spec: F-001 …` / `wip: F-001 …`).
6. Never leave the tree in a "touched but not committed" state when a
   handoff is being written.

## Pointers to deep context

- Architecture diagram: `docs/ARCHITECTURE.md`
- Pentest methodology: `docs/TESTING_CHECKLIST.md`
- Proxy support: `docs/proxy-support.md`
- Full feature list: `feature_list.json`
- Active progress: `progress.md`
- Session handoff template: `session-handoff.md`
- Multi-agent deep walkthrough: `.claude/workflows/xalgorix-architecture-walkthrough.js`
- Env / config reference: `README.md` § "Environment Variables"
