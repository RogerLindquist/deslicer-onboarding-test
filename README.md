# Deslicer token-path repo

This repository is scaffolded for **Path B**: the published CLI talks to Observer
with `DESLICER_API_TOKEN`. It does **not** use GitHub App OIDC.

`change plan` registers the repository URL and commit SHA, then Observer's
ephemeral compile-runner clones that exact commit to build the plan. The job's
own `GITHUB_TOKEN` is forwarded for that single clone and is never stored, so
private repositories work without installing a GitHub App.

Because the plan is built from a real clone, **git-lfs pointers are resolved to
their contents**. Uploading a bundle (`--source-dir .`) cannot do that — it ships
the pointer files themselves. Use `--source-dir` only on air-gapped runners where
Observer has no network path back to the repository.

## Required GitHub configuration

Convention: **GitHub Environment name === YAML stem === `--environment`**.

`deslicer init --provider github-token` prints a `gh` recipe. The CLI does **not**
create Environments or write secrets.

| Scope | Kind | Name | Example |
| --- | --- | --- | --- |
| GitHub Environment `<slug>` | Secret | `DESLICER_API_TOKEN` | Observer tools-scope key (`dslk_…`) |
| GitHub Environment `<slug>` | Variable | `OBSERVER_API_URL` | Observer URL that serves `/api/v1` |

`GITHUB_TOKEN` needs no configuration — GitHub Actions injects it into every job.

Each `.deslicer/environments/<stem>.yml` file maps to a GitHub Environment named
`<stem>`. A second Observer backend is a second Environment (another YAML file),
not a second repo-level token.

CI reads every environment file (or one stem when filtered). On **pull requests**,
jobs run `deslicer inventory validate` (diff/validate check only) and do **not**
create a `pending_approval` plan. On **merge to `main`/`master`** (push) or
`workflow_dispatch`, CI creates **one parallel plan job per
`(environment, inventory_group)` pair** where the destination has apps defined
(`source_path` entries). Parent inventory groups expand to leaf groups when
`OBSERVER_API_URL` and `DESLICER_API_TOKEN` are set on the Environment. Empty
`apps:` stanzas are skipped. `--target-group` receives the matrix
`inventory_group` **name** after allowlist validation (`^[A-Za-z0-9_-]+$` in
`discover-plan-matrix.sh` and create-plan preflight). The previous UUID matrix
output could not carry whitespace-injected CLI flags; names need that check.
CLI v1.3.2+ resolves the name to a host-group UUID (fail-closed on
missing/duplicate names). Plans are idempotent per `(commit, target group)` so
parallel matrix jobs do not collide.

## Workflows

- `.github/workflows/deslicer-plan.yml` — validate on PR; create/reconcile plan on merge to `main`/`master`
- `.github/workflows/deslicer-plan-actions.yml` — verify / approve / reject / deploy / status

Approve remains portal-gated when Observer requires a verified human.
