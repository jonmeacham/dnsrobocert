## DNSroboCert – Performance, Security, and Testing Improvement Plan

This document outlines prioritized, actionable improvements across performance, security, and testing for this repository. Priorities are ranked by expected impact and relative implementation effort.

### Top Priorities (High impact, Low/Medium effort)
- Fix background scheduler thread implementation and avoid busy waits
- ~~Replace 1s polling loop for config changes with event-driven file watching (fallback to mtime)~~
- Eliminate shell=True in deploy hook; accept list-form commands to avoid injection
- Align and pin dependency sources (git refs, constraints) consistently across pyproject, uv.lock, and Dockerfile
- Harden container: non-root user, minimal runtime deps, read-only filesystem, no git in final image
- Expand tests for hooks, scheduler, permissions, and command execution; enforce in CI

---

## Performance

1) ~~Replace tight polling with event-driven reloads~~ (High impact, Low effort)
- Current: `main._watch_config` recomputes SHA-256 every second to detect changes, and `background` thread wakes every second to run `schedule.run_pending()`.
- Actions:
  - ~~Use `watchdog`/inotify to watch the config file and trigger `_process_config` immediately on change; fallback to mtime/size check if watchdog unavailable.~~
  - ~~Increase sleep to e.g. 5–10s when falling back to polling.~~
  - ~~Compute digest only when mtime/size changed to avoid reading file on every loop.~~

2) Correct scheduler thread implementation and graceful shutdown (High impact, Low effort)
- Ensure the background thread uses an instance method `run(self, ...)` and joins on shutdown for deterministic cleanup.
- Replace `time.sleep()` with `Event.wait(timeout)` everywhere to enable fast termination (already partially used).

3) Parallelize TXT propagation checks (Medium impact, Medium effort)
- In `hooks.auth`, checking multiple `_acme-challenge` records is sequential with fixed sleeps.
- Actions:
  - Use a `ThreadPoolExecutor` to check all domains concurrently with per-query timeout and exponential backoff.
  - Consider early-exit when all required TXT records are observed.

4) Avoid redundant chmod/chown (Medium impact, Medium effort)
- `utils.fix_permissions` currently chmod/chown every file/dir recursively on each run.
- Actions:
  - Compare current mode/uid/gid via `os.stat` and only apply changes when needed.
  - Skip following symlinks; guard against broken links.

5) Logging consolidation (Low impact, Low effort)
- Avoid calling `coloredlogs.install()` in every module; initialize logging once in `main` and use module-level loggers.

6) Minor correctness/perf fixes (Low/Medium impact, Low effort)
- `utils.execute`: set `PYTHONUNBUFFERED` without trailing space; avoid printing full command lines when they may contain secrets; route to logger.
- Use caching for provider config resolution where reasonable (e.g., repeated `tldextract` calls).

## Security

1) Remove shell=True in deploy hook (High impact, Low effort)
- `hooks._deploy_hook` uses `subprocess.check_call(deploy_hook, shell=True)`.
- Actions:
  - Accept both string and list forms; prefer list form and call without `shell=True`.
  - If only string is provided, parse with `shlex.split` and still avoid the shell.
  - Document this change in `configuration_reference.rst`.

2) Pin and align dependencies (High impact, Low/Medium effort)
- Dockerfile installs `dns-lexicon` from `@main` while `pyproject.toml` pins a commit; versions of core deps differ between constraints and Docker explicit pins.
- Actions:
  - Generate a single constraints lock (via `uv export --no-emit-project --no-hashes`) and use it consistently for all installs, including `dns-lexicon` pinned to the same git commit as in `pyproject.toml`.
  - Remove ad-hoc version overrides in the Dockerfile where possible, letting constraints govern.

3) Container hardening (High impact, Medium effort)
- Actions:
  - Create and switch to a non-root user; set home and ownership of needed paths.
  - Drop unnecessary packages from the final image (remove `git`, prefer wheels/SDists resolved in build stage only).
  - Make filesystem read-only, add `tmpfs` or writable dirs only where required.
  - Set sensible defaults: `UMASK=027`, `PYTHONHASHSEED=random`, disable `.pyc` writes if acceptable.
  - Add a lightweight init (e.g., `tini`) to handle PID1 semantics if long-running.

4) Secrets and permissions (Medium/High impact, Low effort)
- Ensure `.pfx` and private keys are written with `0600` perms; verify `certs_permissions` defaults enforce least privilege.
- Mask sensitive values in logs (tokens, passphrases, deploy command args).

5) Environment variable injection hygiene (Medium impact, Low effort)
- `config._inject_env_variables` replaces `${VAR}`; consider support for default forms `${VAR:-default}` and whitelist of allowed prefixes to reduce risk of unintentionally exposing environment.

6) Runtime socket usage (Medium impact, Low effort)
- Before using Docker/Podman sockets, validate access and provide clearer errors; optionally allow disabling `docker exec` features entirely via config flag.

7) Supply-chain and static analysis (Medium impact, Low effort)
- Add `bandit` and `pip-audit` (or `uv pip audit`) to CI.
- Enable CodeQL for Python.
- Adopt SBOM generation (CycloneDX) in releases and publish with artifacts.

## Testing

1) Unit tests for critical paths (High impact, Low effort)
- Add tests for:
  - `hooks._deploy_hook` command shaping (list vs string), no-shell execution, env propagation.
  - `utils.execute` error handling, lock behavior, environment handling, secret masking.
  - `utils.fix_permissions` idempotency and selective `chmod/chown` behavior.
  - `background.worker` lifecycle: schedule registration, thread start/stop, fast shutdown.
  - `config._inject_env_variables` edge cases and failure modes.

2) Integration tests with Pebble (High impact, Medium effort)
- Extend existing integration to cover multi-domain issuance, wildcard flows, and deploy hooks inside a container environment.
- Parameterize tests for both Docker and Podman sockets when available.

3) Property-based tests (Medium impact, Low effort)
- Use `hypothesis` for configuration validation to fuzz schema-bound inputs and ensure business rules hold.

4) CI enforcement and coverage (High impact, Low effort)
- Run `tox` envs in CI for `flake8`, `mypy`, unit + integration tests, and coverage.
- Fail PRs on coverage drop; upload `coverage.xml` to Codecov (or built-in summary).

5) Cross-platform matrix (Medium impact, Medium effort)
- Add Linux and Windows runners for non-container tests (where feasible) to catch path/permission differences.

## CI/CD and Tooling

1) GitHub Actions (or equivalent) workflows
- Jobs: Lint (flake8), Types (mypy), Test (pytest with coverage), Security (bandit, pip-audit), Build (wheel + Docker multi-arch), Release (tagged builds).
- Cache `uv`, wheels, and pip to speed up.

2) Reproducible builds
- Use a single source of truth constraints; verify deterministic wheels.
- Generate and publish SBOM and provenance for releases.

3) Dependency automation
- Enable automated dependency update PRs for both application and dev deps. Use lock refresh and CI to verify safety.

## Docker Image

1) Align package sources and minimize final image size
- Build wheel in a builder stage; install only from local wheels and a constrained requirements set in the final stage.
- Remove `git` from the final stage, avoid `pip install` from `git+` URLs at runtime.

2) Security best practices
- Switch to non-root user, read-only root FS, least privileges.
- Add healthcheck for the long-running mode.

3) Tagging and distribution
- Standardize local build/publish tags for this repo; use the canonical tag for your registry workflows (e.g., `jonmeacham/dnsrobocert:latest`).

## Concrete Task List (prioritized)

1) Performance
- Replace polling with watchdog + mtime fallback; reduce loop frequency
- Fix scheduler thread `run` implementation; join on shutdown
- Parallelize DNS TXT checks with timeouts and backoff
- Make `fix_permissions` idempotent and selective

2) Security
- Remove `shell=True` in deploy hook; support list-form commands
- Unify constraints across pyproject/uv.lock/Dockerfile; pin `dns-lexicon` commit
- Harden container (non-root, RO filesystem, minimal deps)
- Mask secrets in logs; ensure restrictive perms for key material
- Add bandit, pip-audit, CodeQL, SBOM generation to CI

3) Testing & CI
- Add unit tests for hooks, utils, config, background
- Extend integration tests with Pebble for multi-domain/wildcard + deploy hooks
- Add hypothesis-based tests for config
- Enforce coverage and run tox envs in CI matrix (Linux, Windows where possible)

## Notes
- Keep documentation updated: `docs/configuration_reference.rst` and `docs/developer_guide.rst` should reflect behavior changes (e.g., deploy hook command form, file watching behavior, container user).
- Changes to Docker image should be accompanied by migration guidance for existing users.

