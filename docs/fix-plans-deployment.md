# Fix plans: deployment notes

A repo scan can optionally run `pa fix` after a successful scan that found something, and attach the resulting
**fix plan** (which dependency upgrades would clear the findings, and whether a trial resolve verified them) to the
scan result. Producing a plan means resolving dependencies, and resolving dependencies means running code from the
scanned repository (build backends, `setup.py`). This note explains how the scan task contains that code and what you
must provide in the deployment.

A fix plan never changes the scan: the scan is always reported `success` when the scan itself succeeded, no extra email
is sent, and no finding is lost. Any failure of the fix step is recorded as the plan's own `status`
(`planned`, `unsupported`, `error`, `skipped` or `timeout`).

Fix plans need `package-alert` **0.10.0** or later (container isolation). package-alert is not baked into the scan
image: the scan task pip-installs it at run time from the **`pa_version`** system setting. Set `pa_version` to `0.10.0`
or later, or leave it blank to install the latest release. With an older `pa_version`, fix plans come back `skipped`
(the installed version has no `pa fix`) or unverified.

## 1. What runs and as whom

The scan task (`docker/scan_task/scan_task.py`) runs as root and holds the task's secrets: the git credential, the
fleet API key and the AWS task role. `pa scan-project` runs as root as before (it does not execute repository code), but with an allow-listed
environment only (`scan_env()` in `scan_task.py`): `PATH`, `HOME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`, the proxy
variables unchanged (it must reach OSV) and `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`. It never sees
`FLEET_*`, `CREDENTIAL_*`, `AWS_*`, `ECS_*`, `PACKAGE_INDEXES` or `FIX_PLAN*`. The fix step
(`docker/scan_task/fix_plan.py`) runs **every** process that can execute repository code, including the `pa fix --help`
capability probe and `uv auth login`, as the dedicated `pa-trial` user:

- uid/gid `10001`, home `/home/pa-trial`, shell `nologin`. The home is created **empty** (`useradd -k /dev/null`), so it
  starts with no dotfiles, keys or config (`docker/scan_task/Dockerfile`).
- A **scrubbed environment**: `PATH`, `HOME`, `LANG` and `PA_SANDBOX_ISOLATION=container`; `PA_RUN_OPTS` only when
  registry credentials are configured; and the proxy and TLS variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and
  lowercase forms, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`) when the task has them. It never holds
  `FLEET_*`, `CREDENTIAL_*`, `AWS_*`, `ECS_*` or `PACKAGE_INDEXES`.
- A **copy of the repository without `.git`** (at any depth), owned by the trial user. `pa fix` runs in the scan's
  subfolder within it, so a path dependency outside that subfolder (`../shared`) resolves as it does in the repo.
  Symlinks are copied as links, never followed, so a link pointing outside the repository cannot expose a root-owned
  file.
- A **config copy** without `plugins`, `api_key` and `server_url`, the keys that could carry a secret and that
  `pa fix` does not need.

Before any of this, the scan task rewrites the clone's `origin` URL without credentials and verifies that neither the
URL nor `.git/config` still contains the token. If that cannot be verified the fix step is refused (`status: error`).

A fix plan pa-central cannot ingest (too deeply nested, too large or otherwise rejected with an HTTP 4xx) is
replaced by an error entry and re-posted once; the scan result is still stored.

## 2. What the trial user can and cannot reach

package-alert's container isolation (`PA_SANDBOX_ISOLATION=container`) does not use bwrap, because Fargate cannot
enable user namespaces. Instead it states four requirements the deployment must meet
(`package-alert/THREAT_MODEL.md`, "Container isolation"). This is how the scan task meets each.

| Requirement | How the scan task meets it |
|---|---|
| **R1** pa starts with no secrets in its environment, and no process under the same uid holds secrets | `pa` runs as uid 10001 with the scrubbed environment above. The scan task and its secrets run as root, so `/proc/<pid>/environ` of the task is unreadable to the trial user. |
| **R2** nothing readable by that uid holds secrets, apart from deliberately granted registry credentials | The home starts empty; the project copy has no `.git`; the remote URL is verified credential-free; the config copy drops `plugins`, `api_key`, `server_url`. |
| **R3** the uid is not root | uid 10001; package-alert also refuses to run as root. |
| **R4** the container is disposable | Each scan runs in its own ephemeral ECS or Docker task, discarded at the end. |

**What the trial user can reach.** Repository build code runs as this user, so it can read anything uid 10001 can read:
the project copy, its own home, world-readable files in the image, and the network. It can also read the **registry
credential granted to trials** (section 4); that is inherent, and why the token must be read-only.

**What it cannot reach.** The task's environment, the git credential, the fleet API key, the task role credentials, and
the root-owned files of the container.

## 3. Why fix plans default off

Fix plans are off for each repo scan (`fix_plans_enabled` is false). Turning one on means that, after each scan with
findings, code from that repository is executed in the scan container, inside the protections above. That is a
deliberate decision, not something to enable fleet-wide by default: it adds run time and compute, needs the ECS task
and network to be set up as described here, and for internal repositories needs registry credentials. The setting is
per repo scan so it can be enabled for repositories you trust to be resolved.

A plan is generated only when the flag is on **and** the scan succeeded with at least one finding.

## 4. Private registries and proxies

For a repository that depends on packages from an internal index, add **Package index** credentials (the Credentials
tab: an `https://` index URL, an optional username, and the secret) and attach them to the repo scan.

- **Use read-only tokens, scoped to the registry.** Before `pa fix`, the scan task fetches each secret and runs
  `uv auth login` as the trial user, which writes it into uv's credential store in `/home/pa-trial`. The secret is never
  placed in `pa`'s environment, and is redacted from anything posted back. Repository build code runs while the store
  exists and **can read it**, as with any private-registry resolve, so a leaked token must only be able to download
  packages. The task sets `PA_RUN_OPTS="--flags python:uv-auth"` for the trial, and that flag is **required** under
  container isolation: without it, trials cannot see the credential store and cannot authenticate.
- **The registries must be reachable from the ECS subnets.** Trials run inside the scan task, so they use the task's
  network: `SCAN_TASK_SUBNET_IDS` and `SCAN_TASK_SECURITY_GROUP_IDS`. An internal registry that is only reachable from
  another network is held as "could not verify" in the plan. A repo scan with fix plans on but no registry credentials,
  on an internal repository, surfaces the authentication failure the same way.
- **Authenticated proxies are not supported for fix plans.** Proxy variables are forwarded **without** their
  `user:password@` part, so a trial behind a proxy that needs credentials fails visibly (HTTP 407) instead of being
  given the password. Use an unauthenticated egress proxy, or none.
- Package-index credentials cannot be used as a repo scan's git credential.

## 5. Time budget

The system setting **`fix_plan_timeout_seconds`** (Settings, Fix Plans; default **900**, allowed 120 to 3600) is the
budget for the whole fix step. It covers the capability probe, copying the project, fetching registry secrets,
`uv auth login`, and `pa fix` itself; each stage is given only the time left. When it runs out the plan has
`status: timeout`. A plan that finished but used 80% or more of the budget is shown with a "near time limit" warning;
raise the budget before it starts timing out.

Separately, **package-alert limits each trial resolve to 120 seconds** and reports an inconclusive trial as held. That
limit is inside package-alert and is not changed by this setting.

The setting also sets how long a scan task is expected to live: the task-length bound is
`max(1800, 600 + budget + 300)` seconds (600 for the scan itself, and a 300-second margin for the clone, the
package-alert install and the scan task's own overhead; registry login is part of the fix-plan budget, not this
margin). The scan dedup lock TTLs and stuck-scan recovery both use it, so a long budget does not get a running scan
declared stuck or re-launched. A missing or invalid stored value falls back to 900.

Stuck-scan recovery uses the budget **current at recovery time**, not the one the scan started with. Lowering the
budget while a long scan is running can get that scan marked failed early; if its task then finishes, its late result
still overwrites the row.

## 6. ECS task sizing

Trial resolves are resolver processes (uv, pip, npm and their build backends) that each use hundreds of MB, and npm runs
up to four at a time. The scan task definition used for scans without fix plans is likely too small. When enabling fix
plans, **raise the task's CPU and memory and its ephemeral storage** (the project copy, uv and npm caches and the
credential store live in the container).

**Recommended: 2 vCPU / 4 GB, with the default 900-second budget.** Peak memory stayed between 1 and 1.4 GB, so it is
CPU, not memory, that sets the fix step's length: halving the CPU roughly doubles it. Use 1 vCPU only with the budget
raised to at least 1500 seconds.

Measured with package-alert 0.10.0rc1 on a local Docker host, using `docker run --cpus/--memory` to approximate the task
sizes, and the 2 vCPU size repeated with 0.10.0 (652.8 s fix step, 734 s whole task, 1412 MiB peak, the same plan). For
the largest project tried, an npm project with 1768 locked packages and 254 findings:

| Limits | Fix step | Whole task | Peak memory | Budget used (900 s) |
|---|---|---|---|---|
| none (host CPUs) | 422 s | 502 s | 1125 MiB | 47% |
| 2 vCPU / 4 GB | 656 s | 735 s | 1070 MiB | 73% |
| 1 vCPU / 2 GB | 1244 s | 1318 s | 1043 MiB | 138% (times out) |

The plan was identical at every size (49 planned, 33 held), and no trial hit package-alert's 120-second per-trial limit.
Smaller projects take far less time: a uv service with 77 locked packages took 27.5 s, including private-registry
login, and a small npm project about 16 s.

These are upper bounds for Fargate only as far as its vCPUs match the test host's; confirm with one run on ECS and watch
for the "near time limit" warning. Ephemeral storage was not measured; the Fargate default of 20 GiB was not tested
against.
