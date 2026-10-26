# Deploying PathCutter (install, container, scheduled runs)

PathCutter is a single offline Python CLI with one dependency (NetworkX), no database and no network calls. It fits three
deployment shapes: an analyst's machine, a container, and a scheduled job on a management server.

## Install

```bash
pip install pathcutter            # once published to PyPI
# or from a checkout:
pip install .
pip install .[yaml]               # add PyYAML for Ansible change input
pathcutter --version
```

Python 3.10+ . The only runtime dependency is NetworkX.

## Container

```bash
docker build -t pathcutter .
# mount a folder with your collection in, write the report back out:
docker run --rm -v "$PWD/data:/data" pathcutter analyze /data/export.zip --html -o /data/report
docker run --rm -v "$PWD/data:/data" pathcutter breach  /data/baseline.pcsnap --from "JSMITH@CORP.LOCAL"
```

The image runs as a non-root user and only reads the collection you mount and writes the report. Nothing privileged runs
in the container; collection happens outside it (SharpHound / AzureHound / AD Explorer on the Windows side).

## Publishing to PyPI (maintainer)

Releases use PyPI **Trusted Publishing** (OIDC) - no API token is stored anywhere.

1. One time, on PyPI, register a trusted publisher for the project
   (https://pypi.org/manage/account/publishing/):
   Owner `farouq7assan0o`, Repository `PathCutter`, Workflow `release.yml`, Environment `pypi`.
2. In the GitHub repo, add a protected environment named `pypi` (optionally require manual approval).
3. Bump the version in both `pyproject.toml` and `pathcutter/__init__.py` (a test enforces they match), commit, then:
   ```bash
   git tag v0.7.0 && git push origin v0.7.0
   ```
   `.github/workflows/release.yml` builds the sdist + wheel, runs `twine check`, and publishes.

## Scheduled runs (snapshot -> analyze -> diff, with history)

Run PathCutter nightly against whatever your collector produced that day. It keeps a dated history of snapshots, writes a
dated analyze report, and - from the second run on - a diff report of what changed since the last run. `tools/nightly.ps1`
(Windows / Task Scheduler) and `tools/nightly.sh` (cron / container) do exactly this.

**Windows (Task Scheduler), on a management server near the DC:**

```powershell
# run as a least-privilege service account that can READ the collection and WRITE C:\PathCutter
schtasks /Create /TN PathCutter-Nightly /SC DAILY /ST 02:30 /RU DOMAIN\svc-pathcutter /RP * `
  /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\PathCutter\tools\nightly.ps1 -Collection D:\collect\today -Home C:\PathCutter -CrownJewels C:\PathCutter\crown.json"
```

**Linux (cron) or a scheduled container:**

```bash
30 2 * * *  PC_HOME=/var/lib/pathcutter /opt/pathcutter/tools/nightly.sh /collect/today /etc/pathcutter/crown.json >> /var/log/pathcutter.log 2>&1
```

Output layout under the home folder:

```
snapshots/2026-10-26.pcsnap        one per run, the reusable baseline
reports/2026-10-26/                that day's analyze report (open index in a browser)
reports/2026-10-26-diff/           what changed since the previous run (paths opened / closed)
```

Gate on drift in CI or a job by using exit codes instead of the HTML: `pathcutter export <snap> --fail-above 50`
(risk score) or `--fail-exposure 30`, and `pathcutter check` for a proposed-change gate. See
[ad-change-gate.md](ad-change-gate.md) and `examples/github-actions`.

## Handling the data

Snapshots and reports contain your full directory topology and attack paths. Treat them like the sensitive data they are:
restrict the home folder, keep it off shared drives, and use `pathcutter anonymize` before sharing a collection outside
the team (salted pseudonyms, identical attack paths). The `.pcsnap` extension is git-ignored by default.
