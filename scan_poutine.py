"""Run BoostSecurity's poutine (https://github.com/boostsecurityio/poutine) on each account's
sampled public repos that have GitHub Actions workflows (from raw/<slug>.json), in parallel.

Writes poutine/<slug>/<repo>.json per repo and poutine_summary.json per account.
Needs `poutine` on PATH and GH_TOKEN set (gh auth token).
"""
import json, os, pathlib, subprocess, sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).parent
OUT = ROOT / "poutine"
POUTINE = os.environ.get("POUTINE", "poutine")
ACCOUNTS = json.loads((ROOT / "accounts.json").read_text())

# Rules that mean an outsider can get code to run with the repo's secrets — the attacks poutine exists to catch.
EXPLOITABLE = {"untrusted_checkout_exec", "injection", "if_always_true", "confused_deputy_auto_merge", "job_all_secrets"}


def scan(slug, repo):
    out = OUT / slug / (repo.replace("/", "__") + ".json")
    if out.exists():
        return repo, json.loads(out.read_text())
    out.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([POUTINE, "analyze_repo", repo, "-f", "json", "-q", "--disable-version-check"],
                       capture_output=True, text=True, timeout=600)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        data = {"error": r.stderr[-500:], "findings": [], "rules": {}}
    out.write_text(json.dumps(data))
    return repo, data


summary = {}
for acct in ACCOUNTS:
    if len(sys.argv) > 1 and acct["slug"] not in sys.argv[1:]:
        continue
    raw = json.loads((ROOT / "raw" / f"{acct['slug']}.json").read_text())
    repos = (raw.get("github") or {}).get("repos_with_actions", [])
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda r: scan(acct["slug"], r), repos))
    by_rule, by_level, exploitable_repos, errors = Counter(), Counter(), set(), 0
    for repo, data in results:
        if data.get("error"):
            errors += 1
        rules = data.get("rules", {})
        for f in data.get("findings", []):
            rid = f["rule_id"]
            by_rule[rid] += 1
            by_level[rules.get(rid, {}).get("level", "?")] += 1
            if rid in EXPLOITABLE:
                exploitable_repos.add(repo)
    summary[acct["slug"]] = {
        "name": acct["name"], "repos_scanned": len(repos), "scan_errors": errors,
        "findings_total": sum(by_rule.values()), "by_level": dict(by_level), "by_rule": dict(by_rule),
        "exploitable_findings": sum(by_rule[r] for r in EXPLOITABLE),
        "exploitable_repos": sorted(exploitable_repos),
    }
    s = summary[acct["slug"]]
    print(f"{acct['name']:<16} repos {s['repos_scanned']:>2} err {errors} | findings {s['findings_total']:>4} "
          f"| error-level {by_level.get('error',0):>3} warning {by_level.get('warning',0):>3} "
          f"| exploitable {s['exploitable_findings']:>3} in {len(exploitable_repos)} repos", flush=True)

prev = json.loads((ROOT / "poutine_summary.json").read_text()) if (ROOT / "poutine_summary.json").exists() else {}
prev.update(summary)
(ROOT / "poutine_summary.json").write_text(json.dumps(prev, indent=2))
