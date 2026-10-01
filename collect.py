"""Collect machine-detectable signals for each account from free public APIs.

C1 hiring  -> Greenhouse / Ashby public job-board APIs
C2 CI/CD   -> GitHub REST: 30 most recently pushed public repos, check .github/workflows
C3 exposure-> GitHub repo security advisories (published) on those same repos

Uses `gh api` (authenticated, 5k req/h). Writes raw/<slug>.json.
"""
import json, re, subprocess, urllib.request, datetime, pathlib, sys

ROOT = pathlib.Path(__file__).parent
RAW = ROOT / "raw"
RAW.mkdir(exist_ok=True)
ACCOUNTS = json.loads((ROOT / "accounts.json").read_text())

# Title patterns. Strong = the exact champion/buyer role; partial = adjacent security roles.
STRONG = re.compile(r"application security|appsec|product security|devsecops|supply.?chain security|"
                    r"software security|security engineer.*(product|application|devsecops|supply)", re.I)
PARTIAL = re.compile(r"security engineer|security architect|head of security|\bciso\b|"
                     r"infrastructure security|cloud security|platform security", re.I)
NOT_APPSEC = re.compile(r"\bsoc\b|grc|governance|compliance|risk|analyst|sales|account exec|"
                        r"solutions engineer|marketing|recruit|partner", re.I)


def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "icp-prototype"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def gh(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    return json.loads(out.stdout) if out.returncode == 0 else None


def jobs(ats, slug):
    if ats == "greenhouse":
        d = http_json(f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs")
        return [(j["title"], j["absolute_url"]) for j in d["jobs"]], \
            f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs"
    if ats == "ashby":
        d = http_json(f"https://api.ashbyhq.com/posting-api/job-board/{slug}")
        return [(j["title"], j["jobUrl"]) for j in d["jobs"]], \
            f"https://api.ashbyhq.com/posting-api/job-board/{slug}"
    return None, None


def classify_jobs(postings):
    strong, partial = [], []
    for title, url in postings:
        if STRONG.search(title):
            strong.append((title, url))
        elif PARTIAL.search(title) and not NOT_APPSEC.search(title):
            partial.append((title, url))
    return strong, partial


def github(org):
    repos = gh(f"/orgs/{org}/repos?sort=pushed&per_page=60&type=public") or []
    repos = [r for r in repos if not r["fork"] and not r["archived"]][:30]
    with_actions, advisories = [], []
    cutoff12 = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
    cutoff24 = cutoff12 - datetime.timedelta(days=365)
    for r in repos:
        wf = gh(f"/repos/{r['full_name']}/contents/.github/workflows")
        if isinstance(wf, list) and any(f["name"].endswith((".yml", ".yaml")) for f in wf):
            with_actions.append(r["full_name"])
        for a in gh(f"/repos/{r['full_name']}/security-advisories?state=published&per_page=100") or []:
            pub = datetime.datetime.fromisoformat(a["published_at"].replace("Z", "+00:00"))
            if pub >= cutoff24:
                advisories.append({"id": a["ghsa_id"], "repo": r["full_name"], "published": a["published_at"][:10],
                                   "severity": a.get("severity"), "within_12m": pub >= cutoff12,
                                   "url": a["html_url"], "summary": a["summary"]})
    org_info = gh(f"/orgs/{org}") or {}
    return {"org_url": f"https://github.com/{org}", "public_repos_total": org_info.get("public_repos"),
            "sampled": len(repos), "repos_with_actions": with_actions, "advisories": advisories}


for acct in ACCOUNTS:
    if len(sys.argv) > 1 and acct["slug"] not in sys.argv[1:]:
        continue
    out = {"name": acct["name"], "collected_at": datetime.date.today().isoformat()}
    postings, board_url = jobs(acct.get("ats"), acct.get("ats_slug"))
    if postings is not None:
        s, p = classify_jobs(postings)
        out["jobs"] = {"board": board_url, "total_open": len(postings), "strong": s, "partial": p}
    out["github"] = github(acct["github"]) if acct.get("github") else None
    (RAW / f"{acct['slug']}.json").write_text(json.dumps(out, indent=2))
    g = out["github"] or {}
    print(acct["name"], "| jobs", out.get("jobs", {}).get("total_open"),
          "strong", len(out.get("jobs", {}).get("strong", [])), "partial", len(out.get("jobs", {}).get("partial", [])),
          "| actions", len(g.get("repos_with_actions", [])), "/", g.get("sampled"),
          "| advisories<24m", len(g.get("advisories", [])))
