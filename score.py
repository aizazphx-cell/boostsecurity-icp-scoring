"""Score accounts: knockout gates, then 7 weighted criteria (0 / 0.5 / 1) x weight.

Inputs : raw/<slug>.json      (API signals from collect.py)
         poutine_summary.json (pipeline-risk scan from scan_poutine.py)
         manual.json          (web-researched signals, each with a source URL)
Output : results.csv, signals.csv
"""
import csv, json, pathlib

ROOT = pathlib.Path(__file__).parent
ACCOUNTS = json.loads((ROOT / "accounts.json").read_text())
MANUAL = json.loads((ROOT / "manual.json").read_text())
POUTINE = json.loads((ROOT / "poutine_summary.json").read_text())

WEIGHTS = {"C1 Hiring": 20, "C2 Pipeline risk": 15, "C3 Exposure": 15, "C4 New sec leader": 15,
           "C5 Firmographic": 15, "C6 Compliance": 10, "C7 Funding": 10}
assert sum(WEIGHTS.values()) == 100
EXPLOITABLE_RULES = {"untrusted_checkout_exec", "injection", "if_always_true", "confused_deputy_auto_merge", "job_all_secrets"}


TIMING = ("C1 Hiring", "C3 Exposure", "C4 New sec leader")


def tier(score, dq, sig):
    if dq:
        return "DQ"
    # Tier 1 also needs one full-strength timing trigger; otherwise the account caps at Tier 2.
    has_trigger = any(sig[k][0] == 1 for k in TIMING)
    return "Tier 1" if score >= 65 and has_trigger else "Tier 2" if score >= 40 else "Tier 3"


def auto_signals(raw, pt):
    """C1-C3 straight from API / scanner data."""
    out = {}
    j = raw.get("jobs")
    if j is None:
        out["C1 Hiring"] = (0, "no public ATS API (not scored)", "")
    elif j["strong"]:
        out["C1 Hiring"] = (1, f"{len(j['strong'])} AppSec/ProdSec role(s): " + "; ".join(t for t, _ in j["strong"][:2]),
                            j["strong"][0][1])
    elif j["partial"]:
        out["C1 Hiring"] = (0.5, f"{len(j['partial'])} adjacent security role(s): " + "; ".join(t for t, _ in j["partial"][:2]),
                            j["partial"][0][1])
    else:
        out["C1 Hiring"] = (0, f"0 security roles of {j['total_open']} open", j["board"])

    g = raw.get("github") or {}
    # Breadth beats count: exploitable workflow patterns in 3+ repos is systemic, one bad repo is a one-off.
    ex_repos = pt.get("exploitable_repos", [])
    rules = {k: v for k, v in pt.get("by_rule", {}).items() if k in EXPLOITABLE_RULES}
    s = 1 if len(ex_repos) >= 3 else 0.5 if ex_repos else 0
    rule_txt = ", ".join(f"{v} {k}" for k, v in sorted(rules.items(), key=lambda kv: -kv[1])) or "none"
    if not pt.get("repos_scanned"):
        out["C2 Pipeline risk"] = (0, f"{len(g.get('repos_with_actions', []))}/{g.get('sampled', 0)} sampled public repos run Actions, so nothing to scan",
                                   g.get("org_url", ""))
    else:
        out["C2 Pipeline risk"] = (s, f"poutine: exploitable findings in {len(ex_repos)}/{pt.get('repos_scanned', 0)} scanned repos "
                                      f"({rule_txt}); {len(g.get('repos_with_actions', []))}/{g.get('sampled', 0)} sampled repos run Actions",
                                   f"https://github.com/{ex_repos[0]}/tree/HEAD/.github/workflows" if ex_repos else g.get("org_url", ""))

    # Only high/critical advisories count: a low-severity GHSA on a side repo is noise (tightened after run 1).
    adv = [a for a in g.get("advisories", []) if a.get("severity") in ("high", "critical")]
    recent = [a for a in adv if a["within_12m"]]
    if recent:
        out["C3 Exposure"] = (1, f"{len(recent)} high/critical GHSA in last 12m, latest {max(a['published'] for a in recent)}",
                              sorted(recent, key=lambda a: a["published"])[-1]["url"])
    elif adv:
        out["C3 Exposure"] = (0.5, f"{len(adv)} high/critical GHSA 12-24m ago", adv[0]["url"])
    else:
        out["C3 Exposure"] = (0, "no high/critical GHSA on sampled repos in 24m", "")
    return out


results, signal_rows = [], []
for a in ACCOUNTS:
    raw = json.loads((ROOT / "raw" / f"{a['slug']}.json").read_text())
    m = MANUAL[a["slug"]]
    sig = auto_signals(raw, POUTINE.get(a["slug"], {}))
    # Manual criteria may override C3 when a non-GHSA incident was found (e.g. compromised dependency).
    for k, v in m["signals"].items():
        if k in ("C1 Hiring", "C3 Exposure") and sig[k][0] > v[0]:
            continue
        sig[k] = tuple(v)
    dq = m.get("gate")
    raw_score = sum(WEIGHTS[k] * sig[k][0] for k in WEIGHTS)
    score = 0 if dq else raw_score
    for k in WEIGHTS:
        s, ev, url = sig[k]
        signal_rows.append({"Company": a["name"], "Criterion": k, "Weight": WEIGHTS[k], "Value (0/0.5/1)": s,
                            "Points": WEIGHTS[k] * s, "Evidence": ev, "Source URL": url})
    results.append({"Company": a["name"], "Score": round(score), "Pre-gate score": round(raw_score),
                    "Tier": tier(score, dq, sig), "Gate": dq or "pass",
                    **{k: sig[k][0] for k in WEIGHTS}, "Rationale": m["rationale"]})

results.sort(key=lambda r: (r["Tier"] == "DQ", -r["Score"], -r["Pre-gate score"]))
for path, rows in (("results.csv", results), ("signals.csv", signal_rows)):
    with open(ROOT / path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
for r in results:
    print(f"{r['Score']:>4} ({r['Pre-gate score']:>3}) {r['Tier']:<7} {r['Company']:<22} "
          + " ".join(f"{r[k]:>3}" for k in WEIGHTS))
