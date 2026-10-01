# BoostSecurity account-scoring prototype

Scores 10 real accounts against the BoostSecurity ICP using free/public data only.

    python3 collect.py        # C1, C3 from Greenhouse/Ashby job APIs + GitHub REST (needs `gh auth login`)
    python3 scan_poutine.py   # C2: BoostSecurity's poutine over each account's sampled repos (needs poutine + GH_TOKEN)
    python3 score.py          # gates + weighted criteria -> results.csv, signals.csv
    python3 build_sheet.py    # -> BoostSecurity_ICP_Scoring.xlsx

- `accounts.json`        – the 10 accounts (domain, GitHub org, ATS slug)
- `manual.json`          – C4-C7 + gates, researched by hand, every value with a source URL
- `raw/`                 – raw API pulls (1 Oct 2026)
- `poutine/`             – per-repo poutine JSON output; `poutine_summary.json` per account
- poutine: https://github.com/boostsecurityio/poutine (v1.1.6 used)

Per-repo poutine output (`poutine/`) is excluded from this repo because it names exploitable
workflow paths in third-party repositories; available on request.

Companion doc (ICP, scoring model, debrief notes): https://claude.ai/code/artifact/5a3a6c0f-a61d-4fcd-adcf-3ba87c090db9
