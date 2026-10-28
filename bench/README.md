# DOC-06 benchmark harness

Implements `DOC-06_CAPACITY_AND_PRICING_BENCHMARK_PLAN` (H0 build pack, 2026-10-24).

| Path | Purpose |
|---|---|
| `image/` | Odoo 19.0 CE image from a pinned upstream commit (ADR-H0-010); `build.sh` writes `evidence/image.json`; `platform/` holds the DOC-04 §5.4 `platform-defaults <create\|copy>` one-shot, run at dataset creation (step 6a) and after every run's restore |
| `dataset/` | Band datasets S/M/L (+ XS smoke): demo seed → `odoo populate` → second populate pass on `stock.move`+`stock.move.line` to hit the §3 stock-move target → users + attachments → dump + SHA-256 |
| `load/` | Locust personas (DOC-06 §4); request names carry the SLO class (`read:`, `write:`, `pdf:`, `heavy:`); `browsers.py` = Playwright bus users (5% of VUs, min 2) mentioning each other in chatter, timed to the receiving page (E8) |
| `cost/` | §7 cost model and §8 RC-2 rule; refuses to run while inputs are pending |
| `infra/` | Hetzner fleet: `budget` (live prices, read-only), `up` (needs `--approved-eur`), `status`, `down` |
| `evidence/` | Image provenance, dataset manifests, run records (§10) |

Local smoke run:

```bash
image/build.sh
BAND=XS LOC=eg dataset/make_dataset.sh
```

Hetzner: `export HCLOUD_TOKEN=...` in your own shell, then `python3 infra/hz.py budget infra/plan.json`.
Ordering hosts needs the owner's priced approval (DOC-06 §9).
