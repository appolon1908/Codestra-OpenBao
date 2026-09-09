# OpenBao policy matrix

All listed operations are read-only unless a separately reviewed dynamic
engine role explicitly grants credential generation. Every policy also denies
other environments and system administration.

| Identity | Allowed relative path | Explicitly excluded |
| --- | --- | --- |
| Kong | `codestra/{env}/kong/*` | Middleware, n8n, Odoo, provider credentials |
| Middleware API | `codestra/{env}/middleware/api/*` | worker/provider masters, other services |
| Middleware Worker | `codestra/{env}/middleware/worker/{email,sms,social,advertising,ai,telephony,crawler}/*` | unsplit `middleware/*`, API and other products |
| n8n | `codestra/{env}/n8n/middleware-client/*` | provider, database, VICIdial admin, trading credentials |
| Odoo | `codestra/{env}/odoo/integration/*` | provider masters and unrelated products |
| Prometheus | authenticated `sys/metrics` policy only | `codestra/*` secret data |
| Klyrow adapter | `codestra/{env}/middleware/worker/email/klyrow/*` | all non-email and non-Klyrow paths |
| Telnexa adapter | `codestra/{env}/middleware/worker/sms/telnexa/*` | all non-SMS and non-Telnexa paths |
| VICIdial adapter | `codestra/{env}/middleware/worker/telephony/vicidial/*` | VICIdial administration and unrelated paths |
| Crawler adapter | `codestra/{env}/middleware/worker/crawler/kyqra/*` | other provider families and other crawler authorities |

Generated policy files under `openbao/policies/` are deployment authority.
`scripts/generate_workload_policies.py` must reproduce them byte-for-byte.
Broad prefixes, wildcards, `sudo`, default-policy inheritance and
cross-environment paths fail validation.

Dynamic database, PKI and Transit permissions are not granted by this matrix.
They remain evaluated/disabled until a real compatible consumer has staged
lease, renewal, revocation and rollback evidence.
