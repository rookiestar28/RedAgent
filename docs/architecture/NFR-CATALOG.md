# Production Non-Functional Requirements Catalog

Architecture contract: compat_091-1
Status: Provisional numeric baseline; enforcement is owned by compat_092-compat_117

All thresholds are pass/fail targets for the stated reference profile. Owners may tighten them with evidence; weakening requires an ADR and roadmap change.

| Metric | Target | Reference profile | Measurement owner / enforcement |
| --- | --- | --- | --- |
| Control-plane startup | <= 60 s | 4 vCPU, 16 GiB RAM, NVMe, warm images, single-node local profile | compat_092 / compat_116 |
| First synthetic campaign | <= 180 s | Fresh local profile, bundled fixture, UI/API path | compat_095 / compat_117 |
| Idle CPU | <= 5% of 4 vCPU | Healthy profile idle 10 minutes | compat_102 / compat_116 |
| Idle RAM | <= 4096 MiB | Healthy profile idle 10 minutes | compat_102 / compat_116 |
| Idle disk | <= 2048 MiB | Fresh profile excluding images and user evidence | compat_092 / compat_116 |
| Emergency stop acknowledgement | <= 10 s | 10 concurrent synthetic jobs, two workers | compat_101 / compat_117 |
| API throughput | >= 100 req/s | Authenticated read-heavy workload, 50 users, 4 vCPU API | compat_093 / compat_117 |
| API p95 | <= 300 ms | Same workload at target throughput | compat_093 / compat_117 |
| Workflow throughput | >= 20 actions/s | 100 synthetic workflows, excluding scanner latency | compat_096 / compat_117 |
| Workflow local-activity p95 | <= 1000 ms | Policy/evidence metadata activities, 100 workflows | compat_096 / compat_117 |
| Runner capacity | >= 10 concurrent synthetic jobs | Two 4 vCPU/8 GiB isolated workers | compat_100 / compat_117 |
| Reference monthly cost | <= USD 750 | One small enterprise environment; excludes scanner/model licenses and evidence egress | compat_116 / compat_117 |
| Recovery point objective | <= 15 min | Transactional metadata and evidence manifests | compat_116 / compat_117 |
| Recovery time objective | <= 60 min | Single-region control-plane recovery | compat_116 / compat_117 |
| Reference restore time | <= 45 min | 100,000 metadata rows plus 10 GiB evidence | compat_116 / compat_117 |

Measurements must record date, environment, workload fixture/version, command or test path, raw result artifact, and pass/fail mapping in a repo-local command log. A passing unit test that only compares constants is not performance evidence.
