# Milestone 2 validation record

Executed 2026-10-16 (Malaysia time), Linux, Python 3.12, Flask 3.1.2, Werkzeug 3.1.3 and pytest 8.4.2.

**44 tests passed** (`python -m pytest -q`). See `test-results.txt` for the captured output. Milestone 1's original 19 tests remain in the suite.

| Area | Checked |
|---|---|
| Original workflow | Benign fixture, rule scores/evidence, thresholds, distinct ports/accounts, validation, login/logout, CSRF, viewer restrictions, throttling, atomic imports, deduplication, notes, escaping, filters, JSON reports and request limits |
| Raw adapters | SSH, common/combined access and Zeek fixtures normalise to the exact same 75 content IDs as the original demo; one unrelated SSH record counted as skipped |
| Timestamps | Traditional SSH requires year and offset; explicit +08:00 converts to UTC |
| Bad logs | Invalid format, malformed Zeek data and unsupported SSH auth method rejected; ICMP is counted as skipped |
| Collector API | Missing tokens rejected; no browser read privileges; deduplicated ingest; provenance links; revocation; owner role and request rate limits; error state and heartbeats |
| Token creation | Token written privately to file; DB stores only digest; viewer cannot own collector; existing file is not overwritten |
| Tailing | Partial-line buffering; rotation/truncation reset; checkpoint unchanged on network failure; local URL restriction |
| Real local HTTP | Actual tailer subprocess waits on empty file, ingests appended SSH records over HTTP, checkpoints, restarts and does not duplicate events |
| AI contract | Mocked Ollama HTTP transport, controlled facts omit untrusted username/IP, JSON/reference validation, unavailable-service error |
| AI workflow | Disabled state, viewer restriction, draft persistence and report separation; incident status unchanged |
| Migration | New tables added to a pre-upgrade schema while retaining users/events/alerts |

The live collector test used a real loopback HTTP server and subprocess; it did not mock the ingestion transport. The AI tests **did mock the model response**. No actual Ollama model was installed or benchmarked here. JSON/reference validation cannot establish model factual accuracy.

Windows instructions target the user's existing Python 3.11 installation. Windows execution, msvcrt file-lock behaviour and Python 3.11 execution were not verified in this Linux runtime. Docker was not executed. No real telemetry dataset, broad false-positive study, throughput/load test, security audit or dependency vulnerability scan was performed.

The 46-event benign fixture produces zero alerts, and the combined 75-event fixture produces four expected alerts. These are fixture checks, not real-world accuracy claims.

Browser visual verification was attempted again, but the Chromium headless download returned invalid/truncated archives. Updated templates render successfully in route tests; desktop/mobile visual layout remains unverified in this build environment.
