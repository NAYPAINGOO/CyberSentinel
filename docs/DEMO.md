# Milestone 2 presentation rehearsal — after local verification

Do not publish yet if you have not run the upgraded features yourself. Use synthetic data and make claims only about checks you actually completed. AI-assisted development should be acknowledged.

1. **Overview (30 seconds):** Explain that CyberSentinel correlates authentication, web and network logs and records human investigation decisions. Show the four detection rules and their fixed severity priorities.
2. **Raw parsing (30 seconds):** Import a bundled raw sample with the correct format. Explain timestamp normalisation, rejection of malformed batches and deduplication. Files mirror the original demo, so previously loaded records should not duplicate.
3. **Live collection (60 seconds):** Show the collector terminal and health page. Start `samples/live_demo.py` in another terminal. Demonstrate seven new events and two alerts, noting that the writer emits simulated logs without making real login attempts.
4. **Investigation (45 seconds):** Open AUTH-002, expand failed/successful login evidence, add a note and set investigating. Explain that compromise is not proven.
5. **Optional AI (45 seconds):** Only if you have installed and tested Ollama locally, generate a draft. Show observed evidence separately from suggestions, and explain which fields are excluded from the prompt. Check the generated prose rather than blindly endorsing it.
6. **Export and limitations (30 seconds):** Download the JSON report. Mention local-only collection, bounded event storage, supported parser subsets, best-effort rotation, daily alert suppression and the need for more realistic evaluation.

Suggested screenshots: updated dashboard, collector with recent heartbeat, incident evidence and notes, AI draft alongside its warning (only after genuine local inference), and your test output. Avoid displaying token-file contents or passwords.

Build-environment evidence: 44 automated tests passed, including live HTTP collector append/restart. AI output/transport tests used mocks; do not describe them as proof that an actual model was run. Windows, actual local model generation and Docker need their own validation.
