# Upgrade guide — Windows, Milestone 1 → Milestone 2

You already have a working Milestone 1 installation using Python 3.11. This guide preserves your account, events and incident notes. The upgraded source uses Python 3.11-compatible syntax; automated validation was performed on Python 3.12 on Linux, not on Windows.

## A. Keep your existing data and launch the upgrade

1. In the old server PowerShell window, press **Ctrl+C**. Stop any other process using its database.
2. Open your old project folder (the one containing `run.py`). Copy the entire **instance** folder to a separate backup location. It holds your database and `.secret` signing-key file. Keep both private.
3. Extract the new ZIP to a **separate folder**. Open its inner **cybersentinel** folder, where `run.py` is located.
4. Copy the old **instance** folder into this new **cybersentinel** folder, beside `run.py`. Do this **before starting the new app**. Do not copy the old `.venv` folder.
5. Open PowerShell here (type `powershell` in File Explorer's address bar).
6. Run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe run.py
```

7. Open http://127.0.0.1:8000. Sign in with your **existing** username and password. New database tables are created automatically; existing records are retained. Look for **Collectors** in the navigation and **Log format** in the import form.

If you intentionally prefer a fresh lab, skip copying `instance` and create a new analyst account before running the server:
```powershell
.\.venv\Scripts\python.exe -m flask --app sentinel:create_app create-user analyst
```

If you previously set `CYBER_DB` or `CYBER_SECRET`, keep the same settings or point them deliberately at your copied database. The default-copy instructions assume neither override was set.

**Rollback:** stop the new server and run the old project against your untouched backup. Never run both versions simultaneously against the same database.

## B. Import raw log formats

In the dashboard, keep automatic refresh paused while selecting a file. Choose the matching format and import:

| Sample file | Select this format | Expected result on a fresh DB |
|---|---|---|
| samples/ssh-auth.log | OpenSSH authentication log | 29 events, 2 alerts; 1 non-auth SSH record skipped |
| samples/access.log | Apache / Nginx common or combined | 22 events, 1 alert |
| samples/zeek-conn.jsonl | Zeek conn.log (JSON) | 24 events, 1 alert |
| samples/ssh-legacy.log | OpenSSH authentication log | Set year 2026, offset +08:00; 1 event |

The first three files represent the same 75 events as the original synthetic demo. If you already loaded it, matching events are intentionally deduplicated: zero new events is expected.

These adapters accept the specific documented formats, not every possible custom server configuration. For traditional SSH timestamps such as `Oct 15 16:00:00`, enter the actual log year and UTC offset; the app will not guess. Split files that span years or offset changes and import each portion with the correct settings. ISO timestamps already include their zone. See README for parser limits.

## C. Start a live collector

Keep **PowerShell A** running the server. Open **PowerShell B** in the new project folder.

Create an ingest-only token linked to your analyst account:
```powershell
.\.venv\Scripts\python.exe -m flask --app sentinel:create_app create-collector analyst windows-lab --out instance\windows-lab.token
```
Use your actual analyst username if it differs. Keep the token private. It is written to a file, not printed. This command is needed once; if the name/file exists, reuse the valid token or choose a new name and file.

Create the lab log only if it does not exist:
```powershell
if (!(Test-Path .\instance\live-auth.log)) { New-Item -ItemType File .\instance\live-auth.log | Out-Null }
```

Start the collector:
```powershell
.\.venv\Scripts\python.exe collector\tail.py --file instance\live-auth.log --format ssh --token-file instance\windows-lab.token --state instance\windows-lab-state.json
```
Leave this window open. Idle operation is quiet. Open **Collectors** in the app; refresh the page to see a **Recent heartbeat**.

Open **PowerShell C**, also in the new project folder. Generate a safe live demonstration:
```powershell
.\.venv\Scripts\python.exe samples\live_demo.py
```
This appends seven simulated log lines over about 14 seconds. It **does not attempt real logins or attack anything**. The collector reads actual file appends and sends them over local HTTP. Each run uses a distinct synthetic account so the daily suppression rule does not hide later demos.

On the dashboard, click **Enable live view (10-second refresh)**. Expect:
- Seven additional authentication events.
- Two additional alerts: AUTH-001 and AUTH-002.
- A recent collector heartbeat and an increased received-events count.

Click an alert to investigate; incident pages do not auto-refresh, so your unsaved notes are not interrupted. Pause live refresh before using the dashboard import form.

Press **Ctrl+C** in B to stop collecting. Restart the same command to continue from the acknowledged checkpoint. If you revoke the token in Collectors, the old token will no longer work.

## D. Monitor a real authorised log file

Replace `--file` with a file you own or are authorised to monitor, and select its actual format:
```powershell
.\.venv\Scripts\python.exe collector\tail.py --file "C:\Lab\nginx\logs\access.log" --format apache --token-file instance\windows-lab.token --state instance\nginx-state.json
```
The quoted path is an **example**, not a file installed by CyberSentinel. Create a separate collector/token for each source if you want separate health and counters. Use a separate state file for every source/parser configuration. Never share one state file between processes.

The collector starts at the beginning of an unseen file. It supports UTF-8 newline-delimited files and runs while its terminal stays open. It is not a Windows Event Log agent, PCAP collector, or automatic system-wide scanner. Keep the server and collector on the same computer; remote URLs are intentionally rejected.

Malformed records stop collection without advancing the checkpoint; the message identifies the bad record in the pending batch. Inspect the source and format settings. Do not silently delete records just to bypass an error. If you deliberately switch to a cleaned file, preserve the original and use a new state path.

## E. Enable optional local AI summaries

Monitoring works with AI disabled. For this feature, install **Ollama for Windows** from the official page: https://ollama.com/download/windows . Model download requires internet and disk space; generation speed depends on your computer.

In a new PowerShell window, download the example small model:
```powershell
ollama pull qwen2.5:1.5b
ollama list
```
The second command should list `qwen2.5:1.5b`. The app does not automatically download models.

Ollama for Windows normally runs in the background. If it is not running, start it with `ollama serve` in a separate window. If it reports the port is already in use, an Ollama instance may already be running; do not start a duplicate.

In **PowerShell A**, press Ctrl+C to stop CyberSentinel, then run:
```powershell
$env:CYBER_AI="1"
$env:CYBER_AI_MODEL="qwen2.5:1.5b"
.\.venv\Scripts\python.exe run.py
```

These environment settings apply to that PowerShell session. Repeat them when starting from a new window, or leave AI disabled when you do not need it.

Open an incident → **Optional AI assistance** → **Generate local AI draft**. The app sends derived event counts, timestamps, rule identifiers and evidence IDs to **127.0.0.1:11434**. It excludes usernames, IP addresses, request paths, raw messages and analyst notes. The model has no tools or action permissions.

The draft appears separately from the original evidence and is included separately in the JSON incident report. You must review it: valid JSON and valid evidence IDs do **not** prove the model's statements are correct. The draft cannot close incidents, alter severity or run commands.

If Ollama is absent, the selected model is missing, or generation exceeds 90 seconds, the app shows an error and keeps your incident unchanged. A slow first load may need a smaller model or a later retry. This local AI connection expects native execution; the supplied Docker configuration does not connect to Ollama on the Windows host.

To disable AI, stop the server and run:
```powershell
$env:CYBER_AI="0"
.\.venv\Scripts\python.exe run.py
```

## F. Verify before calling the upgrade complete

- Existing account and incident history remain available.
- Raw-file uploads produce expected results or correctly deduplicate existing events.
- Live demo adds seven events and two alerts.
- Collector restart does not duplicate events.
- AI produces a reviewable draft on your local model, or reports a clear connection/model error.
- Run the automated suite:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```
The delivered build passed 44 tests in Linux/Python 3.12. Actual Ollama inference and Windows-specific locking still require verification on your laptop.
