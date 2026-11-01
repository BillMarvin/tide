# Tide — Local Account Server

A small, dependency-free PowerShell 5.1 / .NET HttpListener backend for the Tide menstrual cycle tracker. It provides real account authentication with server-side per-user storage, moving beyond the original single-file/offline design.

## Features

- **Authentication**: POST /api/auth/signup, POST /api/auth/login, POST /api/auth/logout, GET /api/auth/me
- **Data**: GET /api/data, PUT /api/data (with revision-based conflict detection)
- **Health**: GET /api/health
- **Security**: PBKDF2-SHA256 password hashing (150,000 iterations), HttpOnly/SameSite=Strict cookies, login throttling (8 failures → 5 min block), security headers, CSP
- **Persistence**: Runtime JSON store (data/tide-server.json), per-user dataRevision conflict detection
- **Session**: In-memory sessions, 7-day expiry, carried by HttpOnly, SameSite=Strict cookie

## Usage

```powershell
# Start the server (default port 8799)
powershell -ExecutionPolicy Bypass -File .\server.ps1

# Start with a specific port
powershell -ExecutionPolicy Bypass -File .\server.ps1 -Port 8800

# Start without auto-opening browser
powershell -ExecutionPolicy Bypass -File .\server.ps1 -NoBrowser
```

Then open http://127.0.0.1:8799/ in your browser.

## Options

| Option | Description |
|--------|-------------|
| `-Port N` | Choose another loopback port (default: 8799) |
| `-NoBrowser` | Do not open a browser automatically |

## Account Behavior

- **Signup**: Creates a new account with email/password and an optional name, sets a 7-day session cookie
- **Greeting**: Home says "Good morning, Mira" etc. using the account name; if no name was given, a friendly name is derived from the email
- **Login**: Restores an existing account session; throttles after 8 failed attempts (5-min block, 429 response)
- **Logout**: Clears the session, returns to the auth gate, shows "You are signed out. Your data is still on the server."
- **Session restore**: On page load, tries to restore the session from the cookie via /api/auth/me
- **Data conflict**: PUT /api/data returns 409 if the revision doesn't match the server's current revision; the response includes the current data so the client can adopt it

## API

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/auth/signup` | `{email, password, name?}` → `201` + session cookie. `name` is optional (≤40 chars). Duplicate email → `409` |
| POST | `/api/auth/login` | `{email, password}` → `200` + session cookie. Bad credentials → `401` |
| POST | `/api/auth/logout` | Ends the session and clears the cookie → `200` |
| GET | `/api/auth/me` | Current user + data + revision. No session → `401` |
| GET | `/api/data` | Current account data. No session → `401` |
| PUT | `/api/data` | `{revision, data}` → `200`. Stale revision → `409` with the current server data |
| GET | `/api/health` | `{"app":"tide","ok":true,"version":1}` |

Other errors: `400` invalid JSON / bad fields, `413` body over 2 MB, `415` non-JSON body, `404` unknown route, `429` throttled login.

## Data Store

- Location: `data/tide-server.json` (relative to the server.ps1 file)
- Created automatically on first run
- Contains: version, createdAt, updatedAt, users (array of user objects)
- Each user has: id, email, name, emailNorm, passwordHash, salt, iterations, data, dataRevision, dataUpdatedAt, createdAt
- Passwords are stored as PBKDF2-SHA256 hashes with random per-user salts (16 bytes, 150,000 iterations)
- Sessions live in memory and do not survive server restart
- To reset all accounts: stop the server, then delete or rename `data/tide-server.json`

## Security Notes

- Server binds to `http://127.0.0.1:8799/` (loopback only)
- Passwords are hashed with PBKDF2-SHA256 (150,000 iterations, 16-byte random salts)
- Sessions carried by HttpOnly, SameSite=Strict cookies
- Login throttling: 8 failures → 5-minute block, returns 429 with Retry-After
- Security headers: Cache-Control: no-store, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer
- Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
- Oversized bodies (>2MB) rejected with 413
- Non-JSON bodies rejected with 415
- Invalid JSON rejected with 400

## Frontend (index.html)

The frontend has been updated to work with the account-backed server:

- **Auth gate**: Shown before sign-in; hides the app shell and tab bar
- **Session restore**: On load, fetches /api/auth/me to restore the session
- **Per-user localStorage cache**: Keyed `tide.cycle.v1.<userId>`, with debounced server sync
- **Conflict adoption**: If the server data changes in another session, the client adopts the newest data
- **Offline retry**: Sync retries after 5 seconds of failures; resumes when back online
- **Theme preference**: Saved as `tide.theme` in localStorage for pre-paint restoration
- **Legacy import**: Prompted after first login to import on-device data (key: `tide.migrate.<userId>`)
- **Clear all data**: Removes data from the server account; local cache also cleared
- **Sign out**: Flushes pending changes, syncs, calls /api/auth/logout, hides app, shows gate with email prefilled

## Cycle Classification Rules

All cycle and prediction logic is derived from the raw daily logs by pure functions (`buildFlowRuns`, `buildSpottingEpisodes`, `buildPeriodEpisodes`, `deriveCycleModel`). Nothing is cached as a computed cycle, so backfilling, editing or deleting a log always produces the same result as a fresh compute.

Thresholds live in one place, `CYCLE_RULES`, near the top of `index.html`:

| Rule | Default | Meaning |
|------|---------|---------|
| `spottingFlow` | `spotting` | The only flow value treated as spotting |
| `flowJoinGapDays` | `1` | Flow days this close are one run |
| `strayGapDays` | `3` | A new cycle needs at least this many non-flow days |
| `strayConfirmFlowDays` | `2` | Flow days needed to accept a new cycle without asking |
| `longGapDays` | `90` | Gaps longer than this leave the prediction average |
| `gapRecoveryCycles` | `3` | Cycles after a gap with a widened window |
| `lowConfidencePadDays` | `7` | Padding applied on each side while relearning |
| `minCycleDays` | `15` | Shorter intervals are ignored as noise |
| `maxPeriodDays` | `14` | Longer completed periods are not averaged |

### Spotting

- Spotting is saved and shown (calendar dot, day sheet, Insights) but **never** starts a cycle and **never** adds to period length.
- Spotting immediately before real flow does not move the cycle start; the first light/medium/heavy day remains day 1.
- A month of only spotting produces no cycle and no period.

### Stray flow days

- Flow logs are grouped into runs. A run only becomes a new cycle when it has at least `strayConfirmFlowDays` flow days **and** is separated from the previous period by at least `strayGapDays` non-flow days — unless the user explicitly confirms that it was a period start.
- A single stray flow day inside an ongoing period extends/joins that period instead of splitting it.
- A single flow day in the middle of a gap is kept in the logs but marked **unconfirmed**. The app asks once (home, day sheet, Insights) whether it was a period start; either answer is stored in `confirmations` (`start` / `not-start`). Logs are never deleted by classification.
- Explicit “Log period” entries are treated as user-confirmed and remain authoritative.

### Long gaps

- A gap longer than `longGapDays` between two period starts is excluded from the cycle-length average and listed in Insights.
- An **open** gap (no new period yet) with no real flow since the last start is surfaced as a neutral check-in. A reason can be stored in `gapTags` keyed by the earlier period start: `pregnant`, `postpartum`, `contraception`, `medical`, `other`, `prefer-not-to-say`.
- `pregnant` and `postpartum` pause predictions, fertile-day estimates and reminders until either real flow is logged or the user taps **Resume predictions** (`settings.resumePredictions = true`). Other reasons only remove the gap from the average.
- After a completed long gap, the first `gapRecoveryCycles` cycles are low confidence: prediction windows are widened by ±`lowConfidencePadDays`. A neutral note explains this until enough new cycles are logged.

### Assumptions

- Only `light`, `medium` and `heavy` count as real flow; `spotting` is the only non-period flow value.
- Explicit period entries are intentional confirmation and are never reclassified by the stray-flow rules.
- “Today” is the current local date; future logs and period starts are rejected by `normalizeData`.
- A gap is measured start-to-start, not end-to-start. Recovery counts cycles after the gap interval, and only the most recent long gap drives the widened window.
- Pausing affects predictions only — it never hides or deletes history. Logging real flow automatically lifts the pause.
- The rules are heuristics for a self-tracking app, not medical advice or contraception.

Exported JSON includes `confirmations` and `gapTags` alongside periods, logs and settings, so an export/import round-trip keeps every classification decision.

## Developing

No Node/npm/Python/dotnet/PHP/Java/Ruby is available. The entire backend stays in PowerShell 5.1 / .NET Framework.

To start the server for CDP testing:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Marvin\Downloads\Red Sea\server.ps1" -NoBrowser
```

Then launch Edge with a fresh user-data-dir for CDP tests:

```powershell
$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$port = 9337
$profile = Join-Path $env:TEMP "edge-tide-cdp"
# ... remove old profile, start Edge with --remote-debugging-port=$port
```

Use the CDP test scripts in `C:\Users\Marvin\AppData\Local\Temp\tide-auth-test.ps1` etc. for automated validation.

## Project Structure

```
C:\Users\Marvin\Downloads\Red Sea\
├── index.html          # Frontend (auth gate, account UI, server sync)
├── server.ps1          # PowerShell backend (auth, sessions, persistence, API routes)
├── data/               # Runtime data store (tide-server.json, created at startup)
└── README.md           # This file
```
### Local notifications

- Browser Notification API only. No service worker or push service is used. Permission is requested from a user action in Insights Settings.
- Notification tone: Discreet (default), Gentle, or Sassy. Sassy is opt-in and never the default.
- Discreet copy never mentions period, flow, cramps, or pregnancy and has no emojis. The lock-screen title/body always use the Discreet version unless the user explicitly turns off \"Discreet notification text\". Choosing Discreet re-enables it.
- period_late and gap_checkin have no Sassy variants and fall back to Gentle even if Sassy is chosen.
- Messages are stored in NOTIFICATION_COPY as 	ype -> tone -> list and rotated per type so the same message doesn't repeat back to back. Unsent history and the last index are stored in the user's account data.
- Safety: pregnancy/postpartum pause or any gap tag of loss or medical suppresses period_soon, period_late, during_period, and all Sassy period jokes. Only discreet daily_log or gap_checkin remain. Supplies are also suppressed in sensitive mode as period-adjacent.
- Auto-downgrade: after recent cramps (logged symptom), a low mood log, or a late period, tone is softened to Gentle (never Sassy) for a configurable window (default 3 days).
- Rules: max 2 notifications per day, priority period_late > period_soon > supplies > during_period > daily_log > gap_checkin > small_win. Quiet hours default 22:00�08:00 and are configurable; nothing fires inside them. Each type is individually togglable. No streak-guilt; small wins are progress-only.
- Scheduling runs only while the app is open (on load, on visibility change, and every 5 minutes). Only successfully delivered notifications count toward the daily cap and advance rotation.
