# PrintDash

A self-hosted office printer management dashboard with SNMP-based toner/status monitoring and Telegram alerts.

## Features

- SNMP polling of networked printers (Canon, HP, and others) for toner levels, paper tray status, jams, and online/offline state
- Web dashboard with login/auth (admin and user roles)
- Telegram notifications for low toner, jams, empty trays, and offline printers, with configurable thresholds and alert cooldown
- Add/manage printers via the web UI or by editing the data file directly
- Single Node.js process, no external database required (flat JSON files for storage)

## Requirements

- Node.js 18+
- Network access (SNMP, UDP 161) to your printers
- **CUPS** installed and running on the host — PrintDash shells out to CUPS command-line tools (`lpstat`, `lp`, `cancel`, `lpadmin`, `lpinfo`, `cupsenable`, `cupsdisable`) for print queue management, job control, and IPP-based printer discovery
- **SANE** (`scanimage`) installed on the host if you want scanner support
- Appropriate printer drivers for your hardware (e.g. Canon, HP) installed via CUPS

On Debian/Ubuntu, the system dependencies can be installed with:

```bash
sudo apt update
sudo apt install -y cups cups-client sane-utils printer-driver-all
```

The user running the Node.js process needs permission to run CUPS admin commands (typically by being a member of the `lpadmin` group):

```bash
sudo usermod -aG lpadmin $USER
```

## Installation

```bash
git clone https://github.com/<your-username>/printdash.git
cd printdash
npm install
```

## Configuration

PrintDash stores its runtime data in three JSON files that are **not** included in this repo (they're gitignored since they hold credentials and your internal network layout). Copy the provided examples to get started:

```bash
cp printers.example.json printers.json
cp settings.example.json settings.json
```

- `printers.json` — list of printers to monitor (IP, SNMP community string, brand, location)
- `settings.json` — Telegram bot token/chat ID and alert thresholds
- `users.json` — created automatically on first run with default accounts `admin/admin123` and `user/user123`. **Change these passwords immediately after first login.**

### Environment variables (optional)

| Variable | Default | Purpose |
|---|---|---|
| `USERS_FILE` | `./users.json` | Path to the users/auth file |
| `DATA_FILE` | `./printers.json` | Path to the printers list |
| `SETTINGS_FILE` | `./settings.json` | Path to the settings file |
| `SCAN_DIR` | `/opt/scans` | Directory used for scan storage |
| `UPLOAD_DIR` | `/tmp/printdash-uploads` | Temp upload directory |

The app listens on port `3003` (edit `PORT` in `server.js` to change this).

## Running

```bash
npm start
```

For production, run it under a process manager such as PM2:

```bash
pm2 start server.js --name printdash
```

## Security notes

- Never commit `users.json`, `printers.json`, or `settings.json` — they contain password hashes, your Telegram bot token, and internal network details. They're excluded via `.gitignore`.
- Passwords are stored salted and hashed (scrypt), never in plaintext.
- Put this behind a reverse proxy with HTTPS if exposing it outside your LAN.

## License

MIT