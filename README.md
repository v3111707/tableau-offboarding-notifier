# Tableau Offboarding Notifier

A script that automatically notifies managers about Tableau content owned by employees who are leaving the company. It queries SAP SuccessFactors for upcoming terminations, finds owned workbooks and projects on Tableau Server, and sends email reminders on a schedule.

## How it works

1. Loads runtime config from `config.toml` and fetches secrets from Vault.
2. Builds and signs a SAML assertion (`signxml`) and exchanges it for SAP SuccessFactors OAuth token.
3. Fetches employees with upcoming termination dates from SAP SuccessFactors.
4. For each employee, scans all Tableau Server sites for owned workbooks and projects.
5. Sends an email to recipients with a list of content that needs to be reassigned.

Emails are sent at three stages:
- **First notice** — `days_left >= 7`
- **Second notice** — `0 <= days_left < 7`
- **Third notice** — `-5 <= days_left < 0`

When `days_left < -5`, local mail state for that user is cleaned.

Email send state is tracked in `hrms_report_sender_email_states.json` to avoid duplicate sends.

## Requirements

- Python 3.14+
- Access to SAP SuccessFactors API
- Access to Tableau Server
- HashiCorp Vault (for secrets)
- SAML signing material for SuccessFactors (`cert` + `private key`)
- Zabbix agent (for monitoring), optional via `--zs` stub flag
- Sentry DSN (for error tracking)

## Installation

```bash
git clone https://github.com/your-org/github-tableau-offboarding-notifier.git
cd github-tableau-offboarding-notifier
python -m venv .venv
source .venv/bin/activate
pip install .
```

## Configuration

Copy the example config and fill in your values:

```bash
cp config.toml.example config.toml
```

`config.toml` is gitignored and never committed. All sensitive credentials are read from Vault at runtime using the role/secret IDs in the config.

### Vault secret structure

The script expects the following secrets in Vault:

**`vault.paths.creds`**
| Key | Description |
|-----|-------------|
| `hrms_url` | SAP SuccessFactors base URL |
| `hrms_company_id` | Company ID for SAML auth |
| `hrms_client_id` | OAuth client ID |
| `hrms_user_id` | SuccessFactors technical user ID used in SAML `NameID` |
| `hrms_token_url` | SuccessFactors OAuth token endpoint URL |
| `hrms_cert_pem` | X.509 certificate in PEM format (for signed assertion) |
| `hrms_key_pem` | Private key in PEM format (for signed assertion) |
| `ts_url` | Tableau Server URL |
| `ts_username` | Tableau service account username |
| `ts_password` | Tableau service account password |

**`vault.paths.params`**
| Key | Description |
|-----|-------------|
| `sentry_dsn` | Sentry DSN for error tracking |
| `mail_to` | Comma-separated list of additional email recipients |

**`vault.paths.common` + `mail-bot`**
| Key | Description |
|-----|-------------|
| `host` | SMTP host |
| `port` | SMTP port |
| `username` | SMTP username |
| `password` | SMTP password |
| `sender` | Optional sender email; defaults to `username` if omitted |

## Email template

Copy the example template and customize it for your organization:

```bash
cp leaving_users_report.html.jinja2.example leaving_users_report.html.jinja2
```

The template receives the following variables:

| Variable | Description |
|----------|-------------|
| `displayName` | Full name of the leaving employee |
| `tableau_resources` | Dict of site name → `{user_content_url, workbooks, projects}` |

## Usage

```
python offboarding_notifier.py [OPTIONS]

Options:
  -d, --debug        Enable debug logging
  -m, --mail_to      Override recipients (comma-separated emails)
  -p                 Print fetched HRMS data as JSON and exit
  -l TEXT            Load report data from a JSON file instead of HRMS
  -s TEXT            Save fetched HRMS data to a JSON file and exit
  --zt               Send test value "1" to Zabbix and exit
  --zs               Use Zabbix stub (skip actual Zabbix sends)
  -h, --help         Show this message and exit
```

### Examples

Dry-run: fetch data from HRMS and print without sending emails:
```bash
python offboarding_notifier.py -p --zs
```

Save fetched data to a file for later use:
```bash
python offboarding_notifier.py -s data.json --zs
```

Run using a previously saved file instead of querying HRMS:
```bash
python offboarding_notifier.py -l data.json --zs
```

Override recipients (useful for testing):
```bash
python offboarding_notifier.py -m your@email.com --zs
```

## Running on a schedule

The script is designed to be run as a cron job. Example — run daily at 9:00 AM:

```cron
0 9 * * * /path/to/.venv/bin/python /path/to/offboarding_notifier.py
```

## Monitoring

The script sends two Zabbix metrics on each run:

| Key | Value |
|-----|-------|
| `hrms_report_sender_heartbeat` | `1` on start |
| `hrms_report_sender_exit_code` | `0` on success |

Use `--zs` flag to disable Zabbix sends (e.g. during local testing).
