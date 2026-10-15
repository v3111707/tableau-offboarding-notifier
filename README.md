# Tableau Offboarding Notifier

[![Python](https://img.shields.io/badge/Python-3.14%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Tableau Server Client](https://img.shields.io/badge/Tableau-Server%20Client-E97627?logo=tableau&logoColor=white)](https://tableau.github.io/server-client-python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Tableau Offboarding Notifier is a Python CLI that helps operations teams find Tableau content owned by employees who are leaving the company and notify the right people before the content becomes orphaned.

The script reads upcoming termination data from SAP SuccessFactors, resolves managers and email addresses, scans every Tableau Server site for workbooks and projects where the employee is the owner or the business owner, and sends templated HTML email reminders. Runtime configuration is stored in `config.toml`, while credentials and operational parameters are loaded from HashiCorp Vault.

## What It Does

1. Loads Vault connection settings from `config.toml`.
2. Reads SAP SuccessFactors, Tableau Server, SMTP, Sentry, and recipient settings from Vault.
3. Builds and signs a SAML assertion with `signxml`.
4. Exchanges the assertion for a SAP SuccessFactors OAuth token.
5. Fetches employees with termination dates from the previous 7 days through the next 30 days.
6. Finds Tableau workbooks and projects on every site where each leaving employee is the owner or the business owner (see [Business Owner](#business-owner)).
7. Sends notification emails to the employee, their manager, and configured additional recipients. Employees without any Tableau content are skipped.
8. Sends heartbeat and exit-code metrics to Zabbix.

Email send state is stored in `hrms_report_sender_email_states.json` to avoid duplicate reminders.

## Notification Schedule

| Stage | Condition | Behavior |
|-------|-----------|----------|
| First notice | `days_left >= 7` | Sends the first reminder |
| Second notice | `0 <= days_left < 7` | Sends the second reminder |
| Third notice | `-5 <= days_left < 0` | Sends the final reminder after the termination date |
| Cleanup | `days_left < -5` | Removes local email state for the user |

## Business Owner

Tableau has no built-in business owner field, so the script reads it from the resource description. Add a line like this to a workbook or project description:

```text
Business owner – a_doe@example.com
```

- The match is case-insensitive; `-`, `–`, `—`, and `:` are accepted as separators.
- Only the first `Business owner` entry in a description is used.
- The email is resolved to a Tableau user by the user's email on the same site.
- If the employee is both the owner and the business owner of a resource, it is listed once with both roles.

## Requirements

- Python 3.14+
- Access to SAP SuccessFactors OData API
- SAP SuccessFactors SAML signing certificate and private key
- Access to Tableau Server with a service account
- HashiCorp Vault AppRole credentials
- SMTP account for sending email
- Sentry DSN
- Zabbix agent configuration, unless running with `--zs`

## Installation

```bash
git clone https://github.com/v3111707/tableau-offboarding-notifier.git
cd tableau-offboarding-notifier
python -m venv .venv
source .venv/bin/activate
pip install .
```

You can also install dependencies directly from `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Configuration

Copy the example files and fill in organization-specific values:

```bash
cp config.toml.example config.toml
cp leaving_users_report.html.jinja2.example leaving_users_report.html.jinja2
```

`config.toml`, `leaving_users_report.html.jinja2`, JSON state files, and logs are ignored by Git.

### `config.toml`

```toml
[vault]
url = "https://vault.example.com"
role_id = "..."
secret_id = "..."

[vault.paths]
params = "path/to/script/params"
creds = "path/to/script/creds"
common = "path/to/common/"
```

### Vault Secrets

The script reads three Vault locations.

`vault.paths.creds`:

| Key | Description |
|-----|-------------|
| `hrms_url` | SAP SuccessFactors base URL |
| `hrms_company_id` | SAP SuccessFactors company ID |
| `hrms_client_id` | OAuth client ID used as the SAML `api_key` attribute |
| `hrms_user_id` | Technical user ID used as SAML `NameID` |
| `hrms_token_url` | OAuth token endpoint URL |
| `hrms_cert_pem` | X.509 certificate in PEM format |
| `hrms_key_pem` | Private key in PEM format |
| `ts_url` | Tableau Server URL |
| `ts_username` | Tableau service account username |
| `ts_password` | Tableau service account password |

`vault.paths.params`:

| Key | Description |
|-----|-------------|
| `sentry_dsn` | Sentry DSN for error tracking |
| `mail_to` | Comma-separated list of additional recipients |

`vault.paths.common` + `mail-bot`:

| Key | Description |
|-----|-------------|
| `host` | SMTP host |
| `port` | SMTP port |
| `username` | SMTP username |
| `password` | SMTP password |
| `sender` | Optional sender address; defaults to `username` |

## Email Template

The default template is `leaving_users_report.html.jinja2.example`. After copying it to `leaving_users_report.html.jinja2`, update the support link and team signature for your organization.

The template receives the full user record plus these important fields:

| Variable | Description |
|----------|-------------|
| `userId` | Leaving employee SuccessFactors user ID |
| `username` | Leaving employee username |
| `displayName` | Leaving employee display name |
| `email` | Leaving employee email |
| `manager` | Manager user object from SuccessFactors |
| `termination_date` | Parsed termination date |
| `tableau_resources` | Dict of site name to workbooks, projects, and `user_content_url` (a link built from the Tableau Server URL) |

`tableau_resources` structure:

```python
{
    "<site name>": {
        "user_content_url": "https://tableau.example.com/#/user/local/a_doe/content",
        "workbooks": [
            {"name": "Sales Overview", "project_name": "Sales",
             "project_path": "Home / Sales", "roles": ["owner", "business_owner"]},
        ],
        "projects": [
            {"name": "Regional Reports", "path": "Home / Sales", "roles": ["owner"]},
        ],
    },
}
```

## Email Example

**Subject:** Moving tableau.example.com reports of the user leaving the company
**To:** a_doe@example.com, j_smith@example.com, plus `mail_to` recipients

> Hello,
>
> As you are assigned as a manager of a person **Alex Doe** who is leaving the company soon, we would like to ask you to review the Tableau content that is presented below:
>
> **Default**: https://tableau.example.com/#/user/local/a_doe/content
> **Marketing**: https://tableau.example.com/#/site/marketing/user/local/a_doe/content
>
> On the Tableau server, the employee is the owner and/or business owner of the following content:
>
> | Site name | Type | Location | Name | Role |
> |-----------|------|----------|------|------|
> | Default | Workbook | Home / Sales | Sales Overview | Owner, Business owner |
> | Default | Project | Home / Sales | **Regional Reports** | Owner |
> | Marketing | Workbook | Home / Campaigns / 2026 | Campaign Performance | Business owner |
>
> We would like to ask you to complete the following steps:
>
> 1. Review to identify what reports can be removed and what reports should be moved to the new owner
> 2. Assign the reports you want to keep to the new owners.
>
> Please note that when you change the report owner, you should reenter and reserve the credentials to the data connection.
>
> If you need any assistance with the steps, you can contact our team using the link.
>
> In case that required information isn't provided, all content owned by the employee will be moved to your personal folder, and you will be assigned as the owner of the reports.
>
> For content where the employee is a business owner, please specify a new business owner in the content description.
>
> Best regards,
> Your team

## Usage

```bash
python offboarding_notifier.py [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-d`, `--debug` | Enable debug logging |
| `-m`, `--mail_to TEXT` | Override recipients with a comma-separated email list |
| `-p` | Print fetched HRMS report data as JSON and exit |
| `-l TEXT` | Load report data from a JSON file instead of querying HRMS |
| `-s TEXT` | Save fetched HRMS report data to a JSON file and exit |
| `--zt` | Send test value `1` to Zabbix and exit |
| `--zs` | Use Zabbix stub and skip actual Zabbix sends |
| `-h`, `--help` | Show CLI help |

### Examples

Fetch HRMS data, print it, and skip Zabbix sends:

```bash
python offboarding_notifier.py -p --zs
```

Save fetched HRMS data for later testing:

```bash
python offboarding_notifier.py -s data.json --zs
```

Run from a previously saved report file:

```bash
python offboarding_notifier.py -l data.json --zs
```

Send test notifications only to one mailbox:

```bash
python offboarding_notifier.py -l data.json -m your.email@example.com --zs
```

## Monitoring and Runtime Files

The script writes logs to `offboarding_notifier.log` in the repository directory and rotates them with a 20 MiB limit and 5 backups.

Zabbix metrics:

| Key | Value |
|-----|-------|
| `hrms_report_sender_heartbeat` | `1` at startup |
| `hrms_report_sender_exit_code` | `0` on successful completion |

Local runtime files:

| File | Purpose |
|------|---------|
| `config.toml` | Vault connection settings |
| `leaving_users_report.html.jinja2` | Organization-specific email template |
| `hrms_report_sender_email_states.json` | Notification state used to prevent duplicate sends |
| `offboarding_notifier.log` | Rotating application log |

## Running on a Schedule

The script is intended to run from cron or another scheduler. Example daily run at 09:00:

```cron
0 9 * * * /path/to/tableau-offboarding-notifier/.venv/bin/python /path/to/tableau-offboarding-notifier/offboarding_notifier.py
```

Use an absolute path so `config.toml`, the email template, logs, and state files resolve consistently.

## Repository Structure

```text
tableau-offboarding-notifier/
|-- offboarding_notifier.py                  # Main Typer CLI and integration logic
|-- config.toml.example                      # Vault configuration template
|-- leaving_users_report.html.jinja2.example # HTML email template example
|-- pyproject.toml                           # Python package metadata and dependencies
|-- requirements.txt                         # pip-compatible dependency list
|-- LICENSE                                  # MIT license
`-- README.md                                # Project documentation
```

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

This project uses:

- [Python](https://www.python.org/)
- [Typer](https://typer.tiangolo.com/)
- [Tableau Server Client](https://tableau.github.io/server-client-python/)
- [SignXML](https://xml-security.github.io/signxml/)
- [hvac](https://hvac.readthedocs.io/)
- [Jinja](https://jinja.palletsprojects.com/)
- [Sentry SDK](https://docs.sentry.io/platforms/python/)
- [zabbix-utils](https://github.com/zabbix/python-zabbix-utils)
