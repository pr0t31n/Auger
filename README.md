<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Auger — Database Security Auditor

Auger is a read-only, authenticated database security auditor for the pr0t31n toolkit. It performs thorough security assessments across a wide range of database engines, maps findings to major compliance frameworks, and integrates with Crucible as a managed console tool.

---

## Features

- **Multi-engine support**: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Cassandra, Elasticsearch, CouchDB, InfluxDB, Neo4j, Memcached, AWS Redshift, AWS DynamoDB
- **Read-only**: zero writes, zero config changes — all checks use SELECT/SHOW/GET
- **False-positive prevention**: every finding is confirmed before reporting; ambiguous findings are flagged with `validation_required=true` and specific validation commands
- **Compliance mappings per finding**: OWASP ASVS 4.0, ISO 27001:2022, PCI DSS v4.0, HIPAA §164, NIST SP 800-53
- **Oracle Label Security (OLS)** and **Row-Level Security (RLS)** checks for Oracle and PostgreSQL
- **CVE database**: offline per-engine CVE tables with CVSS scores
- **Default credentials check**: probes known default username/password pairs per engine
- **Sensitive column detection**: scans `information_schema` for PII/PHI/PCI column names
- **TLS/SSL inspection**: version, cipher suite, certificate expiry, self-signed detection
- **Findings catalogue**: 44-entry JSON catalogue (`catalogue/auger_catalogue.json`) with full compliance metadata
- **Fracture-compatible output**: `findings.json`, `findings.csv`, `summary.json`, `scan.log`, `errors.log`
- **Crucible integration**: runs as a managed subprocess under Crucible's console tab (tool key `db`)

---

## Requirements

- Python 3.10+
- macOS: `libpq`, `openssl`, `freetds` (via Homebrew)
- Linux: `libpq-dev`, `libssl-dev`, `freetds-dev`, `unixodbc-dev`
- See `requirements.txt` for Python packages

---

## Installation

```bash
python3 install.py
```

For production deployment (requires sudo):

```bash
sudo bash /tmp/deploy_auger.sh
```

---

## Usage

### Basic (direct)

```bash
# MySQL
python3 auger.py --host 192.168.1.10 --db-type mysql -U root -P password

# PostgreSQL
python3 auger.py --host 192.168.1.20 --db-type postgresql -U postgres -P password --database mydb

# MSSQL
python3 auger.py --host 192.168.1.30 --db-type mssql -U sa -P password

# MongoDB (no auth)
python3 auger.py --host 192.168.1.40 --db-type mongodb

# Redis with password
python3 auger.py --host 192.168.1.50 --db-type redis -P mypassword

# Elasticsearch
python3 auger.py --host 192.168.1.60 --db-type elasticsearch -U elastic -P password
```

### JDBC connection string

```bash
python3 auger.py --jdbc "jdbc:mysql://192.168.1.10:3306/appdb" -U root -P password
```

### TLS/SSL

```bash
python3 auger.py --host db.example.com --db-type postgresql -U postgres -P password \
    --ssl --ssl-ca /path/to/ca.pem
```

### Settings file (Crucible-managed)

```bash
python3 auger.py --settings /path/to/project/db_settings.json
```

### Project output directory

```bash
python3 auger.py --host 192.168.1.10 --db-type mysql -U root -P password \
    --project /opt/pr0t31n/Crucible/data/projects/my_project/auger_output
```

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `--settings FILE` | Load all settings from a JSON file (Crucible mode) |
| `--host HOST` | Target hostname or IP |
| `--port PORT` | Target port (default: per DB type) |
| `--db-type TYPE` | Database type (see supported list below) |
| `-U, --username` | Database username |
| `-P, --password` | Database password |
| `--database NAME` | Database/schema name to audit |
| `--jdbc URL` | JDBC connection string (overrides host/port/type) |
| `--auth-type TYPE` | Auth type: `password`, `kerberos`, `ldap`, `iam` |
| `--ssl` | Enable SSL/TLS for the connection |
| `--ssl-ca FILE` | CA certificate path |
| `--ssl-cert FILE` | Client certificate path |
| `--ssl-key FILE` | Client key path |
| `--ssl-verify` | Verify SSL certificate (default: False) |
| `--aws-profile NAME` | AWS profile for IAM auth (Redshift/DynamoDB) |
| `--aws-region REGION` | AWS region |
| `--timeout SECS` | Connection timeout in seconds (default: 10) |
| `--threads N` | Worker threads for parallel checks (default: 4) |
| `--project DIR` | Output directory for findings |

---

## Supported Database Types

| Type key | Engine |
|----------|--------|
| `mysql` | MySQL 5.x, 8.x |
| `mariadb` | MariaDB 10.x |
| `postgresql` | PostgreSQL 12–17 |
| `mssql` | Microsoft SQL Server 2012–2022 |
| `oracle` | Oracle Database 11g–21c |
| `mongodb` | MongoDB 4.x–7.x |
| `redis` | Redis 5.x–7.x |
| `cassandra` | Apache Cassandra 3.x–5.x |
| `elasticsearch` | Elasticsearch 7.x–8.x |
| `couchdb` | Apache CouchDB 3.x |
| `influxdb` | InfluxDB 2.x |
| `neo4j` | Neo4j 4.x–5.x |
| `memcached` | Memcached 1.6.x |
| `redshift` | AWS Redshift |
| `dynamodb` | AWS DynamoDB |

---

## Output Files

All output is written to the project directory (or `./auger_output_<timestamp>/` if `--project` is not set):

| File | Description |
|------|-------------|
| `findings.json` | All confirmed findings in Fracture-compatible schema |
| `findings.csv` | CSV export of findings |
| `summary.json` | Scan summary (total counts by risk, engine version, scan metadata) |
| `scan.log` | Full scan activity log |
| `errors.log` | Non-fatal errors and warnings |

---

## Findings Schema

Auger produces Fracture-compatible `findings.json` with these additional fields:

```json
{
  "title": "...",
  "datetime": "2026-01-01T00:00:00",
  "ip": "192.168.1.10",
  "port": "3306",
  "hostname": "192.168.1.10",
  "risk": "HIGH",
  "command": "SHOW VARIABLES LIKE 'have_ssl'",
  "description": "...",
  "output": "...",
  "cves": "CVE-XXXX-XXXX",
  "sources": "auger-mysql",
  "service": "mysql",
  "owasp": "A02:2021",
  "owasp_asvs": "V9.1.1",
  "iso_27001": "A.8.24",
  "pci_dss": "4.2.1",
  "hipaa": "164.312(e)(1)",
  "nist": "SC-8",
  "remediation": "...",
  "db_type": "mysql",
  "db_version": "8.0.36",
  "phase": "network",
  "validation_required": false,
  "validation_notes": "",
  "catalogue_id": "DB-001"
}
```

---

## Crucible Integration

Auger runs as a managed subprocess under Crucible (tool key `db`). When launched by Crucible:

- `CRUCIBLE_MANAGED=1` is set in the environment
- All output is emitted via protocol tokens (`__CRUCIBLE_LOG__:`, `__CRUCIBLE_ERR__:`, `__CRUCIBLE_STATUS__:`, `__CRUCIBLE_PROMPT__:`)
- Settings are passed via a `db_settings.json` file in the project directory
- Findings are loaded from `auger_output/findings.json` by Crucible's findings panel

---

## Compliance Mappings

Each finding in `catalogue/auger_catalogue.json` includes:

| Framework | Standard |
|-----------|----------|
| OWASP ASVS | Application Security Verification Standard 4.0 |
| ISO 27001 | ISO/IEC 27001:2022 Annex A controls |
| PCI DSS | Payment Card Industry DSS v4.0 |
| HIPAA | Health Insurance Portability and Accountability Act §164 |
| NIST | SP 800-53 Rev 5 controls |
| Oracle OLS | Oracle Label Security (Oracle findings only) |
| RLS | Row-Level Security (PostgreSQL/Oracle findings) |

---

## False-Positive Prevention

Auger takes multiple steps to avoid false positives:

1. **Connectivity confirmation** — all audits require a successful authenticated connection before any checks run
2. **Direct query confirmation** — every finding is based on direct query output, not inference
3. **Default credential checks** — only reported when login actually succeeds
4. **Version range checks** — CVE findings validated against actual version strings
5. **Ambiguous findings** — flagged with `"validation_required": true` and `"validation_notes"` containing specific `bash` commands, GitHub repos, or tools to confirm the finding

---

## pr0t31n Integration Points

- **Crucible** — managed console tool (tool key `db`)
- **Prometheus** — findings ingested via `parsers/auger.py`
- **Arsenal** — registered for install/version tracking
