#!/usr/bin/env python3
"""
auger.py — Database Security Auditor

Performs comprehensive authenticated security audits of network-accessible
databases: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, MongoDB, Redis,
Cassandra, Elasticsearch, CouchDB, InfluxDB, Neo4j, Memcached, and AWS
managed databases (RDS, DynamoDB, Redshift).

Does NOT modify the database in any way.
Accepts Crucible as a management console.
"""

import sys
import os
import json
import re
import socket
import ssl
import argparse
import threading
import time
import csv
import hashlib
import platform
import ipaddress
import traceback
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

# ---------------------------------------------------------------------------
# Crucible protocol tokens (same as Fracture/Siphon)
# ---------------------------------------------------------------------------
_CRUCIBLE_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
_CP_LOG    = "__CRUCIBLE_LOG__:"
_CP_ERR    = "__CRUCIBLE_ERR__:"
_CP_PROMPT = "__CRUCIBLE_PROMPT__:"
_CP_STATUS = "__CRUCIBLE_STATUS__:"
_CP_ACTION  = "__CRUCIBLE_ACTION_ITEM__:"
_CP_FINDING = "__CRUCIBLE_FINDING__:"

try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_pause as _pp
except ImportError:
    _pp = None
_PAUSE = None

# ---------------------------------------------------------------------------
# ANSI colours (disabled under Crucible)
# ---------------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as _ca_init
    _ca_init(autoreset=True)
    _HAS_COLOR = not _CRUCIBLE_MANAGED
except ImportError:
    class _FallbackFore:
        CYAN = RED = GREEN = YELLOW = WHITE = MAGENTA = ""
    class _FallbackStyle:
        RESET_ALL = ""
    Fore  = _FallbackFore()
    Style = _FallbackStyle()
    _HAS_COLOR = False

# ---------------------------------------------------------------------------
# EOL version tables (confirmed by vendor EOL announcements)
# ---------------------------------------------------------------------------
_EOL_VERSIONS = {
    "mysql": {
        "5.0": True, "5.1": True, "5.5": True, "5.6": True, "5.7": True,
    },
    "mariadb": {
        "5.5": True, "10.0": True, "10.1": True, "10.2": True, "10.3": True,
        "10.4": True, "10.5": True, "10.6": False,
    },
    "postgresql": {
        "9.0": True, "9.1": True, "9.2": True, "9.3": True, "9.4": True,
        "9.5": True, "9.6": True, "10": True, "11": True, "12": False,
    },
    "mssql": {
        "2005": True, "2008": True, "2012": True, "2014": True, "2016": False,
    },
    "oracle": {
        "9i": True, "10g": True, "11g": True, "11.1": True, "11.2": True,
        "12.1": True, "12.2": False,
    },
    "mongodb": {
        "2.4": True, "2.6": True, "3.0": True, "3.2": True, "3.4": True,
        "3.6": True, "4.0": True, "4.2": False,
    },
    "redis": {
        "2.0": True, "2.2": True, "2.4": True, "2.6": True, "2.8": True,
        "3.0": True, "3.2": True, "4.0": True, "5.0": False,
    },
    "elasticsearch": {
        "1.0": True, "1.5": True, "1.7": True, "2.0": True, "2.4": True,
        "5.0": True, "5.6": True, "6.0": True, "6.8": True, "7.0": False,
    },
    "cassandra": {
        "1.0": True, "1.1": True, "1.2": True, "2.0": True, "2.1": True,
        "2.2": True, "3.0": False,
    },
}

# ---------------------------------------------------------------------------
# Critical CVEs by database type and version prefix
# ---------------------------------------------------------------------------
_KNOWN_CVES = {
    "mysql": [
        {"cve": "CVE-2016-6662", "versions": ["5.5", "5.6", "5.7"], "cvss": 10.0,
         "desc": "MySQL configuration file injection via general_log_file, allowing RCE as root."},
        {"cve": "CVE-2016-6663", "versions": ["5.5", "5.6", "5.7"], "cvss": 7.0,
         "desc": "Race condition allowing local privilege escalation to mysql system user."},
        {"cve": "CVE-2021-2022", "versions": ["8.0"], "cvss": 4.4,
         "desc": "InnoDB vulnerability allowing high-privilege attackers to cause DoS."},
        {"cve": "CVE-2023-21980", "versions": ["8.0"], "cvss": 7.1,
         "desc": "MySQL Server privilege escalation via optimizer component."},
    ],
    "postgresql": [
        {"cve": "CVE-2018-1058", "versions": ["9.3", "9.4", "9.5", "9.6", "10"], "cvss": 8.8,
         "desc": "Uncontrolled search_path allows superuser function hijacking."},
        {"cve": "CVE-2019-10164", "versions": ["11", "10", "9.6", "9.5", "9.4"], "cvss": 7.5,
         "desc": "Stack-based buffer overflow in SCRAM message processing."},
        {"cve": "CVE-2023-2454", "versions": ["15", "14", "13", "12", "11"], "cvss": 7.2,
         "desc": "Row security policies can be bypassed by superuser."},
    ],
    "mssql": [
        {"cve": "CVE-2019-1068", "versions": ["2014", "2016", "2017"], "cvss": 8.8,
         "desc": "Remote code execution via database engine memory corruption."},
        {"cve": "CVE-2021-1636", "versions": ["2014", "2016", "2017", "2019"], "cvss": 8.8,
         "desc": "Microsoft SQL Server privilege escalation vulnerability."},
        {"cve": "CVE-2022-23276", "versions": ["2019", "2017"], "cvss": 8.8,
         "desc": "SQL Server elevation of privilege vulnerability."},
    ],
    "mongodb": [
        {"cve": "CVE-2019-2389", "versions": ["4.0", "3.6", "3.4"], "cvss": 7.5,
         "desc": "MongoDB arbiter can bypass auth and access replica set data."},
        {"cve": "CVE-2021-32036", "versions": ["4.4", "4.2", "4.0"], "cvss": 6.5,
         "desc": "Missing authorization on certain diagnostic commands allows info disclosure."},
    ],
    "redis": [
        {"cve": "CVE-2022-0543", "versions": ["6.0", "6.2", "5.0"], "cvss": 10.0,
         "desc": "Lua sandbox escape in Debian/Ubuntu packages allowing RCE."},
        {"cve": "CVE-2023-28425", "versions": ["7.0"], "cvss": 5.5,
         "desc": "OBJECT ENCODING command argument injection."},
        {"cve": "CVE-2021-32761", "versions": ["6.2", "6.0", "5.0"], "cvss": 6.0,
         "desc": "Integer overflow in GETDEL/GETEX commands."},
    ],
    "elasticsearch": [
        {"cve": "CVE-2014-3120", "versions": ["1.1", "1.2"], "cvss": 9.0,
         "desc": "Dynamic scripting RCE via Groovy sandbox escape."},
        {"cve": "CVE-2021-22145", "versions": ["7.13", "7.12"], "cvss": 6.5,
         "desc": "Sensitive information disclosure in error messages."},
        {"cve": "CVE-2023-31419", "versions": ["8.8", "7.17"], "cvss": 7.5,
         "desc": "Stack overflow in wildcard query processing (DoS)."},
    ],
    "cassandra": [
        {"cve": "CVE-2021-44521", "versions": ["3.0", "3.11", "4.0"], "cvss": 9.1,
         "desc": "UDF execution allows RCE via Nashorn JS engine (when allow_insecure_udfs=true)."},
    ],
}

# ---------------------------------------------------------------------------
# Default credentials database
# ---------------------------------------------------------------------------
_DEFAULT_CREDS = {
    "mysql":         [("root", ""), ("root", "root"), ("root", "mysql"),
                      ("root", "toor"), ("mysql", "mysql"), ("admin", "admin")],
    "mariadb":       [("root", ""), ("root", "root"), ("root", "mariadb"), ("mysql", "mysql")],
    "postgresql":    [("postgres", "postgres"), ("postgres", ""), ("admin", "admin"),
                      ("postgres", "password")],
    "mssql":         [("sa", ""), ("sa", "sa"), ("sa", "password"), ("sa", "Password1"),
                      ("sa", "Admin1234!"), ("admin", "admin")],
    "oracle":        [("sys", "change_on_install"), ("system", "manager"),
                      ("scott", "tiger"), ("hr", "hr"), ("sh", "sh"),
                      ("oe", "oe"), ("pm", "pm"), ("bi", "bi"),
                      ("dbsnmp", "dbsnmp"), ("sysman", "sysman"),
                      ("outln", "outln"), ("mdsys", "mdsys")],
    "mongodb":       [("admin", "admin"), ("root", "root"), ("admin", ""),
                      ("administrator", "administrator")],
    "redis":         [("", ""), ("", "redis"), ("", "password"), ("", "admin"),
                      ("", "123456"), ("", "foobared")],
    "cassandra":     [("cassandra", "cassandra"), ("admin", "admin")],
    "elasticsearch": [("elastic", "changeme"), ("elastic", "elastic"),
                      ("admin", "admin"), ("kibana", "kibana")],
    "couchdb":       [("admin", "admin"), ("admin", "password"), ("couchdb", "couchdb")],
    "influxdb":      [("admin", "admin"), ("admin", "password"), ("influxdb", "influxdb"),
                      ("root", "root")],
    "neo4j":         [("neo4j", "neo4j"), ("neo4j", "password"), ("admin", "admin")],
}

# ---------------------------------------------------------------------------
# Compliance mappings helper
# ---------------------------------------------------------------------------
_OWASP_URLS = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
}


def _load_catalogue() -> dict:
    """Load finding catalogue keyed by finding ID."""
    cat_path = Path(__file__).parent / "catalogue" / "auger_catalogue.json"
    if not cat_path.exists():
        return {}
    try:
        items = json.loads(cat_path.read_text(encoding="utf-8"))
        return {item["id"]: item for item in items if "id" in item}
    except Exception:
        return {}


_CATALOGUE = _load_catalogue()

# ---------------------------------------------------------------------------
# Console  (Crucible-aware)
# ---------------------------------------------------------------------------
class AugerConsole:
    def __init__(self):
        self._managed = _CRUCIBLE_MANAGED
        self._lock = threading.Lock()

    @property
    def managed(self):
        return self._managed

    def log(self, message: str, level: str = "INFO") -> None:
        with self._lock:
            if self._managed:
                entry = {"ts": datetime.now().isoformat(), "level": level, "message": message}
                sys.stdout.write(_CP_LOG + json.dumps(entry) + "\n")
                sys.stdout.flush()
            else:
                _tags = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[~]",
                         "ERROR": "[!]", "DEBUG": "[.]"}
                _cols = {"INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "WARNING": Fore.YELLOW,
                         "ERROR": Fore.RED, "DEBUG": Fore.WHITE}
                c = _cols.get(level, "") if _HAS_COLOR else ""
                tag = _tags.get(level, "[*]")
                reset = Style.RESET_ALL if _HAS_COLOR else ""
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"{c}[{ts}] {tag}{reset} {message}")

    def error(self, message: str, detail: str = "") -> None:
        with self._lock:
            if self._managed:
                entry = {"ts": datetime.now().isoformat(), "source": "auger",
                         "message": message, "detail": detail, "category": "Scan"}
                sys.stderr.write(_CP_ERR + json.dumps(entry) + "\n")
                sys.stderr.flush()
            else:
                r = Style.RESET_ALL if _HAS_COLOR else ""
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"{Fore.RED if _HAS_COLOR else ''}[{ts}] [!]{r} {message}", file=sys.stderr)

    def status(self, phase: str, label: str = "", status: str = "running",
               step: str = "", progress: int = 0, total: int = 0) -> None:
        with self._lock:
            if self._managed:
                entry = {"phase": phase, "label": label or phase, "status": status,
                         "step": step, "progress": progress, "total": total,
                         "ts": datetime.now().isoformat()}
                sys.stdout.write(_CP_STATUS + json.dumps(entry) + "\n")
                sys.stdout.flush()
            else:
                pct = f" ({progress}/{total})" if total else ""
                r = Style.RESET_ALL if _HAS_COLOR else ""
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"{Fore.MAGENTA if _HAS_COLOR else ''}[{ts}] [{label or phase}]{r} {step}{pct}")

    def action_item(self, entry: dict) -> None:
        with self._lock:
            if self._managed:
                sys.stdout.write(_CP_ACTION + json.dumps(entry) + "\n")
                sys.stdout.flush()
            else:
                tool = entry.get("recommended_tool", "unknown")
                title = entry.get("title", "")
                target = entry.get("target", "")
                r = Style.RESET_ALL if _HAS_COLOR else ""
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"{Fore.YELLOW if _HAS_COLOR else ''}[{ts}] [ACTION → {tool}]{r} {title}  ({target})")


_console = AugerConsole()

# Human-readable labels for check methods — turns "check_ssl_config" into
# "SSL configuration" for console output.
_CHECK_LABELS: dict = {}

def _check_label(method_name: str) -> str:
    if method_name in _CHECK_LABELS:
        return _CHECK_LABELS[method_name]
    label = method_name.replace("check_", "").replace("_check_", "")
    label = label.replace("_", " ").strip()
    return label


def _run_checks(db_label: str, host: str, port: int, checks: list,
                out: "AugerOutput") -> list:
    """Run a list of (method, phase) pairs with verbose START/END logging."""
    phases: list = []
    total = len(checks)
    for idx, (method, phase) in enumerate(checks, 1):
        label = _check_label(method.__name__)
        _console.status(db_label.lower(), label=f"{db_label} {phase}",
                        step=method.__name__, status="running",
                        progress=idx, total=total)
        _console.log(f"[{phase}] Checking {label} on {host}:{port}...", "INFO")
        out.log_step(f"START {db_label} {method.__name__} ({phase})")
        try:
            result = method()
            if result is not None and isinstance(result, str) and result:
                _console.log(f"[{phase}] {label} — {result}", "SUCCESS")
            else:
                _console.log(f"[{phase}] {label} — done", "INFO")
        except Exception as e:
            _console.log(f"[{phase}] {label} — error: {e}", "ERROR")
            out.log_error(method.__name__, str(e))
        out.log_step(f"END   {db_label} {method.__name__}")
        if phase not in phases:
            phases.append(phase)
    return phases


# ---------------------------------------------------------------------------
# Output / finding manager  (Fracture-compatible schema)
# ---------------------------------------------------------------------------
_RE_UNSAFE = re.compile(r'[^\w\-]')

FINDINGS_CSV_FIELDS = [
    "title", "datetime", "ip", "port", "hostname", "risk", "command",
    "description", "output", "cves", "sources", "service", "output_file",
    "affected", "owasp", "owasp_asvs", "iso_27001", "pci_dss", "hipaa",
    "nist", "remediation", "db_type", "db_version", "phase",
    "validation_required", "validation_notes",
]

class AugerOutput:
    _findings_lock = threading.Lock()
    _log_lock      = threading.Lock()
    _action_items_lock = threading.Lock()

    def __init__(self, project_name: str, db_type: str, host: str, port: int) -> None:
        self.project_name  = project_name
        self.root          = Path(project_name).resolve()
        self.db_type       = db_type
        self.host          = host
        self.port          = port
        self.findings_json  = self.root / "findings.json"
        self.findings_csv   = self.root / "findings.csv"
        self.summary_json   = self.root / "summary.json"
        self.schema_json    = self.root / "db_schema.json"
        self.checkpoint_json = self.root / "checkpoint.json"
        self.log_file       = self.root / "scan.log"
        self.error_log      = self.root / "errors.log"
        self._seen_keys: set = set()
        self._action_items: list = []
        self._ai_seen: set = set()
        self._fdb = None
        _db_path = os.environ.get("PR0T31N_FINDINGS_DB")
        if _db_path:
            try:
                import sys as _s
                if "/opt/pr0t31n/shared" not in _s.path:
                    _s.path.insert(0, "/opt/pr0t31n/shared")
                import pr0t31n_findings_db
                self._fdb = pr0t31n_findings_db.FindingsDB(_db_path)
            except Exception:
                self._fdb = None
        self._setup()

    def _setup(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.findings_json.exists():
            self.findings_json.write_text("[]", encoding="utf-8")
        else:
            try:
                existing = json.loads(self.findings_json.read_text(encoding="utf-8"))
                for ex in (existing if isinstance(existing, list) else []):
                    k = (ex.get("title", "").strip().lower(),
                         ex.get("ip", ""), ex.get("port", 0))
                    self._seen_keys.add(k)
            except Exception:
                pass
        if not self.findings_csv.exists():
            self._write_csv_header()
        if not self.log_file.exists():
            self.log_file.write_text(
                f"{'='*70}\n  auger.py — Scan Log\n"
                f"  Project : {self.project_name}\n"
                f"  Created : {self._ts()}\n"
                f"{'='*70}\n\n", encoding="utf-8")
        if not self.error_log.exists():
            self.error_log.write_text(
                f"{'='*70}\n  auger.py — Error Log\n"
                f"  Project : {self.project_name}\n"
                f"  Created : {self._ts()}\n"
                f"{'='*70}\n\n", encoding="utf-8")
        # Action items
        self._ai_path = self.root / "action_items.json"
        if not self._ai_path.exists():
            self._ai_path.write_text("[]", encoding="utf-8")

    def _write_csv_header(self) -> None:
        with self.findings_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FINDINGS_CSV_FIELDS, extrasaction="ignore")
            w.writeheader()

    def _ts(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def log_step(self, msg: str) -> None:
        with self._log_lock:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(f"[{self._ts()}] {msg}\n")

    def log_error(self, tool: str, detail: str) -> None:
        with self._log_lock:
            with self.error_log.open("a", encoding="utf-8") as f:
                f.write(f"[{self._ts()}] TOOL={tool}\n  {detail}\n\n")

    def add_finding(self, title: str, risk: str, description: str,
                    phase: str = "", output: str = "", cves: str = "",
                    sources: str = "auger", remediation: str = "",
                    owasp: str = "", owasp_asvs: str = "", iso_27001: str = "",
                    pci_dss: str = "", hipaa: str = "", nist: str = "",
                    catalogue_id: str = "", command: str = "",
                    validation_required: bool = False,
                    validation_notes: str = "",
                    db_version: str = "") -> None:
        ts = self._ts()
        # Enrich from catalogue
        cat = _CATALOGUE.get(catalogue_id, {})
        if not risk and cat:        risk        = cat.get("risk", "")
        if not owasp and cat:       owasp       = cat.get("owasp", "")
        if not owasp_asvs and cat:  owasp_asvs  = cat.get("owasp_asvs", "")
        if not iso_27001 and cat:   iso_27001   = cat.get("iso_27001", "")
        if not pci_dss and cat:     pci_dss     = cat.get("pci_dss", "")
        if not hipaa and cat:       hipaa       = cat.get("hipaa", "")
        if not nist and cat:        nist        = cat.get("nist", "")
        if not remediation and cat: remediation = cat.get("remediation", "")
        if not cves and cat:        cves        = ",".join(cat.get("cves", []))
        if not validation_required and cat: validation_required = cat.get("validation_required", False)
        if not validation_notes and cat:    validation_notes    = cat.get("validation_notes", "")
        owasp_url = _OWASP_URLS.get(owasp, "")
        entry = {
            "title":              title,
            "datetime":           ts,
            "ip":                 self.host,
            "port":               self.port,
            "hostname":           self.host,
            "risk":               risk.upper(),
            "command":            command,
            "description":        description,
            "output":             output[:4096] if output else "",
            "cves":               cves,
            "sources":            sources,
            "service":            self.db_type,
            "output_file":        "",
            "affected":           f"{self.host}:{self.port}",
            "exploitdb":          False,
            "metasploit":         False,
            "exploit_details":    [],
            "owasp":              owasp,
            "owasp_url":          owasp_url,
            "owasp_asvs":         owasp_asvs,
            # v1.1 compliance lists — wrap scalars as single-element lists.
            # iso_27001 / pci_dss_4 / nist_800_53 are list-valued per v1.1
            # spec so multiple controls per finding are representable.
            "iso_27001":          [iso_27001] if iso_27001 else [],
            "pci_dss_4":          [pci_dss] if pci_dss else [],
            "nist_800_53":        [nist] if nist else [],
            # Legacy scalar HIPAA stays as a string (no v1.1 list form yet)
            "hipaa":              hipaa,
            # Keep scalar 'nist' for backward compat with consumers expecting it
            "nist":               nist,
            "remediation":        remediation,
            "db_type":            self.db_type,
            "db_version":         db_version,
            "phase":              phase,
            "validation_required": validation_required,
            "validation_notes":   validation_notes,
            "catalogue_id":       catalogue_id,
            # v1.1 confidence derives from Auger's validation_required flag
            "confidence":         "Tentative" if validation_required else "Firm",
        }
        with self._findings_lock:
            key = (title.strip().lower(), self.host, self.port)
            if key in self._seen_keys:
                return
            self._seen_keys.add(key)
            # §13b/§14i: persist the query result as an output file and a query
            # transcript .log, then point the finding's output_file at both
            # (run-dir-relative). Auger uses DB client libraries (no subprocess),
            # so this is the DB-query analogue of the §14 tool .log.
            if output or command:
                try:
                    _safe = re.sub(r'[^\w.-]', '_', title)[:60] or "finding"
                    _stamp = re.sub(r'[^0-9]', '', ts)[:14] or "ts"
                    _evdir = self.root / "evidence" / (re.sub(r'[^\w.-]', '_', str(self.db_type or "db")))
                    _evdir.mkdir(parents=True, exist_ok=True)
                    _res = _evdir / f"{_safe}_{_stamp}_result.txt"
                    _res.write_text(output or "(no result rows)", encoding="utf-8")
                    _log = _evdir / f"{_safe}_{_stamp}.log"
                    _log.write_text(
                        f"# Auger DB query evidence\n"
                        f"# target:   {self.host}:{self.port} ({self.db_type})\n"
                        f"# finding:  {title}\n"
                        f"# risk:     {risk.upper()}\n"
                        f"# datetime: {ts}\n"
                        f"# query:\n{command or '(n/a)'}\n"
                        f"# result_file: {_res.name}\n",
                        encoding="utf-8")
                    entry["output_file"] = ",".join(
                        str(p.relative_to(self.root)) for p in (_res, _log))
                except Exception:
                    pass
            try:
                existing = json.loads(self.findings_json.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []
            existing.append(entry)
            self.findings_json.write_text(json.dumps(existing, indent=2, ensure_ascii=False),
                                           encoding="utf-8")
            if self._fdb:
                try:
                    self._fdb.insert_finding(entry)
                except Exception:
                    pass
            try:
                with self.findings_csv.open("a", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=FINDINGS_CSV_FIELDS, extrasaction="ignore")
                    w.writerow(entry)
            except Exception:
                pass
        if _CRUCIBLE_MANAGED:
            try:
                print(_CP_FINDING + json.dumps({
                    "title": title, "ip": self.host, "port": self.port,
                    "hostname": self.host, "risk": risk.upper(),
                    "description": description or "",
                    "sources": sources or "", "service": self.db_type or "",
                    "affected": f"{self.host}:{self.port}",
                    "cves": cves or "", "remediation": remediation or "",
                    "catalogue_id": catalogue_id or "",
                }, ensure_ascii=False), flush=True)
            except Exception:
                pass
        _console.log(
            f"  [{risk.upper()}] {title}{'  [needs-validation]' if validation_required else ''}",
            "SUCCESS" if risk in ("CRITICAL", "HIGH") else "WARNING"
        )

    def log_action_item(self, *, type: str, recommended_tool: str,
                        target: str, ip: str, port: int, title: str,
                        description: str, hostname: str = "",
                        source_finding: str = "", priority: str = "MEDIUM",
                        scope: str = "database", metadata: dict = None):
        import uuid as _uuid
        key = (recommended_tool.lower(), target.lower(), title.strip().lower())
        with self._action_items_lock:
            if key in self._ai_seen:
                return
            self._ai_seen.add(key)
            entry = {
                "id":               str(_uuid.uuid4()),
                "type":             type,
                "recommended_tool": recommended_tool,
                "target":           target,
                "ip":               ip,
                "port":             port,
                "hostname":         hostname or ip,
                "title":            title,
                "description":      description,
                "source_finding":   source_finding,
                "priority":         priority.upper(),
                "scope":            scope,
                "status":           "pending",
                "datetime":         self._ts(),
                "metadata":         metadata or {},
            }
            _console.action_item(entry)
            self._action_items.append(entry)
            try:
                tmp = self._ai_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self._action_items, indent=2, ensure_ascii=False),
                               encoding="utf-8")
                os.replace(str(tmp), str(self._ai_path))
            except Exception:
                pass

    def write_summary(self, db_version: str, db_type: str,
                      auth_success: bool, phases_run: list) -> None:
        try:
            findings = json.loads(self.findings_json.read_text(encoding="utf-8"))
        except Exception:
            findings = []
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            r = f.get("risk", "INFO").upper()
            risk_counts[r] = risk_counts.get(r, 0) + 1
        summary = {
            "tool": "auger",
            "version": VERSION,
            "db_type": db_type,
            "db_version": db_version,
            "target": f"{self.host}:{self.port}",
            "auth_success": auth_success,
            "phases_run": phases_run,
            "total_findings": len(findings),
            "risk_counts": risk_counts,
            "completed_at": self._ts(),
        }
        self.summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    def write_schema(self, schema: dict) -> None:
        self.schema_json.write_text(json.dumps(schema, indent=2, ensure_ascii=False),
                                    encoding="utf-8")

    def write_checkpoint(self, db_version: str, db_type: str,
                         completed_phases: list, auth_success: bool) -> None:
        cp = {
            "version": VERSION,
            "host": self.host,
            "port": self.port,
            "db_type": db_type,
            "completed_phases": completed_phases,
            "db_version": db_version,
            "auth_success": auth_success,
            "generated_at": self._ts(),
        }
        self.checkpoint_json.write_text(json.dumps(cp, indent=2), encoding="utf-8")

    def load_checkpoint(self) -> dict:
        if not self.checkpoint_json.exists():
            return {}
        try:
            return json.loads(self.checkpoint_json.read_text(encoding="utf-8"))
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Network / TLS helpers
# ---------------------------------------------------------------------------
def _tcp_open(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _tls_info(host: str, port: int, timeout: float = 8.0) -> dict:
    """Return TLS information for the given host:port without sending DB handshake."""
    result = {"tls_ok": False, "version": None, "cipher": None,
              "cert_subject": None, "cert_issuer": None, "cert_expired": False,
              "self_signed": False, "weak_version": False, "weak_cipher": False,
              "error": ""}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                ver    = s.version()
                cipher = s.cipher()
                cert   = s.getpeercert()
                result["tls_ok"]     = True
                result["version"]    = ver
                result["cipher"]     = cipher[0] if cipher else ""
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    issu = dict(x[0] for x in cert.get("issuer", []))
                    result["cert_subject"] = subj.get("commonName", "")
                    result["cert_issuer"]  = issu.get("commonName", "")
                    result["self_signed"]  = (subj == issu)
                    exp = cert.get("notAfter", "")
                    if exp:
                        import email.utils
                        import calendar
                        result["cert_expired"] = (
                            calendar.timegm(email.utils.parsedate(exp)) < time.time()
                        )
                result["weak_version"] = ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
                cn = (cipher[0] or "").upper() if cipher else ""
                result["weak_cipher"]  = any(w in cn for w in
                    ("RC4", "DES", "EXP", "NULL", "ANON", "3DES", "ADH", "AECDH"))
    except ssl.SSLError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


def _grab_banner(host: str, port: int, probe: bytes = b"", timeout: float = 4.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if probe:
                s.sendall(probe)
            s.settimeout(2.0)
            data = b""
            for _ in range(10):
                try:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
            return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# JDBC connection string parser
# ---------------------------------------------------------------------------
def _parse_jdbc(jdbc: str) -> dict:
    """
    Parse JDBC URL into {db_type, host, port, database, params}.
    Handles: jdbc:mysql, jdbc:postgresql, jdbc:sqlserver, jdbc:oracle:thin,
             jdbc:mongodb, jdbc:redshift
    """
    result = {"db_type": "", "host": "", "port": 0, "database": "", "params": {}}
    if not jdbc or not jdbc.startswith("jdbc:"):
        return result
    rest = jdbc[5:]
    m = re.match(r'^([a-z]+):(?:thin:)?(?://)?([^:/;?]+)(?::(\d+))?[/;:]?([^?;]*)',
                 rest, re.IGNORECASE)
    if not m:
        return result
    db_type = m.group(1).lower()
    if "sqlserver" in db_type or "mssql" in db_type or "jtds" in db_type:
        db_type = "mssql"
    elif "oracle" in db_type:
        db_type = "oracle"
    elif "postgresql" in db_type or "redshift" in db_type:
        db_type = "postgresql" if "postgresql" in db_type else "redshift"
    result["db_type"]   = db_type
    result["host"]      = m.group(2) or ""
    result["port"]      = int(m.group(3)) if m.group(3) else _default_port(db_type)
    result["database"]  = (m.group(4) or "").lstrip("/")
    qs = rest.split("?", 1)
    if len(qs) > 1:
        for kv in qs[1].split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                result["params"][k] = v
    return result


def _default_port(db_type: str) -> int:
    _ports = {
        "mysql": 3306, "mariadb": 3306, "postgresql": 5432, "postgres": 5432,
        "mssql": 1433, "oracle": 1521, "mongodb": 27017, "redis": 6379,
        "cassandra": 9042, "elasticsearch": 9200, "couchdb": 5984,
        "influxdb": 8086, "neo4j": 7474, "memcached": 11211,
        "redshift": 5439, "dynamodb": 8000,
    }
    return _ports.get(db_type, 0)


# ---------------------------------------------------------------------------
# Database connector helpers  (optional imports)
# ---------------------------------------------------------------------------
def _try_import(module: str, package: str = ""):
    try:
        import importlib
        return importlib.import_module(module)
    except ImportError:
        pkg = package or module
        _console.log(f"Optional dependency '{pkg}' not installed — some checks skipped", "WARNING")
        return None


# ---------------------------------------------------------------------------
# MySQL / MariaDB Auditor
# ---------------------------------------------------------------------------
class MySQLAuditor:
    def __init__(self, host, port, username, password, database, out: AugerOutput,
                 ssl_enabled=False, timeout=10):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.database = database or "information_schema"
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._conn    = None
        self._version = ""

    def connect(self) -> bool:
        pymysql = _try_import("pymysql")
        if not pymysql:
            return False
        try:
            ssl_cfg = {"ssl_disabled": not self.ssl_en}
            self._conn = pymysql.connect(
                host=self.host, port=self.port,
                user=self.username, password=self.password,
                database=self.database, connect_timeout=self.timeout,
                **ssl_cfg
            )
            return True
        except Exception as e:
            _console.log(f"MySQL connect failed: {e}", "ERROR")
            return False

    def _q(self, sql: str, args=None) -> list:
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, args or ())
                return cur.fetchall()
        except Exception as e:
            self.out.log_error("mysql-query", str(e))
            return []

    def _q1(self, sql: str, args=None):
        rows = self._q(sql, args)
        return rows[0] if rows else None

    def _var(self, name: str) -> str:
        row = self._q1("SHOW VARIABLES LIKE %s", (name,))
        return (row[1] if row else "").strip().lower()

    def check_version(self) -> str:
        row = self._q1("SELECT VERSION()")
        if not row:
            return ""
        ver = str(row[0])
        self._version = ver
        self.out.log_step(f"MySQL version: {ver}")
        # Determine if MariaDB
        db_type = "mariadb" if "mariadb" in ver.lower() else "mysql"
        major_minor = ".".join(ver.split(".")[:2])
        eol = _EOL_VERSIONS.get(db_type, {}).get(major_minor, False)
        if eol:
            self.out.add_finding(
                title=f"EOL Software: End-of-Life MySQL/MariaDB Version: {ver}",
                risk="CRITICAL", phase="version", catalogue_id="DB-009",
                description=f"The database is running version {ver} which is past end-of-life.",
                output=f"VERSION(): {ver}", db_version=ver,
                command="SELECT VERSION()"
            )
            self.out.log_action_item(
                type="vulnerability",
                recommended_tool="ExploitDB",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title=f"Exploit Verification — EOL MySQL/MariaDB {ver}",
                description=f"End-of-life database version {ver} — search ExploitDB for known exploits targeting this release.",
                source_finding=f"End-of-Life MySQL/MariaDB Version: {ver}",
                priority="CRITICAL",
                metadata={"db_type": db_type, "db_version": ver}
            )
        # CVE check — 2026-06-11 review: was using bare startswith() which
        # over-matched patched mid-minor releases. Now compares against
        # cve["fixed_in"] if catalogue entry has it (semantic version compare),
        # otherwise falls back to startswith with confidence:Tentative.
        for cve in _KNOWN_CVES.get(db_type, []):
            _matched = any(ver.startswith(v) for v in cve["versions"])
            if not _matched:
                continue
            _fixed_in = cve.get("fixed_in")
            _confidence = "Certain"
            if _fixed_in:
                try:
                    def _vt(v: str): return tuple(int(x) for x in v.split(".")[:4] if x.isdigit())
                    if _vt(ver) >= _vt(_fixed_in):
                        # Patched — skip emission.
                        continue
                except Exception:
                    _confidence = "Tentative"  # parse failure; report but mark
            else:
                # No fixed_in available — emit but flag as Tentative since
                # mid-minor patches may already include the fix.
                _confidence = "Tentative"
            # Risk derived from CVSS if available, falling back to HIGH.
            _cvss = float(cve.get("cvss", 0.0) or 0.0)
            if   _cvss >= 9.0: _risk = "CRITICAL"
            elif _cvss >= 7.0: _risk = "HIGH"
            elif _cvss >= 4.0: _risk = "MEDIUM"
            elif _cvss >  0.0: _risk = "LOW"
            else:              _risk = "HIGH"
            self.out.add_finding(
                title=f"Known CVE in MySQL Version: {cve['cve']}",
                risk=_risk, phase="version", catalogue_id="DB-010",
                description=cve["desc"] + (
                    f" Confidence: {_confidence} (no fixed_in in catalogue; "
                    "verify against vendor advisory)." if _confidence == "Tentative" else ""),
                output=f"Version: {ver}  CVE: {cve['cve']}  CVSS: {cve['cvss']}  Confidence: {_confidence}",
                cves=cve["cve"], db_version=ver,
                command="SELECT VERSION()"
            )
            self.out.log_action_item(
                type="exploit",
                recommended_tool="ExploitDB" if "exploit" in cve.get("desc", "").lower() else "Metasploit",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title=f"Exploit Verification — {cve['cve']}",
                description=f"Known CVE {cve['cve']} (CVSS {cve.get('cvss', 'N/A')}) affects MySQL {ver}. Verify exploitability.",
                source_finding=f"Known CVE in MySQL Version: {cve['cve']}",
                priority="HIGH",
                metadata={"cve": cve["cve"], "cvss": cve.get("cvss"), "db_version": ver}
            )
        return ver

    def check_anonymous_users(self):
        rows = self._q("SELECT user, host FROM mysql.user WHERE user=''")
        if rows:
            self.out.add_finding(
                title="Database: MySQL Anonymous User Account Present",
                risk="HIGH", phase="accounts", catalogue_id="DB-100",
                description="Anonymous (blank username) accounts exist allowing unauthenticated access.",
                output=str(rows),
                command="SELECT user, host FROM mysql.user WHERE user=''",
                db_version=self._version
            )

    def check_test_database(self):
        rows = self._q("SHOW DATABASES LIKE 'test'")
        if rows:
            self.out.add_finding(
                title="Database: MySQL Test Database Present and Accessible",
                risk="MEDIUM", phase="config", catalogue_id="DB-101",
                description="The default 'test' database is present and accessible.",
                output="Database 'test' exists",
                command="SHOW DATABASES LIKE 'test'",
                db_version=self._version
            )

    def check_local_infile(self):
        val = self._var("local_infile")
        if val in ("on", "1", "yes"):
            self.out.add_finding(
                title="Database: MySQL LOCAL INFILE Enabled",
                risk="HIGH", phase="config", catalogue_id="DB-102",
                description="local_infile=ON allows reading client-side files.",
                output=f"local_infile = {val}",
                command="SHOW VARIABLES LIKE 'local_infile'",
                db_version=self._version
            )

    def check_secure_file_priv(self):
        val = self._var("secure_file_priv")
        if val == "" or val == "null":
            risk = "HIGH" if val == "" else "INFO"
            self.out.add_finding(
                title="Database: MySQL secure_file_priv Not Configured",
                risk=risk, phase="config", catalogue_id="DB-103",
                description="secure_file_priv is empty — file read/write operations are unrestricted.",
                output=f"secure_file_priv = '{val}'",
                command="SHOW VARIABLES LIKE 'secure_file_priv'",
                db_version=self._version
            )

    def check_root_remote(self):
        rows = self._q(
            "SELECT user, host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')"
        )
        if rows:
            self.out.add_finding(
                title="Database: MySQL Root Account Accessible Remotely",
                risk="CRITICAL", phase="accounts", catalogue_id="DB-104",
                description="Root account has remote host entries allowing external connections.",
                output=str(rows),
                command="SELECT user,host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')",
                db_version=self._version
            )
            self.out.log_action_item(
                type="vulnerability",
                recommended_tool="Manual Verification",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title="Manual Verification Required — MySQL Root Remote Access",
                description="Root account has remote host entries. Verify whether remote root access is intentional and test for weak credentials.",
                source_finding="Database: MySQL Root Account Accessible Remotely",
                priority="CRITICAL",
                metadata={"db_type": self.out.db_type}
            )

    def check_wildcard_hosts(self):
        rows = self._q(
            "SELECT user, host FROM mysql.user WHERE host='%' AND user!='' ORDER BY user"
        )
        if rows:
            self.out.add_finding(
                title="Database: MySQL User Account with Wildcard Host (%)",
                risk="HIGH", phase="accounts", catalogue_id="DB-105",
                description=f"Accounts with wildcard hosts: {[r[0] for r in rows]}",
                output=str(rows),
                command="SELECT user,host FROM mysql.user WHERE host='%'",
                db_version=self._version
            )

    def check_password_policy(self):
        # Try component first (MySQL 8.0+), then plugin (5.7)
        row = self._q1(
            "SELECT variable_value FROM performance_schema.global_variables "
            "WHERE variable_name='validate_password.policy'"
        )
        if not row:
            row = self._q1("SHOW VARIABLES LIKE 'validate_password_policy'")
            val = row[1] if row else None
        else:
            val = row[0]
        if val is None:
            self.out.add_finding(
                title="Database: MySQL Password Validation Plugin Not Installed",
                risk="HIGH", phase="config", catalogue_id="DB-106",
                description="No password validation plugin/component found.",
                output="validate_password not installed",
                command="SHOW VARIABLES LIKE 'validate_password%'",
                db_version=self._version
            )
        elif str(val).upper() in ("LOW", "0"):
            self.out.add_finding(
                title="Database: MySQL Password Validation Policy Set to LOW",
                risk="MEDIUM", phase="config",
                description="validate_password.policy=LOW only checks length, not complexity.",
                output=f"validate_password.policy = {val}",
                command="SHOW VARIABLES LIKE 'validate_password.policy'",
                owasp="A07:2021", owasp_asvs="V2.1.2", nist="IA-5",
                pci_dss="8.3.6", db_version=self._version
            )

    def check_general_log(self):
        val = self._var("general_log")
        if val in ("on", "1"):
            path = self._var("general_log_file")
            self.out.add_finding(
                title="Database: MySQL General Query Log Enabled",
                risk="LOW", phase="logging", catalogue_id="DB-107",
                description=f"General log is ON — queries (including passwords in plain-text) are logged to {path}.",
                output=f"general_log=ON  general_log_file={path}",
                command="SHOW VARIABLES LIKE 'general_log%'",
                db_version=self._version
            )

    def check_ssl_config(self):
        ssl_val = self._var("have_ssl")
        tls_req = self._var("require_secure_transport")
        if ssl_val != "yes":
            self.out.add_finding(
                title="Database: Cleartext Database Protocol (No TLS/SSL)",
                risk="HIGH", phase="network", catalogue_id="DB-001",
                description="MySQL SSL/TLS is not enabled.",
                output=f"have_ssl = {ssl_val}",
                command="SHOW VARIABLES LIKE 'have_ssl'",
                db_version=self._version
            )
        elif tls_req not in ("on", "1"):
            self.out.add_finding(
                title="Database: MySQL TLS Not Required (Optional Only)",
                risk="MEDIUM", phase="network",
                description="SSL is available but require_secure_transport=OFF — clients can connect without TLS.",
                output=f"have_ssl={ssl_val}  require_secure_transport={tls_req}",
                command="SHOW VARIABLES LIKE 'require_secure_transport'",
                owasp="A02:2021", owasp_asvs="V9.1.1", nist="SC-8",
                pci_dss="4.2.1", hipaa="164.312(e)(1)", db_version=self._version
            )

    def check_encryption_at_rest(self):
        """2026-06-11 review: MySQL encryption-at-rest visibility.

        Three checks:
          1. innodb_redo_log_encrypt + innodb_undo_log_encrypt
          2. binlog_encryption
          3. Keyring plugin presence (any of: keyring_file, keyring_okv,
             keyring_aws, keyring_hashicorp, keyring_oci, MySQL Enterprise
             Transparent Data Encryption (TDE))
        """
        # Three relevant variables
        innodb_redo = self._var("innodb_redo_log_encrypt") or "OFF"
        innodb_undo = self._var("innodb_undo_log_encrypt") or "OFF"
        binlog_enc  = self._var("binlog_encryption") or "OFF"
        # Keyring plugins
        try:
            plugins = self._q("SELECT plugin_name, plugin_status FROM information_schema.plugins "
                               "WHERE plugin_name LIKE 'keyring%%' OR plugin_name LIKE '%%tde%%'")
        except Exception:
            plugins = []
        active_keyring = [p for p in plugins
                            if str(p.get("plugin_status","")).upper() == "ACTIVE"]
        if not active_keyring:
            self.out.add_finding(
                title="MySQL Encryption-at-Rest: NO keyring plugin loaded",
                risk="HIGH", phase="encryption", catalogue_id="DB-019",
                description=("No keyring_file / keyring_okv / keyring_aws / keyring_hashicorp "
                              "/ keyring_oci or TDE plugin is ACTIVE. InnoDB tablespace "
                              "encryption requires a keyring plugin; without one, "
                              "encryption-at-rest cannot be enabled."),
                output=f"plugins: {plugins}",
                command="SELECT plugin_name FROM information_schema.plugins WHERE plugin_name LIKE 'keyring%'",
                owasp="A02:2021", nist="SC-28", pci_dss="3.4.1",
                db_version=self._version)
        if str(innodb_redo).upper() != "ON":
            self.out.add_finding(
                title="MySQL InnoDB Redo Log NOT Encrypted",
                risk="MEDIUM", phase="encryption", catalogue_id="DB-019-A",
                description="innodb_redo_log_encrypt=OFF — redo logs contain decrypted page data "
                            "and are not encrypted at rest.",
                output=f"innodb_redo_log_encrypt = {innodb_redo}",
                command="SHOW VARIABLES LIKE 'innodb_redo_log_encrypt'",
                db_version=self._version)
        if str(innodb_undo).upper() != "ON":
            self.out.add_finding(
                title="MySQL InnoDB Undo Log NOT Encrypted",
                risk="MEDIUM", phase="encryption", catalogue_id="DB-019-B",
                description="innodb_undo_log_encrypt=OFF — undo logs are not encrypted at rest.",
                output=f"innodb_undo_log_encrypt = {innodb_undo}",
                command="SHOW VARIABLES LIKE 'innodb_undo_log_encrypt'",
                db_version=self._version)
        if str(binlog_enc).upper() != "ON":
            self.out.add_finding(
                title="MySQL Binary Log NOT Encrypted",
                risk="MEDIUM", phase="encryption", catalogue_id="DB-019-C",
                description="binlog_encryption=OFF — binary logs (and relay logs) are unencrypted.",
                output=f"binlog_encryption = {binlog_enc}",
                command="SHOW VARIABLES LIKE 'binlog_encryption'",
                db_version=self._version)

    def check_audit_log_plugin(self):
        """2026-06-11 review: MySQL Enterprise audit_log plugin or MariaDB
        server_audit plugin presence. general_log is NOT a substitute —
        it's transactional, not security-event oriented.
        """
        try:
            plugins = self._q("SELECT plugin_name, plugin_status FROM information_schema.plugins "
                               "WHERE plugin_name IN ('audit_log','server_audit','keyring_audit')")
        except Exception:
            plugins = []
        active = [p for p in plugins
                    if str(p.get("plugin_status","")).upper() == "ACTIVE"]
        if not active:
            self.out.add_finding(
                title="MySQL Security Audit Log NOT Enabled",
                risk="MEDIUM", phase="logging", catalogue_id="DB-018",
                description=("Neither MySQL Enterprise audit_log nor MariaDB server_audit "
                              "plugin is ACTIVE. general_log is transactional and not "
                              "an adequate substitute. Compliance frameworks (PCI DSS 10.x, "
                              "HIPAA 164.312(b)) require security-event audit logging."),
                output=f"plugins: {plugins}",
                command="SELECT plugin_name FROM information_schema.plugins WHERE plugin_name IN ('audit_log','server_audit')",
                owasp="A09:2021", nist="AU-2", pci_dss="10.2.1", hipaa="164.312(b)",
                db_version=self._version)

    def check_symlinks(self):
        val = self._var("have_symlink")
        if val == "yes":
            self.out.add_finding(
                title="Database: MySQL Symlink Support Enabled",
                risk="MEDIUM", phase="config", catalogue_id="DB-108",
                description="have_symlink=YES — MySQL follows symlinks to table files.",
                output=f"have_symlink = {val}",
                command="SHOW VARIABLES LIKE 'have_symlink'",
                db_version=self._version
            )

    def check_bind_address(self):
        val = self._var("bind_address")
        if val in ("0.0.0.0", "::", "*", ""):
            self.out.add_finding(
                title="Database: Database Listening on All Network Interfaces (0.0.0.0)",
                risk="HIGH", phase="config", catalogue_id="DB-004",
                description=f"MySQL bind_address={val!r} — listening on all interfaces.",
                output=f"bind_address = {val}",
                command="SHOW VARIABLES LIKE 'bind_address'",
                db_version=self._version
            )

    def check_user_privileges(self):
        rows = self._q(
            "SELECT user, host, Super_priv, File_priv, Process_priv, "
            "Shutdown_priv, Reload_priv, Grant_priv "
            "FROM mysql.user WHERE user!='' AND "
            "(Super_priv='Y' OR File_priv='Y') ORDER BY user"
        )
        for row in rows:
            user, host = row[0], row[1]
            super_p = row[2] == "Y"
            file_p  = row[3] == "Y"
            privs   = []
            if super_p: privs.append("SUPER")
            if file_p:  privs.append("FILE")
            if privs and user.lower() not in ("root",):
                self.out.add_finding(
                    title=f"Database: MySQL Overprivileged Account '{user}'@'{host}'",
                    risk="HIGH", phase="permissions", catalogue_id="DB-011",
                    description=f"Account '{user}'@'{host}' has dangerous privileges: {', '.join(privs)}",
                    output=f"user={user} host={host} privileges={privs}",
                    command="SELECT user,host,Super_priv,File_priv FROM mysql.user",
                    db_version=self._version
                )

    def check_sql_mode(self):
        val = self._var("sql_mode")
        missing = []
        for required in ("STRICT_TRANS_TABLES", "NO_BACKSLASH_ESCAPES"):
            if required not in val.upper():
                missing.append(required)
        if missing:
            self.out.add_finding(
                title="Database: MySQL sql_mode Too Permissive",
                risk="LOW", phase="config", catalogue_id="DB-110",
                description=f"sql_mode is missing recommended values: {missing}",
                output=f"sql_mode = {val}",
                command="SHOW VARIABLES LIKE 'sql_mode'",
                db_version=self._version
            )

    def check_error_log(self):
        val = self._var("log_error")
        if val in ("", "off", "0"):
            self.out.add_finding(
                title="Database: Audit Logging Disabled",
                risk="HIGH", phase="logging", catalogue_id="DB-005",
                description="MySQL error logging is disabled.",
                output=f"log_error = {val!r}",
                command="SHOW VARIABLES LIKE 'log_error'",
                db_version=self._version
            )

    def check_default_creds(self):
        """Try well-known default credentials as a verification check."""
        pymysql = _try_import("pymysql")
        if not pymysql:
            return
        for user, pwd in _DEFAULT_CREDS["mysql"]:
            if user == self.username and pwd == self.password:
                continue
            try:
                # connect_timeout derived from --timeout per 2026-06-11 review.
                # The hard-coded 4s was timing out legitimate slow DBs before
                # the user-supplied --timeout fired. New formula: max(4, half
                # the user value) keeps credential probes responsive AND honours
                # explicit --timeout escalation for high-latency targets.
                _ct = max(4, self.timeout // 2)
                c = pymysql.connect(host=self.host, port=self.port,
                                    user=user, password=pwd,
                                    connect_timeout=_ct, ssl={"ssl_disabled": True})
                c.close()
                self.out.add_finding(
                    title="Default Credentials in Use",
                    risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                    description=f"Successfully authenticated with default credentials: {user}/{pwd!r}",
                    output=f"user={user} password={'(empty)' if pwd=='' else '***'}",
                    command=f"mysql -h {self.host} -P {self.port} -u {user} -p{pwd}",
                    db_version=self._version
                )
                self.out.log_action_item(
                    type="vulnerability",
                    recommended_tool="Manual Verification",
                    target=f"{self.out.host}:{self.out.port}",
                    ip=self.out.host, port=self.out.port,
                    title=f"Manual Verification Required — Default Credentials ({self.out.db_type})",
                    description=f"Default credentials confirmed on {self.out.db_type}. Assess data access and lateral movement potential.",
                    source_finding="Default Credentials in Use",
                    priority="CRITICAL",
                    metadata={"db_type": self.out.db_type, "user": user}
                )
                break
            except Exception:
                pass

    def run(self, db_version: str) -> list:
        phases = _run_checks("MySQL", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_default_creds, "auth"),
            (self.check_anonymous_users, "accounts"),
            (self.check_test_database, "config"),
            (self.check_local_infile, "config"),
            (self.check_secure_file_priv, "config"),
            (self.check_root_remote, "accounts"),
            (self.check_wildcard_hosts, "accounts"),
            (self.check_password_policy, "config"),
            (self.check_general_log, "logging"),
            (self.check_audit_log_plugin, "logging"),
            (self.check_ssl_config, "network"),
            (self.check_encryption_at_rest, "encryption"),
            (self.check_symlinks, "config"),
            (self.check_bind_address, "config"),
            (self.check_user_privileges, "permissions"),
            (self.check_sql_mode, "config"),
            (self.check_error_log, "logging"),
        ], self.out)
        return phases


# ---------------------------------------------------------------------------
# PostgreSQL Auditor
# ---------------------------------------------------------------------------
class PostgreSQLAuditor:
    def __init__(self, host, port, username, password, database, out: AugerOutput,
                 ssl_enabled=False, timeout=10):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.database = database or "postgres"
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._conn    = None
        self._version = ""

    def connect(self) -> bool:
        psycopg2 = _try_import("psycopg2")
        if not psycopg2:
            return False
        try:
            ssl_mode = "require" if self.ssl_en else "prefer"
            self._conn = psycopg2.connect(
                host=self.host, port=self.port,
                user=self.username, password=self.password,
                dbname=self.database, connect_timeout=self.timeout,
                sslmode=ssl_mode
            )
            self._conn.autocommit = True
            return True
        except Exception as e:
            _console.log(f"PostgreSQL connect failed: {e}", "ERROR")
            return False

    def _q(self, sql: str, args=None) -> list:
        try:
            import psycopg2.extras
            with self._conn.cursor() as cur:
                cur.execute(sql, args)
                return cur.fetchall()
        except Exception as e:
            self.out.log_error("pg-query", str(e))
            return []

    def _q1(self, sql, args=None):
        rows = self._q(sql, args)
        return rows[0] if rows else None

    def check_version(self) -> str:
        row = self._q1("SELECT version()")
        if not row:
            return ""
        ver_str = str(row[0])
        self._version = ver_str
        m = re.search(r'PostgreSQL\s+([\d.]+)', ver_str, re.I)
        ver_num = m.group(1) if m else ver_str
        self.out.log_step(f"PostgreSQL version: {ver_num}")
        major = ver_num.split(".")[0]
        eol = _EOL_VERSIONS.get("postgresql", {}).get(ver_num[:3], False)
        eol = eol or _EOL_VERSIONS.get("postgresql", {}).get(major, False)
        if eol:
            self.out.add_finding(
                title=f"EOL Software: End-of-Life PostgreSQL Version: {ver_num}",
                risk="CRITICAL", phase="version", catalogue_id="DB-009",
                description=f"PostgreSQL {ver_num} is end-of-life.",
                output=ver_str, db_version=ver_num,
                command="SELECT version()"
            )
        for cve in _KNOWN_CVES.get("postgresql", []):
            if any(ver_num.startswith(v) for v in cve["versions"]):
                self.out.add_finding(
                    title=f"Known CVE in PostgreSQL Version: {cve['cve']}",
                    risk="HIGH", phase="version", catalogue_id="DB-010",
                    description=cve["desc"],
                    output=f"Version: {ver_num}  CVE: {cve['cve']}  CVSS: {cve['cvss']}",
                    cves=cve["cve"], db_version=ver_num, command="SELECT version()"
                )
                self.out.log_action_item(
                    type="exploit",
                    recommended_tool="ExploitDB" if "exploit" in cve.get("desc", "").lower() else "Metasploit",
                    target=f"{self.out.host}:{self.out.port}",
                    ip=self.out.host, port=self.out.port,
                    title=f"Exploit Verification — {cve['cve']}",
                    description=f"Known CVE {cve['cve']} (CVSS {cve.get('cvss', 'N/A')}) affects PostgreSQL {ver_num}. Verify exploitability.",
                    source_finding=f"Known CVE in PostgreSQL Version: {cve['cve']}",
                    priority="HIGH",
                    metadata={"cve": cve["cve"], "cvss": cve.get("cvss"), "db_version": ver_num}
                )
        return ver_num

    def _setting(self, name: str) -> str:
        row = self._q1("SELECT current_setting(%s)", (name,))
        return str(row[0]).strip().lower() if row else ""

    def check_ssl(self):
        val = self._setting("ssl")
        if val == "off":
            self.out.add_finding(
                title="Database: Cleartext Database Protocol (No TLS/SSL)",
                risk="HIGH", phase="network", catalogue_id="DB-001",
                description="PostgreSQL ssl=off — all connections are unencrypted.",
                output="ssl = off", command="SHOW ssl",
                db_version=self._version
            )

    def check_password_encryption(self):
        val = self._setting("password_encryption")
        if "md5" in val:
            self.out.add_finding(
                title="Database: PostgreSQL Weak Password Encryption (MD5)",
                risk="MEDIUM", phase="config", catalogue_id="DB-154",
                description="password_encryption=md5 — use scram-sha-256 instead.",
                output=f"password_encryption = {val}",
                command="SHOW password_encryption",
                db_version=self._version
            )

    def check_superusers(self):
        rows = self._q("SELECT usename, usesuper, usecreatedb FROM pg_user WHERE usesuper=true")
        if rows:
            users = [r[0] for r in rows]
            if len(users) > 1 or (users and users[0] not in ("postgres",)):
                self.out.add_finding(
                    title="Database: PostgreSQL Superuser Account Accessible Remotely",
                    risk="HIGH", phase="accounts", catalogue_id="DB-151",
                    description=f"Superuser accounts: {users}. Verify remote access is restricted in pg_hba.conf.",
                    output=f"Superusers: {users}",
                    command="SELECT usename FROM pg_user WHERE usesuper=true",
                    validation_required=True,
                    validation_notes="Check pg_hba.conf: grep superuser /etc/postgresql/*/main/pg_hba.conf",
                    db_version=self._version
                )
                self.out.log_action_item(
                    type="vulnerability",
                    recommended_tool="Manual Verification",
                    target=f"{self.out.host}:{self.out.port}",
                    ip=self.out.host, port=self.out.port,
                    title="Manual Verification Required — PostgreSQL Superuser Remote Access",
                    description="Check pg_hba.conf: grep superuser /etc/postgresql/*/main/pg_hba.conf",
                    source_finding="Database: PostgreSQL Superuser Account Accessible Remotely",
                    priority="HIGH",
                    metadata={"validation_notes": "Check pg_hba.conf: grep superuser /etc/postgresql/*/main/pg_hba.conf",
                              "db_type": self.out.db_type}
                )

    def check_public_schema_perms(self):
        rows = self._q(
            "SELECT has_schema_privilege('public', 'public', 'CREATE')"
        )
        if rows and rows[0][0]:
            self.out.add_finding(
                title="Database: PostgreSQL Excessive Permissions on Public Schema",
                risk="MEDIUM", phase="permissions", catalogue_id="DB-155",
                description="PUBLIC role has CREATE on public schema — CVE-2018-1058 search_path attack vector.",
                output="has_schema_privilege('public', 'public', 'CREATE') = true",
                command="SELECT has_schema_privilege('public','public','CREATE')",
                db_version=self._version
            )

    def check_row_security(self):
        rows = self._q(
            "SELECT schemaname, tablename FROM pg_tables "
            "WHERE rowsecurity = false AND schemaname NOT IN ('pg_catalog','information_schema') "
            "AND tablename ~* '(user|account|customer|patient|member|person|employee|"
            "card|payment|credit|ssn|health|record|secret|token|password|credential)'"
        )
        if rows:
            tables = [f"{r[0]}.{r[1]}" for r in rows[:10]]
            self.out.add_finding(
                title="Database: PostgreSQL Row-Level Security Not Enabled on Sensitive Tables",
                risk="HIGH", phase="permissions", catalogue_id="DB-153",
                description=f"Tables with sensitive-looking names without RLS: {tables}",
                output=str(tables),
                command="SELECT schemaname,tablename FROM pg_tables WHERE rowsecurity=false",
                db_version=self._version
            )

    def check_logging(self):
        log_conn = self._setting("log_connections")
        log_disc = self._setting("log_disconnections")
        if log_conn == "off" or log_disc == "off":
            self.out.add_finding(
                title="Database: PostgreSQL Connection Logging Disabled",
                risk="MEDIUM", phase="logging", catalogue_id="DB-156",
                description=f"log_connections={log_conn}  log_disconnections={log_disc}",
                output=f"log_connections={log_conn}, log_disconnections={log_disc}",
                command="SHOW log_connections; SHOW log_disconnections",
                db_version=self._version
            )

    def check_extensions(self):
        risky = {"dblink", "pg_read_file", "plsh", "plpython3u", "plpython2u",
                 "plperlu", "adminpack", "pg_read_server_files"}
        rows = self._q(
            "SELECT extname FROM pg_extension WHERE extname = ANY(%s)",
            (list(risky),)
        )
        if rows:
            found = [r[0] for r in rows]
            self.out.add_finding(
                title="Database: PostgreSQL Dangerous Extensions Installed",
                risk="HIGH", phase="config", catalogue_id="DB-157",
                description=f"Potentially dangerous extensions found: {found}",
                output=str(found),
                command="SELECT extname FROM pg_extension",
                db_version=self._version
            )

    def check_default_creds(self):
        psycopg2 = _try_import("psycopg2")
        if not psycopg2:
            return
        for user, pwd in _DEFAULT_CREDS["postgresql"]:
            if user == self.username and pwd == self.password:
                continue
            try:
                # See pymysql connect_timeout note (2026-06-11 review).
                _ct = max(4, self.timeout // 2)
                c = psycopg2.connect(host=self.host, port=self.port,
                                     user=user, password=pwd,
                                     dbname="postgres", connect_timeout=_ct,
                                     sslmode="prefer")
                c.close()
                self.out.add_finding(
                    title="Default Credentials in Use",
                    risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                    description=f"Authenticated with default credentials: {user}/{pwd!r}",
                    output=f"user={user}", db_version=self._version,
                    command=f"psql -h {self.host} -p {self.port} -U {user}"
                )
                break
            except Exception:
                pass

    def check_copy_program(self):
        # If we are superuser, this is accessible
        row = self._q1("SELECT usesuper FROM pg_user WHERE usename = current_user")
        if row and row[0]:
            self.out.add_finding(
                title="Database: PostgreSQL COPY TO/FROM PROGRAM Feature Accessible",
                risk="CRITICAL", phase="config", catalogue_id="DB-152",
                description="Connected user has superuser — COPY FROM PROGRAM provides OS command execution.",
                output="Current user is superuser",
                command="SELECT usesuper FROM pg_user WHERE usename=current_user",
                db_version=self._version
            )

    def check_listen_addresses(self):
        val = self._setting("listen_addresses")
        if val in ("*", "0.0.0.0"):
            self.out.add_finding(
                title="Database: Database Listening on All Network Interfaces (0.0.0.0)",
                risk="HIGH", phase="config", catalogue_id="DB-004",
                description=f"PostgreSQL listen_addresses={val!r}",
                output=f"listen_addresses = {val}",
                command="SHOW listen_addresses", db_version=self._version
            )

    def check_pgcrypto_extension(self):
        """2026-06-11 review: pgcrypto presence for column-level encryption."""
        try:
            rows = self._q("SELECT extname FROM pg_extension WHERE extname='pgcrypto'")
        except Exception:
            rows = []
        if not rows:
            self.out.add_finding(
                title="PostgreSQL pgcrypto extension NOT installed",
                risk="LOW", phase="encryption", catalogue_id="DB-PG-019",
                description=("pgcrypto provides column-level encryption + secure-random + "
                              "hashing primitives. Without it, app-level encryption must be "
                              "implemented elsewhere. Install with: "
                              "CREATE EXTENSION pgcrypto;"),
                output="pg_extension does not include pgcrypto",
                command="SELECT extname FROM pg_extension WHERE extname='pgcrypto'",
                owasp="A02:2021", nist="SC-28", db_version=self._version)

    def check_pg_audit_extension(self):
        """2026-06-11 review: pg_audit security-event audit logging."""
        try:
            rows = self._q("SELECT extname FROM pg_extension WHERE extname='pgaudit'")
        except Exception:
            rows = []
        if not rows:
            self.out.add_finding(
                title="PostgreSQL pgaudit extension NOT installed",
                risk="MEDIUM", phase="logging", catalogue_id="DB-PG-018",
                description=("pgaudit provides session and object audit logging that meets "
                              "PCI DSS 10.x and HIPAA audit requirements. log_statement='all' "
                              "is too verbose for compliance use. "
                              "Install: CREATE EXTENSION pgaudit;"),
                output="pg_extension does not include pgaudit",
                command="SELECT extname FROM pg_extension WHERE extname='pgaudit'",
                owasp="A09:2021", nist="AU-2", pci_dss="10.2.1",
                db_version=self._version)

    def check_data_directory_perms(self):
        """2026-06-11 review: data_directory should be 0700 owned by postgres.
        We can only verify the path, not the on-disk perms, from a remote
        connection — so we surface the path and INFO the operator to verify."""
        try:
            rows = self._q("SHOW data_directory")
            d = rows[0]["data_directory"] if rows else ""
        except Exception:
            d = ""
        if d:
            self.out.add_finding(
                title=f"PostgreSQL data_directory: {d}",
                risk="INFO", phase="config", catalogue_id="DB-PG-020",
                description=(f"PostgreSQL data_directory is {d}. Verify on-host "
                              "permissions: must be 0700 and owned by postgres. "
                              "World/group-readable data dirs leak the on-disk "
                              "files even when DB auth is enforced."),
                output=f"data_directory = {d}",
                command="SHOW data_directory; ls -la <dir>",
                db_version=self._version)

    def run(self, db_version: str) -> list:
        return _run_checks("PostgreSQL", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_default_creds, "auth"),
            (self.check_ssl, "network"),
            (self.check_password_encryption, "config"),
            (self.check_superusers, "accounts"),
            (self.check_public_schema_perms, "permissions"),
            (self.check_row_security, "permissions"),
            (self.check_logging, "logging"),
            (self.check_pg_audit_extension, "logging"),
            (self.check_extensions, "config"),
            (self.check_copy_program, "config"),
            (self.check_listen_addresses, "config"),
            (self.check_pgcrypto_extension, "encryption"),
            (self.check_data_directory_perms, "config"),
        ], self.out)


# ---------------------------------------------------------------------------
# MSSQL Auditor
# ---------------------------------------------------------------------------
class MSSQLAuditor:
    def __init__(self, host, port, username, password, database, out: AugerOutput,
                 timeout=15):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.database = database or "master"
        self.out      = out
        self.timeout  = timeout
        self._conn    = None
        self._version = ""

    def connect(self) -> bool:
        pymssql = _try_import("pymssql")
        if not pymssql:
            # Try pyodbc
            pyodbc = _try_import("pyodbc")
            if not pyodbc:
                return False
            try:
                conn_str = (
                    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                    f"SERVER={self.host},{self.port};DATABASE={self.database};"
                    f"UID={self.username};PWD={self.password};"
                    f"TrustServerCertificate=yes;LoginTimeout={self.timeout}"
                )
                self._conn = pyodbc.connect(conn_str)
                return True
            except Exception as e:
                _console.log(f"MSSQL pyodbc connect failed: {e}", "ERROR")
                return False
        try:
            self._conn = pymssql.connect(
                server=self.host, port=str(self.port),
                user=self.username, password=self.password,
                database=self.database, login_timeout=self.timeout
            )
            return True
        except Exception as e:
            _console.log(f"MSSQL connect failed: {e}", "ERROR")
            return False

    def _q(self, sql: str) -> list:
        try:
            cur = self._conn.cursor()
            cur.execute(sql)
            return cur.fetchall()
        except Exception as e:
            self.out.log_error("mssql-query", str(e))
            return []

    def _q1(self, sql):
        rows = self._q(sql)
        return rows[0] if rows else None

    def _sp_config(self, option: str) -> int:
        rows = self._q(
            f"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
            f"SELECT value_in_use FROM sys.configurations WHERE name='{option}'"
        )
        if rows:
            return int(rows[0][0])
        return -1

    def check_version(self) -> str:
        row = self._q1("SELECT @@VERSION")
        if not row:
            return ""
        ver = str(row[0])
        self._version = ver
        self.out.log_step(f"MSSQL version: {ver[:80]}")
        m = re.search(r'(\d{4})', ver)
        yr = m.group(1) if m else ""
        if yr and _EOL_VERSIONS.get("mssql", {}).get(yr, False):
            self.out.add_finding(
                title=f"EOL Software: End-of-Life MSSQL Version: SQL Server {yr}",
                risk="CRITICAL", phase="version", catalogue_id="DB-009",
                description=f"SQL Server {yr} is end-of-life.",
                output=ver[:200], db_version=yr, command="SELECT @@VERSION"
            )
        return ver

    def check_xp_cmdshell(self):
        rows = self._q(
            "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'"
        )
        if rows and int(rows[0][0]) == 1:
            self.out.add_finding(
                title="Database: MSSQL xp_cmdshell Enabled",
                risk="CRITICAL", phase="config", catalogue_id="DB-200",
                description="xp_cmdshell is enabled — OS command execution possible from T-SQL.",
                output="xp_cmdshell value_in_use = 1",
                command="SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'",
                db_version=self._version
            )
            self.out.log_action_item(
                type="vulnerability",
                recommended_tool="Metasploit",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title="Exploit Verification — MSSQL xp_cmdshell RCE",
                description="xp_cmdshell is enabled allowing OS command execution. Test with Metasploit mssql_payload or manual EXEC xp_cmdshell.",
                source_finding="Database: MSSQL xp_cmdshell Enabled",
                priority="CRITICAL",
                metadata={"db_type": "MSSQL", "module": "exploit/windows/mssql/mssql_payload"}
            )

    def check_sa_account(self):
        rows = self._q(
            "SELECT name, is_disabled FROM sys.server_principals WHERE name='sa'"
        )
        if rows and rows[0][1] == 0:
            self.out.add_finding(
                title="Database: MSSQL SA Account Enabled",
                risk="HIGH", phase="accounts", catalogue_id="DB-201",
                description="The 'sa' built-in account is enabled.",
                output="sa account is_disabled=0",
                command="SELECT name,is_disabled FROM sys.server_principals WHERE name='sa'",
                db_version=self._version
            )

    def check_clr(self):
        rows = self._q(
            "SELECT value_in_use FROM sys.configurations WHERE name='clr enabled'"
        )
        if rows and int(rows[0][0]) == 1:
            self.out.add_finding(
                title="Database: MSSQL CLR Integration Enabled",
                risk="HIGH", phase="config", catalogue_id="DB-202",
                description="CLR integration is enabled — .NET assemblies can run in SQL Server.",
                output="clr enabled = 1",
                command="SELECT value_in_use FROM sys.configurations WHERE name='clr enabled'",
                db_version=self._version
            )

    def check_ole_automation(self):
        rows = self._q(
            "SELECT value_in_use FROM sys.configurations WHERE name='Ole Automation Procedures'"
        )
        if rows and int(rows[0][0]) == 1:
            self.out.add_finding(
                title="Database: MSSQL OLE Automation Procedures Enabled",
                risk="CRITICAL", phase="config", catalogue_id="DB-203",
                description="OLE Automation Procedures enabled — COM/OLE objects accessible from T-SQL.",
                output="Ole Automation Procedures = 1",
                command="SELECT value_in_use FROM sys.configurations WHERE name='Ole Automation Procedures'",
                db_version=self._version
            )

    def check_linked_servers(self):
        rows = self._q(
            "SELECT name, data_source, provider FROM sys.servers WHERE is_linked=1"
        )
        if rows:
            ls = [r[0] for r in rows]
            self.out.add_finding(
                title="Database: MSSQL Linked Servers Configured",
                risk="HIGH", phase="config", catalogue_id="DB-204",
                description=f"Linked servers found: {ls}",
                output=str(rows)[:500],
                command="SELECT name FROM sys.servers WHERE is_linked=1",
                db_version=self._version
            )

    def check_builtin_admins(self):
        rows = self._q(
            "SELECT m.name FROM sys.server_role_members rm "
            "JOIN sys.server_principals m ON rm.member_principal_id=m.principal_id "
            "JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id "
            "WHERE r.name='sysadmin' AND m.name LIKE 'BUILTIN%'"
        )
        if rows:
            self.out.add_finding(
                title="Database: MSSQL BUILTIN\\Administrators in Sysadmin Role",
                risk="HIGH", phase="permissions", catalogue_id="DB-206",
                description=f"BUILTIN accounts with sysadmin: {[r[0] for r in rows]}",
                output=str(rows),
                command="Query sys.server_role_members for BUILTIN sysadmin members",
                db_version=self._version
            )

    def check_password_policy(self):
        rows = self._q(
            "SELECT name, is_policy_checked, is_expiration_checked "
            "FROM sys.sql_logins WHERE is_policy_checked=0 OR is_expiration_checked=0"
        )
        if rows:
            logins = [r[0] for r in rows]
            self.out.add_finding(
                title="Database: MSSQL Mixed Mode Authentication with SQL Logins Not Subject to Password Policy",
                risk="HIGH", phase="config", catalogue_id="DB-205",
                description=f"SQL logins without policy/expiry check: {logins}",
                output=str(rows)[:500],
                command="SELECT name,is_policy_checked FROM sys.sql_logins",
                db_version=self._version
            )

    def check_tde(self):
        rows = self._q(
            "SELECT db.name FROM sys.databases db "
            "LEFT JOIN sys.dm_database_encryption_keys ek ON db.database_id=ek.database_id "
            "WHERE db.name NOT IN ('master','tempdb','model','msdb') "
            "AND (ek.encryption_state IS NULL OR ek.encryption_state=1)"
        )
        if rows:
            dbs = [r[0] for r in rows]
            self.out.add_finding(
                title="Database: MSSQL Transparent Data Encryption (TDE) Not Enabled",
                risk="HIGH", phase="crypto", catalogue_id="DB-207",
                description=f"Databases without TDE: {dbs}",
                output=str(dbs),
                command="Query sys.dm_database_encryption_keys",
                db_version=self._version
            )

    def check_ad_hoc_queries(self):
        rows = self._q(
            "SELECT value_in_use FROM sys.configurations WHERE name='Ad Hoc Distributed Queries'"
        )
        if rows and int(rows[0][0]) == 1:
            self.out.add_finding(
                title="Database: MSSQL Ad Hoc Distributed Queries Enabled",
                risk="HIGH", phase="config", catalogue_id="DB-208",
                description="Ad Hoc Distributed Queries enabled — OPENROWSET/OPENDATASOURCE accessible.",
                output="Ad Hoc Distributed Queries = 1",
                command="SELECT value_in_use FROM sys.configurations WHERE name='Ad Hoc Distributed Queries'",
                db_version=self._version
            )

    def check_database_mail(self):
        rows = self._q(
            "SELECT value_in_use FROM sys.configurations WHERE name='Database Mail XPs'"
        )
        if rows and int(rows[0][0]) == 1:
            self.out.add_finding(
                title="Database: MSSQL Database Mail Enabled",
                risk="LOW", phase="config",
                description="Database Mail XPs are enabled. Review if required.",
                output="Database Mail XPs = 1",
                command="SELECT value_in_use FROM sys.configurations WHERE name='Database Mail XPs'",
                owasp="A05:2021", nist="CM-7", iso_27001="A.8.9",
                db_version=self._version
            )

    def check_default_creds(self):
        pymssql = _try_import("pymssql")
        if not pymssql:
            return
        for user, pwd in _DEFAULT_CREDS["mssql"]:
            if user == self.username and pwd == self.password:
                continue
            try:
                c = pymssql.connect(server=self.host, port=str(self.port),
                                    user=user, password=pwd,
                                    database="master", login_timeout=4)
                c.close()
                self.out.add_finding(
                    title="Default Credentials in Use",
                    risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                    description=f"Authenticated with default credentials: {user}",
                    output=f"user={user}", db_version=self._version,
                    command=f"sqlcmd -S {self.host},{self.port} -U {user} -P ***"
                )
                break
            except Exception:
                pass

    def check_always_encrypted(self):
        """2026-06-11 review: MSSQL Always Encrypted column visibility.

        Always Encrypted (since SQL Server 2016) keeps data encrypted at
        the column level — server never sees plaintext. We surface its
        presence (INFO when used) and ABSENCE on tables containing
        sensitive columns (HIGH when missing on PII-shaped column names).
        """
        try:
            # Tables/columns with Always Encrypted
            ae_rows = self._q("""SELECT t.name AS table_name, c.name AS column_name,
                                  c.encryption_type_desc, c.encryption_algorithm_name
                                  FROM sys.columns c
                                  JOIN sys.tables t ON t.object_id = c.object_id
                                  WHERE c.encryption_type IS NOT NULL""")
        except Exception:
            ae_rows = []
        if ae_rows:
            self.out.add_finding(
                title=f"MSSQL Always Encrypted IN USE — {len(ae_rows)} encrypted columns",
                risk="INFO", phase="crypto", catalogue_id="DB-MS-021-A",
                description=("Always Encrypted is in use on the server. Encrypted "
                              "columns: " + ", ".join(f"{r['table_name']}.{r['column_name']}"
                                                       for r in ae_rows[:10])),
                output="\n".join(f"{r['table_name']}.{r['column_name']} "
                                  f"({r['encryption_type_desc']}, {r['encryption_algorithm_name']})"
                                  for r in ae_rows[:50]),
                command="SELECT FROM sys.columns WHERE encryption_type IS NOT NULL",
                db_version=self._version)
        # PII-shaped column names that are NOT encrypted
        try:
            pii_rows = self._q("""SELECT t.name AS table_name, c.name AS column_name
                                    FROM sys.columns c
                                    JOIN sys.tables t ON t.object_id = c.object_id
                                    WHERE c.encryption_type IS NULL
                                       AND (LOWER(c.name) LIKE '%ssn%'
                                         OR LOWER(c.name) LIKE '%creditcard%'
                                         OR LOWER(c.name) LIKE '%cardnumber%'
                                         OR LOWER(c.name) LIKE '%passport%'
                                         OR LOWER(c.name) LIKE '%dob%'
                                         OR LOWER(c.name) LIKE '%birthdate%'
                                         OR LOWER(c.name) LIKE '%taxid%')""")
        except Exception:
            pii_rows = []
        if pii_rows:
            self.out.add_finding(
                title=f"Database: MSSQL {len(pii_rows)} PII-shaped column(s) NOT Always Encrypted",
                risk="HIGH", phase="crypto", catalogue_id="DB-MS-021-B",
                description=("Columns with PII-shaped names exist without "
                              "Always Encrypted column encryption. PII / PCI "
                              "scope columns should be encrypted at the column "
                              "level so plaintext never traverses the network "
                              "or sits on disk in plain form."),
                output="\n".join(f"{r['table_name']}.{r['column_name']}"
                                  for r in pii_rows[:50]),
                command="SELECT FROM sys.columns WHERE encryption_type IS NULL AND name LIKE 'ssn'/'creditcard'/...",
                owasp="A02:2021", nist="SC-28", pci_dss="3.4.1",
                db_version=self._version)

    def check_audit_destination(self):
        """2026-06-11 review: MSSQL Server Audit destination check.

        sys.server_audits records the destination. Audit logs that write
        to APPLICATION LOG or the LOCAL FILE system on the DB host are
        accessible to a compromised local admin and offer little forensic
        value. SECURITY LOG (Windows Event) or external FILE on a SIEM-
        ingested share are preferred.
        """
        try:
            rows = self._q("""SELECT name, type_desc, on_failure_desc, is_state_enabled,
                                       log_file_path
                                  FROM sys.server_audits""")
        except Exception:
            rows = []
        if not rows:
            self.out.add_finding(
                title="MSSQL Server Audit NOT configured",
                risk="HIGH", phase="logging", catalogue_id="DB-MS-022",
                description=("No SQL Server Audit objects exist. Without "
                              "server-level audit, DDL/DML and login events are "
                              "unlogged. Compliance frameworks (PCI DSS 10.x, "
                              "HIPAA 164.312(b)) require audit logging."),
                output="sys.server_audits is empty",
                command="SELECT FROM sys.server_audits",
                owasp="A09:2021", nist="AU-2", pci_dss="10.2.1",
                db_version=self._version)
            return
        for r in rows:
            dest = (r.get("type_desc") or "").upper()
            if dest == "APPLICATION LOG":
                self.out.add_finding(
                    title=f"MSSQL Audit '{r['name']}' destination is APPLICATION_LOG",
                    risk="MEDIUM", phase="logging", catalogue_id="DB-MS-022-A",
                    description=("Audit destination is the Windows Application Event "
                                  "Log — accessible to any local admin and easily "
                                  "rotated/cleared. Prefer SECURITY LOG or a remote "
                                  "FILE destination shipped to a SIEM."),
                    output=str(dict(r)),
                    command="SELECT type_desc FROM sys.server_audits",
                    db_version=self._version)
            elif dest == "FILE" and r.get("log_file_path"):
                lfp = (r.get("log_file_path") or "").upper()
                if lfp.startswith(("C:\\", "D:\\", "/VAR/", "/OPT/")) \
                        and not lfp.startswith("\\\\"):   # not a UNC share
                    self.out.add_finding(
                        title=f"MSSQL Audit '{r['name']}' writes to LOCAL disk",
                        risk="LOW", phase="logging", catalogue_id="DB-MS-022-B",
                        description=("Audit log file path is a local-only disk "
                                      "location. For tamper-evidence and central "
                                      "retention, ship to a SIEM-ingested UNC share "
                                      "or syslog forwarder."),
                        output=f"log_file_path = {r['log_file_path']}",
                        command="SELECT log_file_path FROM sys.server_audits",
                        db_version=self._version)

    def run(self, db_version: str) -> list:
        phases = _run_checks("MSSQL", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_default_creds, "auth"),
            (self.check_xp_cmdshell, "config"),
            (self.check_sa_account, "accounts"),
            (self.check_clr, "config"),
            (self.check_ole_automation, "config"),
            (self.check_linked_servers, "config"),
            (self.check_builtin_admins, "permissions"),
            (self.check_password_policy, "config"),
            (self.check_tde, "crypto"),
            (self.check_always_encrypted, "crypto"),
            (self.check_audit_destination, "logging"),
            (self.check_ad_hoc_queries, "config"),
            (self.check_database_mail, "config"),
        ], self.out)
        return phases


# ---------------------------------------------------------------------------
# MongoDB Auditor
# ---------------------------------------------------------------------------
class MongoDBauditor:
    def __init__(self, host, port, username, password, database, out: AugerOutput,
                 ssl_enabled=False, timeout=10):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.database = database or "admin"
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._client  = None
        self._version = ""

    def connect(self) -> bool:
        pymongo = _try_import("pymongo")
        if not pymongo:
            return False
        try:
            from pymongo import MongoClient
            from pymongo.errors import ServerSelectionTimeoutError
            auth = ""
            if self.username:
                auth = f"{quote_plus(self.username)}:{quote_plus(self.password)}@"
            tls = "/?tls=true" if self.ssl_en else ""
            uri = f"mongodb://{auth}{self.host}:{self.port}/{self.database}{tls}"
            self._client = MongoClient(
                uri, serverSelectionTimeoutMS=self.timeout * 1000,
                connectTimeoutMS=self.timeout * 1000
            )
            self._client.server_info()
            return True
        except Exception as e:
            _console.log(f"MongoDB connect failed: {e}", "ERROR")
            return False

    def check_version(self) -> str:
        try:
            info = self._client.server_info()
            ver = info.get("version", "")
            self._version = ver
            self.out.log_step(f"MongoDB version: {ver}")
            major_minor = ".".join(ver.split(".")[:2])
            if _EOL_VERSIONS.get("mongodb", {}).get(major_minor, False):
                self.out.add_finding(
                    title=f"EOL Software: End-of-Life MongoDB Version: {ver}",
                    risk="CRITICAL", phase="version", catalogue_id="DB-009",
                    description=f"MongoDB {ver} is end-of-life.",
                    output=f"version={ver}", db_version=ver,
                    command="db.serverStatus()"
                )
            for cve in _KNOWN_CVES.get("mongodb", []):
                if any(ver.startswith(v) for v in cve["versions"]):
                    self.out.add_finding(
                        title=f"Known CVE in MongoDB Version: {cve['cve']}",
                        risk="HIGH", phase="version", catalogue_id="DB-010",
                        description=cve["desc"], cves=cve["cve"],
                        output=f"Version: {ver}", db_version=ver,
                        command="db.serverStatus()"
                    )
                    self.out.log_action_item(
                        type="exploit",
                        recommended_tool="ExploitDB" if "exploit" in cve.get("desc", "").lower() else "Metasploit",
                        target=f"{self.out.host}:{self.out.port}",
                        ip=self.out.host, port=self.out.port,
                        title=f"Exploit Verification — {cve['cve']}",
                        description=f"Known CVE {cve['cve']} (CVSS {cve.get('cvss', 'N/A')}) affects MongoDB {ver}. Verify exploitability.",
                        source_finding=f"Known CVE in MongoDB Version: {cve['cve']}",
                        priority="HIGH",
                        metadata={"cve": cve["cve"], "cvss": cve.get("cvss"), "db_version": ver}
                    )
            return ver
        except Exception:
            return ""

    def check_auth_enabled(self):
        try:
            # Try connecting without credentials
            from pymongo import MongoClient
            test = MongoClient(
                host=self.host, port=self.port,
                serverSelectionTimeoutMS=4000
            )
            test.admin.command("ping")
            # If no exception, auth is not required
            self.out.add_finding(
                title="Database: MongoDB Authentication Disabled",
                risk="CRITICAL", phase="auth", catalogue_id="DB-300",
                description="MongoDB accepted connection without authentication.",
                output=f"Connected to {self.host}:{self.port} without credentials",
                command=f"mongo --host {self.host} --port {self.port}",
                db_version=self._version
            )
            self.out.log_action_item(
                type="vulnerability",
                recommended_tool="Manual Verification",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title="Manual Verification Required — MongoDB No Authentication",
                description="MongoDB accepts unauthenticated connections. Enumerate databases and assess data exposure.",
                source_finding="Database: MongoDB Authentication Disabled",
                priority="CRITICAL",
                metadata={"db_type": "MongoDB"}
            )
            test.close()
        except Exception:
            pass  # Auth is working

    def check_javascript(self):
        try:
            result = self._client.admin.command(
                {"getParameter": 1, "javascriptEnabled": 1}
            )
            if result.get("javascriptEnabled", True):
                self.out.add_finding(
                    title="Database: MongoDB Server-Side JavaScript Execution Enabled",
                    risk="MEDIUM", phase="config", catalogue_id="DB-301",
                    description="Server-side JavaScript is enabled — $where, mapReduce available.",
                    output="javascriptEnabled=true",
                    command="db.adminCommand({getParameter:1,javascriptEnabled:1})",
                    db_version=self._version
                )
        except Exception:
            pass

    def check_tls(self):
        try:
            result = self._client.admin.command("getCmdLineOpts")
            opts = result.get("parsed", {}).get("net", {}).get("tls", {})
            mode = opts.get("mode", "disabled")
            if mode not in ("requireTLS", "allowTLS"):
                self.out.add_finding(
                    title="Database: MongoDB No TLS/SSL Configured",
                    risk="HIGH", phase="network", catalogue_id="DB-302",
                    description=f"MongoDB TLS mode={mode!r} — connections may be unencrypted.",
                    output=f"net.tls.mode = {mode}",
                    command="db.adminCommand('getCmdLineOpts')",
                    db_version=self._version
                )
        except Exception:
            pass

    def check_users(self):
        try:
            result = self._client.admin.command("usersInfo", {"forAllDBs": True})
            users = result.get("users", [])
            for u in users:
                for role in u.get("roles", []):
                    if role.get("role") in ("root", "__system"):
                        self.out.add_finding(
                            title="Database: MongoDB User with Root or __system Role",
                            risk="CRITICAL", phase="accounts", catalogue_id="DB-303",
                            description=f"User {u['user']} has dangerous role: {role['role']}",
                            output=f"user={u['user']} role={role['role']} db={role.get('db','')}",
                            command="db.adminCommand({usersInfo:{forAllDBs:true}})",
                            db_version=self._version
                        )
        except Exception:
            pass

    def check_bind_ip(self):
        try:
            result = self._client.admin.command("getCmdLineOpts")
            bind = result.get("parsed", {}).get("net", {}).get("bindIp", "127.0.0.1")
            if "0.0.0.0" in bind or bind == "":
                self.out.add_finding(
                    title="Database: Database Listening on All Network Interfaces (0.0.0.0)",
                    risk="HIGH", phase="config", catalogue_id="DB-004",
                    description=f"MongoDB net.bindIp={bind!r}",
                    output=f"net.bindIp = {bind}",
                    command="db.adminCommand('getCmdLineOpts')",
                    db_version=self._version
                )
        except Exception:
            pass

    def check_encryption_at_rest(self):
        """2026-06-11 review: WiredTiger encryption-at-rest visibility."""
        try:
            result = self._client.admin.command("getCmdLineOpts")
            wt_engine_cfg = (result.get("parsed", {})
                              .get("storage", {})
                              .get("engine", "wiredTiger"))
            wt_cfg = (result.get("parsed", {})
                       .get("storage", {})
                       .get("wiredTiger", {})
                       .get("engineConfig", {}))
            encryption = (result.get("parsed", {})
                           .get("security", {})
                           .get("enableEncryption", False))
        except Exception:
            wt_engine_cfg = ""; wt_cfg = {}; encryption = False
        if wt_engine_cfg != "wiredTiger":
            return  # Other engines not in scope
        if not encryption:
            self.out.add_finding(
                title="MongoDB WiredTiger Encryption-at-Rest NOT Enabled",
                risk="HIGH", phase="encryption", catalogue_id="DB-MDB-019",
                description=("MongoDB Enterprise supports WiredTiger native encryption "
                              "via security.enableEncryption. Without it, all data files "
                              "are stored unencrypted on disk. Compliance frameworks "
                              "(HIPAA / PCI DSS 3.4) require at-rest encryption."),
                output=f"security.enableEncryption = {encryption}, "
                       f"storage.engine = {wt_engine_cfg}",
                command="db.adminCommand('getCmdLineOpts')",
                owasp="A02:2021", nist="SC-28",
                db_version=self._version)

    def check_oplog_exposure(self):
        """2026-06-11 review: replica set oplog access requires explicit
        roles (clusterMonitor/clusterManager); if any non-admin role can
        access local.oplog.rs, that's a leak vector."""
        try:
            roles = self._client.admin.command("rolesInfo", {"rolesInfo": 1, "showPrivileges": True})
            danger = []
            for r in roles.get("roles", []):
                for priv in (r.get("privileges") or []):
                    res = priv.get("resource", {})
                    if res.get("db") == "local" and res.get("collection") in ("oplog.rs", ""):
                        if r.get("role") not in ("__system","clusterMonitor","clusterManager","backup"):
                            danger.append(r["role"])
            if danger:
                self.out.add_finding(
                    title=f"Database: MongoDB Non-system role(s) can read oplog.rs",
                    risk="HIGH", phase="permissions", catalogue_id="DB-MDB-020",
                    description=(f"Roles {danger} have access to local.oplog.rs. "
                                  "Oplog records every database mutation; access allows "
                                  "covert change-data-capture."),
                    output=f"roles_with_oplog_access = {danger}",
                    command="db.adminCommand('rolesInfo')",
                    db_version=self._version)
        except Exception:
            pass

    def check_default_creds(self):
        from pymongo import MongoClient
        from pymongo.errors import OperationFailure
        for user, pwd in _DEFAULT_CREDS["mongodb"]:
            if user == self.username and pwd == self.password:
                continue
            try:
                auth = f"{quote_plus(user)}:{quote_plus(pwd)}@" if user else ""
                c = MongoClient(
                    f"mongodb://{auth}{self.host}:{self.port}/admin",
                    serverSelectionTimeoutMS=4000
                )
                c.admin.command("ping")
                c.close()
                self.out.add_finding(
                    title="Default Credentials in Use",
                    risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                    description=f"Authenticated with default credentials: {user}",
                    output=f"user={user}", db_version=self._version,
                    command=f"mongo -u {user} -p *** --host {self.host}"
                )
                break
            except Exception:
                pass

    def run(self, db_version: str) -> list:
        return _run_checks("MongoDB", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_auth_enabled, "auth"),
            (self.check_default_creds, "auth"),
            (self.check_javascript, "config"),
            (self.check_tls, "network"),
            (self.check_users, "accounts"),
            (self.check_bind_ip, "config"),
            (self.check_encryption_at_rest, "encryption"),
            (self.check_oplog_exposure, "permissions"),
        ], self.out)


# ---------------------------------------------------------------------------
# Redis Auditor
# ---------------------------------------------------------------------------
class RedisAuditor:
    def __init__(self, host, port, password, out: AugerOutput, ssl_enabled=False, timeout=5):
        self.host     = host
        self.port     = port
        self.password = password
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._client  = None
        self._version = ""

    def connect(self) -> bool:
        redis = _try_import("redis")
        if not redis:
            return False
        try:
            self._client = redis.Redis(
                host=self.host, port=self.port,
                password=self.password or None,
                ssl=self.ssl_en, socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
                decode_responses=True
            )
            self._client.ping()
            return True
        except Exception as e:
            _console.log(f"Redis connect failed: {e}", "ERROR")
            return False

    def check_version(self) -> str:
        try:
            info = self._client.info("server")
            ver = info.get("redis_version", "")
            self._version = ver
            self.out.log_step(f"Redis version: {ver}")
            major_minor = ".".join(ver.split(".")[:2])
            if _EOL_VERSIONS.get("redis", {}).get(major_minor, False):
                self.out.add_finding(
                    title=f"EOL Software: End-of-Life Redis Version: {ver}",
                    risk="CRITICAL", phase="version", catalogue_id="DB-009",
                    description=f"Redis {ver} is end-of-life.",
                    output=f"redis_version={ver}", db_version=ver
                )
            for cve in _KNOWN_CVES.get("redis", []):
                if any(ver.startswith(v) for v in cve["versions"]):
                    self.out.add_finding(
                        title=f"Known CVE in Redis Version: {cve['cve']}",
                        risk="HIGH", phase="version", catalogue_id="DB-010",
                        description=cve["desc"], cves=cve["cve"],
                        output=f"Version: {ver}", db_version=ver
                    )
                    self.out.log_action_item(
                        type="exploit",
                        recommended_tool="ExploitDB" if "exploit" in cve.get("desc", "").lower() else "Metasploit",
                        target=f"{self.out.host}:{self.out.port}",
                        ip=self.out.host, port=self.out.port,
                        title=f"Exploit Verification — {cve['cve']}",
                        description=f"Known CVE {cve['cve']} (CVSS {cve.get('cvss', 'N/A')}) affects Redis {ver}. Verify exploitability.",
                        source_finding=f"Known CVE in Redis Version: {cve['cve']}",
                        priority="HIGH",
                        metadata={"cve": cve["cve"], "cvss": cve.get("cvss"), "db_version": ver}
                    )
            return ver
        except Exception:
            return ""

    def check_no_auth(self):
        """Check if Redis is accessible without authentication."""
        redis = _try_import("redis")
        if not redis:
            return
        if self.password:
            return
        try:
            r2 = redis.Redis(host=self.host, port=self.port, socket_timeout=4,
                             decode_responses=True)
            r2.ping()
            self.out.add_finding(
                title="Database: Redis No Authentication Configured (requirepass Not Set)",
                risk="CRITICAL", phase="auth", catalogue_id="DB-350",
                description="Redis is accessible without a password.",
                output=f"Connected to {self.host}:{self.port} without credentials",
                command=f"redis-cli -h {self.host} -p {self.port} ping",
                db_version=self._version
            )
            self.out.log_action_item(
                type="vulnerability",
                recommended_tool="Manual Verification",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title="Manual Verification Required — Redis No Authentication",
                description="Redis accepts unauthenticated connections. Test for data exfiltration and RCE via CONFIG SET / MODULE LOAD.",
                source_finding="Database: Redis No Authentication Configured (requirepass Not Set)",
                priority="CRITICAL",
                metadata={"db_type": "Redis"}
            )
        except Exception:
            pass

    def check_protected_mode(self):
        try:
            pm = self._client.config_get("protected-mode")
            if pm.get("protected-mode", "yes").lower() in ("no", "0", "false"):
                self.out.add_finding(
                    title="Database: Redis Protected Mode Disabled",
                    risk="HIGH", phase="config", catalogue_id="DB-351",
                    description="protected-mode=no — the safety layer is disabled.",
                    output="protected-mode = no",
                    command="redis-cli CONFIG GET protected-mode",
                    db_version=self._version
                )
        except Exception:
            pass

    def check_dangerous_commands(self):
        dangerous = ["FLUSHALL", "FLUSHDB", "DEBUG", "CONFIG", "SLAVEOF", "REPLICAOF"]
        accessible = []
        for cmd in dangerous:
            try:
                # Try a benign invocation or check via ACL
                if cmd == "CONFIG":
                    self._client.config_get("maxmemory")
                    accessible.append(cmd)
                elif cmd == "DEBUG":
                    # DEBUG SLEEP 0 is harmless
                    self._client.execute_command("DEBUG", "SLEEP", "0")
                    accessible.append(cmd)
            except Exception as e:
                if "unknown command" in str(e).lower() or "renamed" in str(e).lower():
                    pass  # renamed/disabled
                elif "no auth" in str(e).lower():
                    pass
                # Permission denied still means command exists
                else:
                    accessible.append(cmd)
        if accessible:
            self.out.add_finding(
                title="Database: Redis Dangerous Commands Not Renamed or Disabled",
                risk="HIGH", phase="config", catalogue_id="DB-352",
                description=f"Dangerous commands accessible: {accessible}",
                output=f"Accessible: {accessible}",
                command="redis-cli CONFIG GET ... / DEBUG SLEEP 0",
                db_version=self._version
            )

    def check_bind(self):
        try:
            bind = self._client.config_get("bind")
            addr = bind.get("bind", "127.0.0.1")
            if "0.0.0.0" in addr or addr.strip() == "":
                self.out.add_finding(
                    title="Database: Database Listening on All Network Interfaces (0.0.0.0)",
                    risk="HIGH", phase="config", catalogue_id="DB-004",
                    description=f"Redis bind={addr!r}",
                    output=f"bind = {addr}",
                    command="redis-cli CONFIG GET bind",
                    db_version=self._version
                )
        except Exception:
            pass

    def check_tls(self):
        try:
            tls_port = self._client.config_get("tls-port")
            if not tls_port.get("tls-port") or tls_port.get("tls-port") == "0":
                self.out.add_finding(
                    title="Database: Cleartext Database Protocol (No TLS/SSL)",
                    risk="HIGH", phase="network", catalogue_id="DB-001",
                    description="Redis TLS is not configured (tls-port=0).",
                    output=f"tls-port = {tls_port.get('tls-port', '0')}",
                    command="redis-cli CONFIG GET tls-port",
                    db_version=self._version
                )
        except Exception:
            pass

    def check_acl(self):
        """Redis 6+ ACL check."""
        try:
            acl_list = self._client.execute_command("ACL", "LIST")
            default_full = False
            for entry in acl_list:
                if "user default" in str(entry) and "+@all" in str(entry) and "nopass" in str(entry):
                    default_full = True
            if default_full:
                self.out.add_finding(
                    title="Database: Redis Default ACL User Has Full Access (nopass +@all)",
                    risk="CRITICAL", phase="auth",
                    description="The default Redis ACL user has no password and full command access.",
                    output=str(acl_list)[:300],
                    command="redis-cli ACL LIST",
                    owasp="A07:2021", owasp_asvs="V2.1.1", nist="IA-2",
                    pci_dss="8.2.1", hipaa="164.312(d)",
                    db_version=self._version
                )
        except Exception:
            pass

    def check_default_creds(self):
        redis = _try_import("redis")
        if not redis:
            return
        for _, pwd in _DEFAULT_CREDS["redis"]:
            if pwd == self.password:
                continue
            try:
                r2 = redis.Redis(host=self.host, port=self.port, password=pwd or None,
                                 socket_timeout=4, decode_responses=True)
                r2.ping()
                self.out.add_finding(
                    title="Default Credentials in Use",
                    risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                    description=f"Authenticated with default password: {'(empty)' if not pwd else '***'}",
                    output=f"password={'(empty)' if not pwd else '***'}",
                    command=f"redis-cli -h {self.host} -p {self.port} -a ***",
                    db_version=self._version
                )
                break
            except Exception:
                pass

    def run(self, db_version: str) -> list:
        return _run_checks("Redis", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_no_auth, "auth"),
            (self.check_default_creds, "auth"),
            (self.check_protected_mode, "config"),
            (self.check_dangerous_commands, "config"),
            (self.check_bind, "config"),
            (self.check_tls, "network"),
            (self.check_acl, "auth"),
        ], self.out)


# ---------------------------------------------------------------------------
# Cassandra Auditor
# ---------------------------------------------------------------------------
class CassandraAuditor:
    def __init__(self, host, port, username, password, keyspace, out: AugerOutput,
                 ssl_enabled=False, timeout=10):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.keyspace = keyspace
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._session = None
        self._version = ""

    def connect(self) -> bool:
        cassandra = _try_import("cassandra", "cassandra-driver")
        if not cassandra:
            return False
        try:
            from cassandra.cluster import Cluster
            from cassandra.auth import PlainTextAuthProvider
            auth = PlainTextAuthProvider(username=self.username, password=self.password) \
                   if self.username else None
            ssl_ctx = ssl.create_default_context() if self.ssl_en else None
            cluster = Cluster(
                [self.host], port=self.port, auth_provider=auth,
                ssl_context=ssl_ctx, connect_timeout=self.timeout
            )
            self._session = cluster.connect(self.keyspace or None)
            return True
        except Exception as e:
            _console.log(f"Cassandra connect failed: {e}", "ERROR")
            return False

    def _q(self, cql: str) -> list:
        try:
            return list(self._session.execute(cql))
        except Exception as e:
            self.out.log_error("cassandra-query", str(e))
            return []

    def check_version(self) -> str:
        rows = self._q("SELECT release_version FROM system.local")
        ver = rows[0].release_version if rows else ""
        self._version = ver
        self.out.log_step(f"Cassandra version: {ver}")
        major_minor = ".".join(ver.split(".")[:2])
        if _EOL_VERSIONS.get("cassandra", {}).get(major_minor, False):
            self.out.add_finding(
                title=f"EOL Software: End-of-Life Cassandra Version: {ver}",
                risk="CRITICAL", phase="version", catalogue_id="DB-009",
                description=f"Cassandra {ver} is end-of-life.",
                output=f"release_version={ver}", db_version=ver
            )
        for cve in _KNOWN_CVES.get("cassandra", []):
            if any(ver.startswith(v) for v in cve["versions"]):
                self.out.add_finding(
                    title=f"Known CVE in Cassandra Version: {cve['cve']}",
                    risk="HIGH", phase="version", catalogue_id="DB-010",
                    description=cve["desc"], cves=cve["cve"],
                    output=f"Version: {ver}", db_version=ver
                )
                self.out.log_action_item(
                    type="exploit",
                    recommended_tool="ExploitDB" if "exploit" in cve.get("desc", "").lower() else "Metasploit",
                    target=f"{self.out.host}:{self.out.port}",
                    ip=self.out.host, port=self.out.port,
                    title=f"Exploit Verification — {cve['cve']}",
                    description=f"Known CVE {cve['cve']} (CVSS {cve.get('cvss', 'N/A')}) affects Cassandra {ver}. Verify exploitability.",
                    source_finding=f"Known CVE in Cassandra Version: {cve['cve']}",
                    priority="HIGH",
                    metadata={"cve": cve["cve"], "cvss": cve.get("cvss"), "db_version": ver}
                )
        return ver

    def check_auth(self):
        """Try AllowAll — if we connected without a username, auth is disabled."""
        if not self.username:
            self.out.add_finding(
                title="Database: Cassandra AllowAllAuthenticator Configured (No Authentication)",
                risk="CRITICAL", phase="auth", catalogue_id="DB-400",
                description="Connected without credentials — authentication is disabled.",
                output=f"Connected to {self.host}:{self.port} without credentials",
                command=f"cqlsh {self.host} {self.port}",
                db_version=self._version
            )

    def check_default_creds(self):
        cassandra = _try_import("cassandra", "cassandra-driver")
        if not cassandra:
            return
        from cassandra.cluster import Cluster
        from cassandra.auth import PlainTextAuthProvider
        for user, pwd in _DEFAULT_CREDS["cassandra"]:
            if user == self.username and pwd == self.password:
                continue
            try:
                ap = PlainTextAuthProvider(username=user, password=pwd)
                # 2026-06-11 review: connect_timeout from --timeout (not hardcoded 4s)
                _ct = max(4, self.timeout // 2)
                cl = Cluster([self.host], port=self.port, auth_provider=ap,
                             connect_timeout=_ct)
                s = cl.connect()
                s.shutdown()
                cl.shutdown()
                self.out.add_finding(
                    title="Database: Cassandra Default Credentials in Use",
                    risk="CRITICAL", phase="auth", catalogue_id="DB-401",
                    description=f"Authenticated with default credentials: {user}/{pwd}",
                    output=f"user={user}", db_version=self._version,
                    command=f"cqlsh -u {user} -p *** {self.host} {self.port}"
                )
                break
            except Exception:
                pass

    def check_tls(self):
        rows = self._q(
            "SELECT client_id FROM system_auth.roles LIMIT 1"
        )
        # Attempt a cleartext connection to probe TLS
        try:
            from cassandra.cluster import Cluster
            _ct = max(4, self.timeout // 2)
            cl = Cluster([self.host], port=self.port, connect_timeout=_ct)
            s = cl.connect()
            s.shutdown()
            cl.shutdown()
            self.out.add_finding(
                title="Database: Cassandra Client-to-Server Encryption Disabled",
                risk="HIGH", phase="network", catalogue_id="DB-402",
                description="Cassandra accepted a cleartext (non-TLS) connection.",
                output=f"Connected to {self.host}:{self.port} without TLS",
                command=f"cqlsh {self.host} {self.port}",
                db_version=self._version
            )
        except Exception:
            pass

    def check_superusers(self):
        rows = self._q("SELECT role, super FROM system_auth.roles WHERE super=true")
        users = [r.role for r in rows]
        if "cassandra" in users:
            self.out.add_finding(
                title="Default Credentials in Use",
                risk="CRITICAL", phase="auth", catalogue_id="DB-401",
                description="Default 'cassandra' superuser account is still active.",
                output=f"superusers={users}", db_version=self._version
            )
        if len(users) > 2:
            self.out.add_finding(
                title="Database: Cassandra Multiple Superuser Accounts",
                risk="MEDIUM", phase="accounts",
                description=f"More than 2 superuser accounts found: {users}",
                output=str(users),
                command="SELECT role FROM system_auth.roles WHERE super=true",
                owasp="A01:2021", nist="AC-6", pci_dss="7.2.1",
                db_version=self._version
            )

    def run(self, db_version: str) -> list:
        return _run_checks("Cassandra", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_auth, "auth"),
            (self.check_default_creds, "auth"),
            (self.check_tls, "network"),
            (self.check_superusers, "accounts"),
        ], self.out)


# ---------------------------------------------------------------------------
# Elasticsearch Auditor  (HTTP-based)
# ---------------------------------------------------------------------------
class ElasticsearchAuditor:
    def __init__(self, host, port, username, password, out: AugerOutput,
                 ssl_enabled=False, timeout=10):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._version = ""
        self._base_url = f"{'https' if ssl_enabled else 'http'}://{host}:{port}"
        self._auth     = (username, password) if username else None

    def _get(self, path: str) -> dict:
        try:
            import urllib.request
            import base64
            url = self._base_url + path
            req = urllib.request.Request(url)
            if self._auth:
                token = base64.b64encode(
                    f"{self._auth[0]}:{self._auth[1]}".encode()
                ).decode()
                req.add_header("Authorization", f"Basic {token}")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=self.timeout,
                                          context=ctx if self.ssl_en else None)
            return json.loads(resp.read())
        except Exception as e:
            return {"_error": str(e)}

    def connect(self) -> bool:
        result = self._get("/")
        return "_error" not in result

    def check_version(self) -> str:
        data = self._get("/")
        ver = data.get("version", {}).get("number", "")
        self._version = ver
        self.out.log_step(f"Elasticsearch version: {ver}")
        major_minor = ".".join(ver.split(".")[:2])
        if _EOL_VERSIONS.get("elasticsearch", {}).get(major_minor, False):
            self.out.add_finding(
                title=f"EOL Software: End-of-Life Elasticsearch Version: {ver}",
                risk="CRITICAL", phase="version", catalogue_id="DB-009",
                description=f"Elasticsearch {ver} is end-of-life.",
                output=f"version={ver}", db_version=ver
            )
        for cve in _KNOWN_CVES.get("elasticsearch", []):
            if any(ver.startswith(v) for v in cve["versions"]):
                self.out.add_finding(
                    title=f"Known CVE in Elasticsearch Version: {cve['cve']}",
                    risk="HIGH", phase="version", catalogue_id="DB-010",
                    description=cve["desc"], cves=cve["cve"],
                    output=f"Version: {ver}", db_version=ver
                )
                self.out.log_action_item(
                    type="exploit",
                    recommended_tool="ExploitDB" if "exploit" in cve.get("desc", "").lower() else "Metasploit",
                    target=f"{self.out.host}:{self.out.port}",
                    ip=self.out.host, port=self.out.port,
                    title=f"Exploit Verification — {cve['cve']}",
                    description=f"Known CVE {cve['cve']} (CVSS {cve.get('cvss', 'N/A')}) affects Elasticsearch {ver}. Verify exploitability.",
                    source_finding=f"Known CVE in Elasticsearch Version: {cve['cve']}",
                    priority="HIGH",
                    metadata={"cve": cve["cve"], "cvss": cve.get("cvss"), "db_version": ver}
                )
        return ver

    def check_no_auth(self):
        """Test unauthenticated access."""
        result = self._get("/_cluster/health")
        if "_error" not in result:
            self.out.add_finding(
                title="Database: Elasticsearch Security Features Disabled (X-Pack Security)",
                risk="CRITICAL", phase="auth", catalogue_id="DB-450",
                description="Elasticsearch cluster health accessible without authentication.",
                output=json.dumps(result)[:500],
                command=f"curl -s http://{self.host}:{self.port}/_cluster/health",
                db_version=self._version
            )
            self.out.log_action_item(
                type="vulnerability",
                recommended_tool="Manual Verification",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title="Manual Verification Required — Elasticsearch No Authentication",
                description="Elasticsearch cluster accessible without authentication. Enumerate indices and assess data exposure.",
                source_finding="Database: Elasticsearch Security Features Disabled (X-Pack Security)",
                priority="CRITICAL",
                metadata={"db_type": "Elasticsearch"}
            )

    def check_cluster_info_exposed(self):
        data = self._get("/")
        if "cluster_name" in data:
            self.out.add_finding(
                title="Database: Elasticsearch Unauthenticated Cluster Information Exposed",
                risk="HIGH", phase="config", catalogue_id="DB-451",
                description=f"Cluster info exposed: cluster_name={data.get('cluster_name')} version={data.get('version',{}).get('number')}",
                output=json.dumps(data)[:500],
                command=f"curl -s http://{self.host}:{self.port}/",
                db_version=self._version
            )

    def check_indices(self):
        result = self._get("/_cat/indices?format=json")
        if isinstance(result, list) and result:
            idx_names = [i.get("index", "") for i in result]
            self.out.add_finding(
                title="Database: Elasticsearch Index Enumeration Without Authentication",
                risk="HIGH", phase="permissions",
                description=f"All {len(idx_names)} indices are enumerable without auth.",
                output=str(idx_names[:20]),
                command=f"curl -s http://{self.host}:{self.port}/_cat/indices",
                owasp="A01:2021", nist="AC-3", pci_dss="7.2.1",
                hipaa="164.312(a)(1)", db_version=self._version
            )

    def check_security_settings(self):
        result = self._get("/_cluster/settings?include_defaults=true&filter_path=**.security")
        sec = result.get("defaults", {}).get("xpack", {}).get("security", {})
        if sec.get("enabled") is False:
            self.out.add_finding(
                title="Database: Elasticsearch Security Features Disabled (X-Pack Security)",
                risk="CRITICAL", phase="auth", catalogue_id="DB-450",
                description="xpack.security.enabled=false",
                output=json.dumps(sec)[:300],
                command=f"curl -s http://{self.host}:{self.port}/_cluster/settings",
                db_version=self._version
            )

    def check_default_creds(self):
        for user, pwd in _DEFAULT_CREDS["elasticsearch"]:
            if user == self.username and pwd == self.password:
                continue
            import urllib.request
            import base64
            try:
                url = self._base_url + "/"
                req = urllib.request.Request(url)
                token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                req.add_header("Authorization", f"Basic {token}")
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=4,
                                             context=ctx if self.ssl_en else None)
                if resp.status == 200:
                    self.out.add_finding(
                        title="Default Credentials in Use",
                        risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                        description=f"Authenticated with default credentials: {user}/{pwd}",
                        output=f"user={user}", db_version=self._version,
                        command=f"curl -u {user}:*** http://{self.host}:{self.port}/"
                    )
                    break
            except Exception:
                pass

    def run(self, db_version: str) -> list:
        return _run_checks("Elasticsearch", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_no_auth, "auth"),
            (self.check_default_creds, "auth"),
            (self.check_cluster_info_exposed, "config"),
            (self.check_indices, "permissions"),
            (self.check_security_settings, "config"),
        ], self.out)


# ---------------------------------------------------------------------------
# Oracle Auditor  (oracledb thin mode — no Instant Client required)
# ---------------------------------------------------------------------------
class OracleAuditor:
    def __init__(self, host, port, username, password, database, out: AugerOutput,
                 ssl_enabled=False, timeout=15):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.database = database or "ORCL"
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._conn    = None
        self._version = ""

    def connect(self) -> bool:
        oracledb = _try_import("oracledb")
        if not oracledb:
            return False
        try:
            oracledb.init_oracle_client = lambda *a, **k: None  # stay in thin mode
            dsn = f"{self.host}:{self.port}/{self.database}"
            self._conn = oracledb.connect(
                user=self.username, password=self.password, dsn=dsn
            )
            return True
        except Exception as e:
            _console.log(f"Oracle connect failed: {e}", "ERROR")
            return False

    def _q(self, sql: str) -> list:
        try:
            cur = self._conn.cursor()
            cur.execute(sql)
            return cur.fetchall()
        except Exception as e:
            self.out.log_error("oracle-query", str(e))
            return []

    def _q1(self, sql: str):
        rows = self._q(sql)
        return rows[0] if rows else None

    def check_version(self) -> str:
        row = self._q1("SELECT BANNER FROM V$VERSION WHERE ROWNUM=1")
        ver = row[0] if row else ""
        self._version = ver
        self.out.log_step(f"Oracle version: {ver}")
        if "11g" in ver.lower() or "10g" in ver.lower():
            self.out.add_finding(
                title=f"EOL Software: End-of-Life Oracle Database Version: {ver}",
                risk="CRITICAL", phase="version", catalogue_id="DB-009",
                description=f"Oracle {ver} is end-of-life and no longer receives security patches.",
                output=ver, db_version=ver,
                command="SELECT BANNER FROM V$VERSION"
            )
        return ver

    def check_default_passwords(self):
        rows = self._q(
            "SELECT USERNAME,ACCOUNT_STATUS FROM DBA_USERS "
            "WHERE ACCOUNT_STATUS NOT IN ('LOCKED','EXPIRED & LOCKED') "
            "AND USERNAME IN ('SCOTT','HR','OE','SH','PM','BI','OUTLN','MDSYS',"
            "'DBSNMP','SYSMAN','ANONYMOUS','APEX_PUBLIC_USER')"
        )
        if rows:
            users = [r[0] for r in rows]
            self.out.add_finding(
                title="Database: Oracle Default Sample Schema Accounts Active",
                risk="HIGH", phase="auth", catalogue_id="DB-006",
                description=f"Default Oracle schema accounts are active: {users}",
                output=str(users), db_version=self._version,
                command="SELECT USERNAME,ACCOUNT_STATUS FROM DBA_USERS"
            )

    def check_public_grants(self):
        dangerous = ("UTL_FILE","UTL_HTTP","UTL_TCP","UTL_SMTP","DBMS_SQL",
                     "DBMS_SCHEDULER","DBMS_JAVA","JAVA_ADMIN","JAVA_DEPLOY")
        rows = self._q(
            "SELECT GRANTEE,PRIVILEGE,TABLE_NAME FROM DBA_TAB_PRIVS "
            "WHERE GRANTEE='PUBLIC' AND OWNER='SYS' "
            f"AND TABLE_NAME IN ({','.join(repr(p) for p in dangerous)})"
        )
        if rows:
            grants = [f"{r[2]} {r[1]}" for r in rows]
            self.out.add_finding(
                title="Database: Dangerous Oracle PUBLIC Execute Grants (UTL_FILE/DBMS_SQL etc.)",
                risk="HIGH", phase="permissions", catalogue_id="DB-053",
                description=f"PUBLIC execute grants on privileged packages: {grants}",
                output=str(grants), db_version=self._version,
                command="SELECT GRANTEE,PRIVILEGE,TABLE_NAME FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC'"
            )

    def check_remote_os_authent(self):
        row = self._q1("SELECT VALUE FROM V$PARAMETER WHERE NAME='remote_os_authent'")
        if row and str(row[0]).upper() == "TRUE":
            self.out.add_finding(
                title="Database: Oracle REMOTE_OS_AUTHENT Enabled",
                risk="CRITICAL", phase="config", catalogue_id="DB-051",
                description="REMOTE_OS_AUTHENT=TRUE allows OS-level authentication bypass.",
                output="remote_os_authent=TRUE", db_version=self._version,
                command="SELECT VALUE FROM V$PARAMETER WHERE NAME='remote_os_authent'"
            )

    def check_utl_file_dir(self):
        row = self._q1("SELECT VALUE FROM V$PARAMETER WHERE NAME='utl_file_dir'")
        if row and str(row[0]).strip() in ("*", "/"):
            self.out.add_finding(
                title="Database: Oracle UTL_FILE_DIR Wildcard — Arbitrary File Read/Write",
                risk="HIGH", phase="config", catalogue_id="DB-052",
                description=f"UTL_FILE_DIR={row[0]} permits read/write of any OS file.",
                output=f"utl_file_dir={row[0]}", db_version=self._version,
                command="SELECT VALUE FROM V$PARAMETER WHERE NAME='utl_file_dir'"
            )

    def check_audit_trail(self):
        row = self._q1("SELECT VALUE FROM V$PARAMETER WHERE NAME='audit_trail'")
        val = str(row[0]).upper() if row else "NONE"
        if val in ("NONE", "FALSE"):
            self.out.add_finding(
                title="Database: Oracle Unified Auditing Disabled",
                risk="MEDIUM", phase="config", catalogue_id="DB-054",
                description="AUDIT_TRAIL=NONE — no audit records are generated.",
                output=f"audit_trail={val}", db_version=self._version,
                command="SELECT VALUE FROM V$PARAMETER WHERE NAME='audit_trail'"
            )

    def check_excessive_privs(self):
        rows = self._q(
            "SELECT GRANTEE,PRIVILEGE FROM DBA_SYS_PRIVS "
            "WHERE PRIVILEGE IN ('DBA','SYSDBA','SYSOPER','CREATE ANY TABLE',"
            "'DROP ANY TABLE','ALTER ANY TABLE','SELECT ANY TABLE',"
            "'EXECUTE ANY PROCEDURE','CREATE ANY PROCEDURE') "
            "AND GRANTEE NOT IN ('SYS','SYSTEM','DBA','IMP_FULL_DATABASE','EXP_FULL_DATABASE')"
        )
        if rows:
            privs = [f"{r[0]}:{r[1]}" for r in rows[:20]]
            self.out.add_finding(
                title="Database: Excessive Oracle System Privileges Granted to Non-SYS Accounts",
                risk="HIGH", phase="permissions", catalogue_id="DB-055",
                description=f"High-privilege grants: {privs}",
                output=str(privs), db_version=self._version,
                command="SELECT GRANTEE,PRIVILEGE FROM DBA_SYS_PRIVS WHERE ..."
            )

    def check_legacy_hashes(self):
        rows = self._q(
            "SELECT USERNAME FROM DBA_USERS "
            "WHERE PASSWORD_VERSIONS LIKE '%10G%' "
            "AND ACCOUNT_STATUS='OPEN'"
        )
        if rows:
            users = [r[0] for r in rows]
            self.out.add_finding(
                title="Database: Oracle Accounts Using Weak 10g DES Password Hash",
                risk="HIGH", phase="auth", catalogue_id="DB-056",
                description=f"Accounts still using MD5/DES 10g hash: {users}",
                output=str(users), db_version=self._version,
                command="SELECT USERNAME FROM DBA_USERS WHERE PASSWORD_VERSIONS LIKE '%10G%'"
            )

    def check_ols(self):
        rows = self._q(
            "SELECT STATUS FROM V$OPTION WHERE PARAMETER='Oracle Label Security'"
        )
        if rows and str(rows[0][0]).upper() != "TRUE":
            self.out.add_finding(
                title="Database: Oracle Label Security (OLS) Not Enabled",
                risk="LOW", phase="config", catalogue_id="DB-057",
                description="Oracle Label Security is not active — row-level access control unavailable.",
                output="OLS_STATUS=FALSE", db_version=self._version,
                command="SELECT STATUS FROM V$OPTION WHERE PARAMETER='Oracle Label Security'",
                validation_required=True,
                validation_notes="OLS may be intentionally omitted; verify with DBA."
            )
            self.out.log_action_item(
                type="vulnerability",
                recommended_tool="Manual Verification",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title="Manual Verification Required — Oracle Label Security Not Enabled",
                description="OLS may be intentionally omitted; verify with DBA.",
                source_finding="Oracle Label Security (OLS) Not Enabled",
                priority="LOW",
                metadata={"validation_notes": "OLS may be intentionally omitted; verify with DBA.",
                          "db_type": self.out.db_type}
            )

    def run(self, db_version: str) -> list:
        return _run_checks("Oracle", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_default_passwords, "auth"),
            (self.check_public_grants, "permissions"),
            (self.check_remote_os_authent, "config"),
            (self.check_utl_file_dir, "config"),
            (self.check_audit_trail, "config"),
            (self.check_excessive_privs, "permissions"),
            (self.check_legacy_hashes, "auth"),
            (self.check_ols, "config"),
        ], self.out)


# ---------------------------------------------------------------------------
# CouchDB Auditor  (HTTP-based)
# ---------------------------------------------------------------------------
class CouchDBAuditor:
    def __init__(self, host, port, username, password, out: AugerOutput,
                 ssl_enabled=False, timeout=10):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._version = ""
        scheme = "https" if ssl_enabled else "http"
        self._base    = f"{scheme}://{host}:{port}"

    def _get(self, path: str, auth=None) -> tuple:
        """Returns (status_code, body_dict)."""
        import urllib.request, urllib.error, base64
        url = self._base + path
        req = urllib.request.Request(url)
        if auth:
            tok = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            req.add_header("Authorization", f"Basic {tok}")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            resp = urllib.request.urlopen(
                req, timeout=self.timeout,
                context=ctx if self.ssl_en else None
            )
            return resp.getcode(), json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}
        except Exception as e:
            return 0, {"_error": str(e)}

    def connect(self) -> bool:
        code, body = self._get("/")
        if code == 200 and "couchdb" in body:
            self._version = body.get("version", "")
            return True
        return False

    def check_version(self):
        self.out.log_step(f"CouchDB version: {self._version}")

    def check_admin_party(self):
        """Admin party = no admins configured, any user is admin."""
        code, body = self._get("/_config/admins")
        if code == 200 and isinstance(body, dict) and len(body) == 0:
            self.out.add_finding(
                title="Database: CouchDB Admin Party Mode — No Admin Accounts Configured",
                risk="CRITICAL", phase="auth", catalogue_id="DB-400",
                description="CouchDB has no admin accounts; any request has full admin access.",
                output="/_config/admins returned empty object",
                db_version=self._version,
                command=f"curl http://{self.host}:{self.port}/_config/admins"
            )

    def check_no_auth(self):
        code, body = self._get("/_all_dbs")
        if code == 200 and isinstance(body, list):
            self.out.add_finding(
                title="Database: CouchDB Unauthenticated Access to /_all_dbs",
                risk="CRITICAL", phase="auth", catalogue_id="DB-450",
                description=f"All databases readable without credentials: {body[:10]}",
                output=str(body[:10]), db_version=self._version,
                command=f"curl http://{self.host}:{self.port}/_all_dbs"
            )

    def check_cluster_config_exposed(self):
        code, body = self._get("/_node/_local/_config")
        if code == 200:
            self.out.add_finding(
                title="Authentication Bypass: CouchDB Node Configuration Exposed Without Authentication",
                risk="HIGH", phase="config", catalogue_id="DB-401",
                description="/_node/_local/_config accessible without auth — reveals bind addresses, ports, secret keys.",
                output=str(body)[:500], db_version=self._version,
                command=f"curl http://{self.host}:{self.port}/_node/_local/_config"
            )

    def check_default_creds(self):
        for user, pwd in _DEFAULT_CREDS.get("couchdb", []):
            code, body = self._get("/_session", auth=(user, pwd))
            if code == 200 and body.get("ok"):
                self.out.add_finding(
                    title=f"Authentication: Default Credentials Accepted",
                    risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                    description=f"Authenticated with default credentials {user}/{pwd}.",
                    output=f"user={user}", db_version=self._version,
                    command=f"curl -u {user}:*** http://{self.host}:{self.port}/_session"
                )
                break

    def run(self, db_version: str) -> list:
        return _run_checks("CouchDB", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_admin_party, "auth"),
            (self.check_no_auth, "auth"),
            (self.check_cluster_config_exposed, "config"),
            (self.check_default_creds, "auth"),
        ], self.out)


# ---------------------------------------------------------------------------
# InfluxDB Auditor  (HTTP v2 API)
# ---------------------------------------------------------------------------
class InfluxDBAuditor:
    def __init__(self, host, port, username, password, out: AugerOutput,
                 ssl_enabled=False, timeout=10, token=""):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self.token    = token
        self._version = ""
        scheme = "https" if ssl_enabled else "http"
        self._base    = f"{scheme}://{host}:{port}"

    def _get(self, path: str, token=None) -> tuple:
        import urllib.request, urllib.error
        url = self._base + path
        req = urllib.request.Request(url)
        if token:
            req.add_header("Authorization", f"Token {token}")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            resp = urllib.request.urlopen(
                req, timeout=self.timeout,
                context=ctx if self.ssl_en else None
            )
            return resp.getcode(), json.loads(resp.read())
        except Exception as e:
            try:
                import urllib.error
                if isinstance(e, urllib.error.HTTPError):
                    return e.code, {}
            except Exception:
                pass
            return 0, {"_error": str(e)}

    def connect(self) -> bool:
        code, body = self._get("/health")
        return code == 200 and body.get("status") == "pass"

    def check_version(self):
        code, body = self._get("/health")
        self._version = body.get("version", "")
        self.out.log_step(f"InfluxDB version: {self._version}")

    def check_setup_incomplete(self):
        code, body = self._get("/api/v2/setup")
        if code == 200 and not body.get("allowed", True):
            self.out.add_finding(
                title="Database: InfluxDB 2.x Initial Setup Not Completed",
                risk="CRITICAL", phase="auth", catalogue_id="DB-420",
                description="InfluxDB setup endpoint indicates initial admin setup has not been completed.",
                output=str(body)[:300], db_version=self._version,
                command=f"curl http://{self.host}:{self.port}/api/v2/setup"
            )

    def check_no_auth(self):
        code, body = self._get("/api/v2/authorizations")
        if code == 200:
            self.out.add_finding(
                title="Database: InfluxDB 2.x Authorizations Endpoint Accessible Without Token",
                risk="CRITICAL", phase="auth", catalogue_id="DB-450",
                description="Token authorizations accessible without authentication.",
                output=str(body)[:300], db_version=self._version,
                command=f"curl http://{self.host}:{self.port}/api/v2/authorizations"
            )

    def check_buckets_exposed(self):
        code, body = self._get("/api/v2/buckets")
        if code == 200 and "buckets" in body:
            buckets = [b.get("name", "") for b in body.get("buckets", [])]
            self.out.add_finding(
                title="Authentication Bypass: InfluxDB 2.x Buckets Exposed Without Authentication",
                risk="HIGH", phase="permissions", catalogue_id="DB-421",
                description=f"Bucket listing accessible without token: {buckets[:10]}",
                output=str(buckets[:10]), db_version=self._version,
                command=f"curl http://{self.host}:{self.port}/api/v2/buckets"
            )

    def check_default_creds(self):
        for user, pwd in _DEFAULT_CREDS.get("influxdb", []):
            import base64
            import urllib.request, urllib.error
            url = self._base + "/api/v2/signin"
            req = urllib.request.Request(url, method="POST")
            tok = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            req.add_header("Authorization", f"Basic {tok}")
            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                if resp.getcode() in (200, 204):
                    self.out.add_finding(
                        title=f"InfluxDB Default Credentials: {user}/{pwd}",
                        risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                        description=f"Authenticated with default credentials {user}/{pwd}.",
                        output=f"user={user}", db_version=self._version,
                        command=f"curl -u {user}:*** -X POST {self._base}/api/v2/signin"
                    )
                    break
            except Exception:
                pass

    def run(self, db_version: str) -> list:
        return _run_checks("InfluxDB", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_setup_incomplete, "auth"),
            (self.check_no_auth, "auth"),
            (self.check_buckets_exposed, "permissions"),
            (self.check_default_creds, "auth"),
        ], self.out)


# ---------------------------------------------------------------------------
# Neo4j Auditor  (Bolt protocol via neo4j driver)
# ---------------------------------------------------------------------------
class Neo4jAuditor:
    def __init__(self, host, port, username, password, out: AugerOutput,
                 ssl_enabled=False, timeout=10):
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.out      = out
        self.ssl_en   = ssl_enabled
        self.timeout  = timeout
        self._driver  = None
        self._version = ""

    def connect(self) -> bool:
        neo4j = _try_import("neo4j")
        if not neo4j:
            return False
        try:
            from neo4j import GraphDatabase
            scheme = "bolt+s" if self.ssl_en else "bolt"
            uri = f"{scheme}://{self.host}:{self.port}"
            self._driver = GraphDatabase.driver(
                uri, auth=(self.username, self.password),
                connection_timeout=self.timeout,
                max_connection_lifetime=30
            )
            with self._driver.session() as sess:
                sess.run("RETURN 1")
            return True
        except Exception as e:
            _console.log(f"Neo4j connect failed: {e}", "ERROR")
            return False

    def _run(self, cypher: str) -> list:
        try:
            with self._driver.session() as sess:
                result = sess.run(cypher)
                return list(result)
        except Exception as e:
            self.out.log_error("neo4j-query", str(e))
            return []

    def check_version(self):
        rows = self._run("CALL dbms.components() YIELD name, versions, edition")
        for row in rows:
            ver = row["versions"][0] if row["versions"] else ""
            self._version = ver
            self.out.log_step(f"Neo4j version: {ver} edition: {row['edition']}")

    def check_config_exposed(self):
        sensitive_keys = {
            "dbms.security.auth_enabled": ("FALSE", "CRITICAL", "DB-430", "Neo4j authentication disabled."),
            "dbms.connector.bolt.enabled": ("TRUE", None, None, None),
        }
        rows = self._run("CALL dbms.listConfig() YIELD name, value")
        config = {row["name"]: row["value"] for row in rows}
        auth_val = str(config.get("dbms.security.auth_enabled", "true")).lower()
        if auth_val in ("false", "0", "no"):
            self.out.add_finding(
                title="Authentication Bypass: Neo4j Authentication Disabled (dbms.security.auth_enabled=false)",
                risk="CRITICAL", phase="auth", catalogue_id="DB-430",
                description="dbms.security.auth_enabled=false — all connections are unauthenticated.",
                output=f"auth_enabled={auth_val}", db_version=self._version,
                command="CALL dbms.listConfig() YIELD name,value WHERE name CONTAINS 'auth'"
            )
        # Check if cluster info is exposed externally
        if config.get("dbms.mode", "").upper() in ("CORE", "READ_REPLICA", "ARBITER"):
            self.out.add_finding(
                title="Neo4j Cluster Mode Detected — Verify Firewall Isolation",
                risk="MEDIUM", phase="config", catalogue_id="DB-431",
                description=f"Neo4j running in cluster mode ({config.get('dbms.mode')}); cluster discovery ports may be exposed.",
                output=f"mode={config.get('dbms.mode')}", db_version=self._version,
                validation_required=True,
                validation_notes="Confirm cluster ports 5000/6000/7000 are firewalled."
            )
            self.out.log_action_item(
                type="vulnerability",
                recommended_tool="Manual Verification",
                target=f"{self.out.host}:{self.out.port}",
                ip=self.out.host, port=self.out.port,
                title="Manual Verification Required — Neo4j Cluster Firewall Isolation",
                description="Confirm cluster ports 5000/6000/7000 are firewalled.",
                source_finding="Neo4j Cluster Mode Detected — Verify Firewall Isolation",
                priority="MEDIUM",
                metadata={"validation_notes": "Confirm cluster ports 5000/6000/7000 are firewalled.",
                          "db_type": self.out.db_type}
            )

    def check_default_creds(self):
        neo4j = _try_import("neo4j")
        if not neo4j:
            return
        from neo4j import GraphDatabase
        scheme = "bolt+s" if self.ssl_en else "bolt"
        uri = f"{scheme}://{self.host}:{self.port}"
        for user, pwd in _DEFAULT_CREDS.get("neo4j", []):
            if user == self.username and pwd == self.password:
                continue
            try:
                d = GraphDatabase.driver(uri, auth=(user, pwd),
                                         connection_timeout=5, max_connection_lifetime=10)
                with d.session() as sess:
                    sess.run("RETURN 1")
                d.close()
                self.out.add_finding(
                    title=f"Neo4j Default Credentials: {user}/{pwd}",
                    risk="CRITICAL", phase="auth", catalogue_id="DB-006",
                    description=f"Neo4j accepted default credentials {user}/{pwd}.",
                    output=f"user={user}", db_version=self._version,
                    command=f"cypher-shell -a {uri} -u {user} -p *** 'RETURN 1'"
                )
                break
            except Exception:
                pass

    def check_procedures(self):
        dangerous = {"apoc.cypher.runFile", "apoc.cypher.run",
                     "dbms.security.createUser", "dbms.security.deleteUser"}
        rows = self._run("CALL dbms.procedures() YIELD name, rolesExecution")
        for row in rows:
            name = row.get("name", "")
            roles = row.get("rolesExecution") or []
            if name in dangerous and (not roles or "PUBLIC" in roles):
                self.out.add_finding(
                    title=f"Database: Neo4j Dangerous Procedure Publicly Accessible: {name}",
                    risk="HIGH", phase="permissions", catalogue_id="DB-432",
                    description=f"Procedure '{name}' callable by PUBLIC role — may allow code execution or privilege escalation.",
                    output=f"procedure={name} roles={roles}", db_version=self._version,
                    command="CALL dbms.procedures() YIELD name, rolesExecution"
                )

    def run(self, db_version: str) -> list:
        return _run_checks("Neo4j", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_config_exposed, "config"),
            (self.check_default_creds, "auth"),
            (self.check_procedures, "permissions"),
        ], self.out)

    def close(self):
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Memcached Auditor  (raw TCP text protocol)
# ---------------------------------------------------------------------------
class MemcachedAuditor:
    def __init__(self, host, port, out: AugerOutput, timeout=10):
        self.host    = host
        self.port    = port
        self.out     = out
        self.timeout = timeout
        self._sock   = None
        self._version = ""

    def _send(self, cmd: str) -> str:
        try:
            self._sock.sendall((cmd + "\r\n").encode())
            data = b""
            self._sock.settimeout(3.0)
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"END\r\n" in data or b"ERROR\r\n" in data or b"\r\n" in data:
                    break
            return data.decode(errors="replace")
        except Exception:
            return ""

    def connect(self) -> bool:
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            resp = self._send("version")
            if resp.startswith("VERSION"):
                self._version = resp.split()[-1].strip()
                return True
            return False
        except Exception as e:
            _console.log(f"Memcached connect failed: {e}", "ERROR")
            return False

    def check_version(self):
        self.out.log_step(f"Memcached version: {self._version}")

    def check_no_sasl_auth(self):
        resp = self._send("stats settings")
        if "auth_enabled_sasl" in resp:
            for line in resp.splitlines():
                if "auth_enabled_sasl" in line:
                    val = line.split()[-1].strip().lower()
                    if val in ("no", "false", "0"):
                        self.out.add_finding(
                            title="Database: Memcached SASL Authentication Disabled",
                            risk="CRITICAL", phase="auth", catalogue_id="DB-440",
                            description="Memcached has no authentication; any client can read/write all cached data.",
                            output=line, db_version=self._version,
                            command=f"echo 'stats settings' | nc {self.host} {self.port}"
                        )
        else:
            self.out.add_finding(
                title="Database: Memcached No Authentication (SASL Not Supported)",
                risk="CRITICAL", phase="auth", catalogue_id="DB-440",
                description="Memcached instance accessible without any authentication.",
                output=resp[:200], db_version=self._version,
                command=f"echo 'stats' | nc {self.host} {self.port}"
            )

    def check_stats_exposure(self):
        resp = self._send("stats")
        if resp.startswith("STAT"):
            sensitive_keys = []
            for line in resp.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] in ("pid", "uptime", "rusage_user",
                                                      "total_connections", "curr_items", "bytes"):
                    sensitive_keys.append(line.strip())
            if sensitive_keys:
                self.out.add_finding(
                    title="Database: Memcached Runtime Statistics Accessible Without Authentication",
                    risk="HIGH", phase="config", catalogue_id="DB-441",
                    description="STATS command reveals process ID, memory usage, connection counts.",
                    output="\n".join(sensitive_keys[:10]), db_version=self._version,
                    command=f"echo 'stats' | nc {self.host} {self.port}"
                )

    def check_data_access(self):
        resp = self._send("stats slabs")
        slab_ids = []
        for line in resp.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "STAT":
                try:
                    slab_id = int(parts[1].split(":")[0])
                    if slab_id not in slab_ids:
                        slab_ids.append(slab_id)
                except ValueError:
                    pass
        if slab_ids:
            sample_resp = self._send(f"stats cachedump {slab_ids[0]} 3")
            if "ITEM" in sample_resp:
                key_names = [ln.split()[1] for ln in sample_resp.splitlines()
                             if ln.startswith("ITEM")]
                self.out.add_finding(
                    title="Database: Memcached Cached Data Keys Enumerable Without Authentication",
                    risk="HIGH", phase="data", catalogue_id="DB-442",
                    description=f"Sample cached keys: {key_names[:5]}",
                    output=sample_resp[:400], db_version=self._version,
                    validation_required=True,
                    validation_notes="Review key names for PII/session tokens/API keys.",
                    command=f"echo 'stats cachedump {slab_ids[0]} 3' | nc {self.host} {self.port}"
                )
                self.out.log_action_item(
                    type="vulnerability",
                    recommended_tool="Manual Verification",
                    target=f"{self.out.host}:{self.out.port}",
                    ip=self.out.host, port=self.out.port,
                    title="Manual Verification Required — Memcached Data Key Enumeration",
                    description="Review key names for PII/session tokens/API keys.",
                    source_finding="Database: Memcached Cached Data Keys Enumerable Without Authentication",
                    priority="HIGH",
                    metadata={"validation_notes": "Review key names for PII/session tokens/API keys.",
                              "db_type": self.out.db_type}
                )

    def run(self, db_version: str) -> list:
        return _run_checks("Memcached", self.host, self.port, [
            (self.check_version, "version"),
            (self.check_no_sasl_auth, "auth"),
            (self.check_stats_exposure, "config"),
            (self.check_data_access, "data"),
        ], self.out)

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# DynamoDB Auditor — AWS managed key-value store (control-plane audit)
# Fixes the 2026-06-11 review HIGH finding: dynamodb was advertised in
# argparse + docstring but no auditor class existed.
#
# Audits the AWS DynamoDB control plane (not data plane): table encryption-
# at-rest, point-in-time recovery, stream destinations, deletion protection,
# resource-based policy public access. Auger does NOT modify the DB.
# ---------------------------------------------------------------------------
class DynamoDBAuditor:
    """Authenticated DynamoDB control-plane audit via boto3.

    Requires either AWS environment credentials (AWS_ACCESS_KEY_ID +
    AWS_SECRET_ACCESS_KEY) or a profile (--aws-profile). Region selected
    via --aws-region (defaults to us-east-1).
    """
    def __init__(self, *, aws_profile: str, aws_region: str,
                 out: "AugerOutput", timeout: int = 30):
        self.profile  = aws_profile or ""
        self.region   = aws_region or "us-east-1"
        self.out      = out
        self.timeout  = max(int(timeout), 30)
        self._client  = None
        self._version = "AWS DynamoDB (managed)"

    def connect(self) -> bool:
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            _console.error("boto3 not installed (pip install boto3 --break-system-packages).")
            return False
        try:
            cfg = Config(connect_timeout=self.timeout, read_timeout=self.timeout,
                          retries={"max_attempts": 2})
            if self.profile:
                sess = boto3.Session(profile_name=self.profile, region_name=self.region)
            else:
                sess = boto3.Session(region_name=self.region)
            self._client = sess.client("dynamodb", config=cfg)
            # Ping
            self._client.list_tables(Limit=1)
            return True
        except Exception as exc:
            _console.error(f"DynamoDB connect failed: {exc}")
            return False

    def run(self, db_version: str) -> list:
        return _run_checks("DynamoDB", self.region, 0, [
            (self._check_region_tables, "inventory"),
            (self._check_encryption_at_rest, "encryption"),
            (self._check_pitr, "backup"),
            (self._check_streams, "streams"),
            (self._check_deletion_protection, "protection"),
            (self._check_resource_policies, "iam"),
        ], self.out)

    def _list_tables(self) -> list[str]:
        try:
            tables, token = [], None
            while True:
                kw = {"Limit": 100}
                if token: kw["ExclusiveStartTableName"] = token
                resp = self._client.list_tables(**kw)
                tables.extend(resp.get("TableNames", []))
                token = resp.get("LastEvaluatedTableName")
                if not token: break
            return tables
        except Exception as exc:
            self.out.add_finding(
                title="DynamoDB ListTables failed",
                risk="INFO", phase="inventory", catalogue_id="DB-DDB-000",
                description=f"Could not enumerate tables: {exc}",
                output=str(exc), command="dynamodb:ListTables")
            return []

    def _describe(self, table: str) -> dict:
        try: return self._client.describe_table(TableName=table).get("Table", {})
        except Exception: return {}

    def _check_region_tables(self) -> None:
        tables = self._list_tables()
        self.out.add_finding(
            title=f"DynamoDB tables in region {self.region}: {len(tables)}",
            risk="INFO", phase="inventory", catalogue_id="DB-DDB-001",
            description=f"Discovered {len(tables)} tables: {tables[:10]}{'…' if len(tables)>10 else ''}",
            output="\n".join(tables[:200]),
            command="aws dynamodb list-tables")

    def _check_encryption_at_rest(self) -> None:
        for t in self._list_tables():
            d = self._describe(t)
            sse = d.get("SSEDescription") or {}
            status = sse.get("Status", "DISABLED")
            kms_type = sse.get("SSEType", "")
            if status != "ENABLED":
                self.out.add_finding(
                    title=f"DynamoDB Table {t}: Encryption-at-rest not enabled",
                    risk="HIGH", phase="encryption", catalogue_id="DB-DDB-010",
                    description=("Encryption-at-rest is disabled. AWS owns the encryption "
                                  "key — fine for non-sensitive — but for regulated data, "
                                  "enable AWS-KMS-CMK so the org controls key rotation."),
                    output=f"Table={t} SSE.Status={status}",
                    command=f"aws dynamodb describe-table --table-name {t}")
            elif kms_type != "KMS":
                self.out.add_finding(
                    title=f"DynamoDB Table {t}: SSE enabled but using AWS-managed key",
                    risk="LOW", phase="encryption", catalogue_id="DB-DDB-011",
                    description=("SSE is enabled but the key is AWS-owned (default). "
                                  "For sensitive workloads, use a customer-managed KMS key "
                                  "to control key policy and rotation."),
                    output=f"Table={t} SSEType={kms_type}",
                    command=f"aws dynamodb describe-table --table-name {t}")

    def _check_pitr(self) -> None:
        for t in self._list_tables():
            try:
                resp = self._client.describe_continuous_backups(TableName=t)
                pitr = ((resp.get("ContinuousBackupsDescription") or {})
                        .get("PointInTimeRecoveryDescription") or {})
                if pitr.get("PointInTimeRecoveryStatus") != "ENABLED":
                    self.out.add_finding(
                        title=f"DynamoDB Table {t}: Point-in-Time Recovery disabled",
                        risk="MEDIUM", phase="backup", catalogue_id="DB-DDB-020",
                        description="PITR allows restore to any second in the last 35 days. "
                                    "Without it, ransom/corruption events are unrecoverable "
                                    "beyond on-demand backups.",
                        output=f"Table={t} PITR={pitr.get('PointInTimeRecoveryStatus','DISABLED')}",
                        command=f"aws dynamodb describe-continuous-backups --table-name {t}")
            except Exception:
                pass

    def _check_streams(self) -> None:
        for t in self._list_tables():
            d = self._describe(t)
            if (d.get("StreamSpecification") or {}).get("StreamEnabled"):
                # Streams enabled — check if a Lambda/Kinesis consumer is wired
                self.out.add_finding(
                    title=f"DynamoDB Table {t}: Stream enabled",
                    risk="INFO", phase="streams", catalogue_id="DB-DDB-030",
                    description="DynamoDB stream is enabled. Ensure consumer (Lambda / KCL) "
                                "has appropriate IAM scope; streams carry full item data.",
                    output=f"Table={t} ViewType={d['StreamSpecification'].get('StreamViewType')}",
                    command=f"aws dynamodb describe-table --table-name {t}")

    def _check_deletion_protection(self) -> None:
        for t in self._list_tables():
            d = self._describe(t)
            if not d.get("DeletionProtectionEnabled", False):
                self.out.add_finding(
                    title=f"DynamoDB Table {t}: Deletion protection disabled",
                    risk="LOW", phase="protection", catalogue_id="DB-DDB-040",
                    description=("Deletion protection prevents accidental DropTable via IAM. "
                                  "Enable for any production / regulated table."),
                    output=f"Table={t} DeletionProtection=False",
                    command=f"aws dynamodb describe-table --table-name {t}")

    def _check_resource_policies(self) -> None:
        for t in self._list_tables():
            try:
                resp = self._client.get_resource_policy(
                    ResourceArn=self._describe(t).get("TableArn", ""))
                policy = resp.get("Policy", "{}")
                import json as _j
                pol = _j.loads(policy)
                for stmt in pol.get("Statement", []):
                    pr = stmt.get("Principal", {})
                    if pr == "*" or (isinstance(pr, dict) and pr.get("AWS") == "*"):
                        self.out.add_finding(
                            title=f"DynamoDB Table {t}: Resource policy grants Principal=*",
                            risk="CRITICAL", phase="iam", catalogue_id="DB-DDB-050",
                            description="Resource-based policy allows any AWS principal. "
                                        "This effectively makes the table public to every "
                                        "AWS account if the Condition block doesn't restrict.",
                            output=f"Table={t}\nPolicy: {policy[:2000]}",
                            command=f"aws dynamodb get-resource-policy --resource-arn ...")
            except self._client.exceptions.PolicyNotFoundException:
                continue
            except Exception:
                continue

    def close(self) -> None:
        self._client = None


# ---------------------------------------------------------------------------
# RDS Auditor — AWS managed RDS / Aurora control-plane audit
# 2026-06-11 review: native boto3 audit complementing the in-engine audits.
# Audits RDS instances (encryption-at-rest, backups, publicly-accessible,
# parameter group drift, IAM auth) and the cluster-level Aurora settings.
# ---------------------------------------------------------------------------
class RDSAuditor:
    """Authenticated AWS RDS / Aurora control-plane audit via boto3.

    Requires AWS credentials (env or --aws-profile). Region from --aws-region.
    Does NOT connect to the underlying DB engine — Auger's other auditors
    handle that. This class focuses on the AWS control-plane surface."""

    def __init__(self, *, aws_profile: str, aws_region: str,
                  out: "AugerOutput", timeout: int = 30):
        self.profile = aws_profile or ""
        self.region  = aws_region or "us-east-1"
        self.out     = out
        self.timeout = max(int(timeout), 30)
        self._rds    = None
        self._cloudwatch = None
        self._version = "AWS RDS (managed)"

    def connect(self) -> bool:
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            _console.error("boto3 not installed (pip install boto3 --break-system-packages).")
            return False
        try:
            cfg = Config(connect_timeout=self.timeout, read_timeout=self.timeout,
                          retries={"max_attempts": 2})
            sess = (boto3.Session(profile_name=self.profile, region_name=self.region)
                     if self.profile else boto3.Session(region_name=self.region))
            self._rds = sess.client("rds", config=cfg)
            self._cloudwatch = sess.client("cloudwatch", config=cfg)
            # Ping
            self._rds.describe_db_instances(MaxRecords=20)
            return True
        except Exception as exc:
            _console.error(f"RDS connect failed: {exc}")
            return False

    def run(self, db_version: str) -> list:
        _console.log(f"[inventory] Enumerating RDS instances and clusters in {self.region}...", "INFO")
        instances = self._list_instances()
        clusters  = self._list_clusters()
        _console.log(f"[inventory] Found {len(instances)} instances, {len(clusters)} clusters", "SUCCESS")
        self._check_inventory(instances, clusters)
        phases = ["inventory"]
        for idx, inst in enumerate(instances, 1):
            iid = inst.get("DBInstanceIdentifier", "?")
            _console.log(f"[instance] Auditing instance {idx}/{len(instances)}: {iid}...", "INFO")
            self._check_instance(inst)
            _console.log(f"[instance] {iid} — done", "INFO")
        phases.append("instance")
        for idx, cluster in enumerate(clusters, 1):
            cid = cluster.get("DBClusterIdentifier", "?")
            _console.log(f"[cluster] Auditing cluster {idx}/{len(clusters)}: {cid}...", "INFO")
            self._check_cluster(cluster)
            _console.log(f"[cluster] {cid} — done", "INFO")
        phases.append("cluster")
        _console.log("[snapshots] Checking for publicly accessible snapshots...", "INFO")
        self._check_snapshots()
        _console.log("[snapshots] Snapshot audit — done", "INFO")
        phases.append("snapshots")
        return phases

    # ── Discovery ──

    def _list_instances(self) -> list:
        instances = []
        try:
            paginator = self._rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                instances.extend(page.get("DBInstances", []))
        except Exception as exc:
            self.out.add_finding(
                title="RDS DescribeDBInstances failed",
                risk="INFO", phase="inventory", catalogue_id="DB-RDS-000",
                description=f"Could not enumerate instances: {exc}",
                output=str(exc), command="aws rds describe-db-instances")
        return instances

    def _list_clusters(self) -> list:
        clusters = []
        try:
            paginator = self._rds.get_paginator("describe_db_clusters")
            for page in paginator.paginate():
                clusters.extend(page.get("DBClusters", []))
        except Exception:
            pass
        return clusters

    def _check_inventory(self, instances: list, clusters: list) -> None:
        self.out.add_finding(
            title=f"RDS inventory: {len(instances)} instances, {len(clusters)} clusters",
            risk="INFO", phase="inventory", catalogue_id="DB-RDS-001",
            description=(f"Discovered {len(instances)} DB instances and {len(clusters)} "
                          f"Aurora clusters in region {self.region}."),
            output="\n".join(i.get("DBInstanceIdentifier", "?") for i in instances[:20]),
            command=f"aws rds describe-db-instances --region {self.region}")

    # ── Per-instance checks ──

    def _check_instance(self, inst: dict) -> None:
        ident = inst.get("DBInstanceIdentifier", "?")
        engine = inst.get("Engine", "?")
        engine_ver = inst.get("EngineVersion", "?")

        # 1. PubliclyAccessible
        if inst.get("PubliclyAccessible"):
            ep = (inst.get("Endpoint") or {}).get("Address", "?")
            self.out.add_finding(
                title=f"RDS instance {ident} is PubliclyAccessible",
                risk="HIGH", phase="instance", catalogue_id="DB-RDS-020",
                description=("DB endpoint is reachable from the public internet. "
                              "Even with SG restrictions, this surface invites "
                              "brute-force, version-exploit, and side-channel attacks "
                              "against the engine."),
                output=f"DB={ident} Engine={engine} Endpoint={ep}",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")

        # 2. StorageEncrypted
        if not inst.get("StorageEncrypted"):
            self.out.add_finding(
                title=f"RDS instance {ident}: storage NOT encrypted at rest",
                risk="HIGH", phase="instance", catalogue_id="DB-RDS-021",
                description=("StorageEncrypted=false — snapshots and underlying "
                              "disks are unencrypted. Encryption cannot be enabled "
                              "in-place; instance must be recreated from an "
                              "encrypted snapshot copy."),
                output=f"DB={ident} StorageEncrypted=False",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")

        # 3. BackupRetentionPeriod
        retention = inst.get("BackupRetentionPeriod", 0) or 0
        if retention == 0:
            self.out.add_finding(
                title=f"RDS instance {ident}: automated backups DISABLED",
                risk="HIGH", phase="instance", catalogue_id="DB-RDS-022",
                description=("BackupRetentionPeriod=0 — automated backups are "
                              "disabled. Recovery from ransom / accidental drop "
                              "events is impossible without manual snapshots."),
                output=f"DB={ident} BackupRetentionPeriod=0",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")
        elif retention < 7:
            self.out.add_finding(
                title=f"RDS instance {ident}: BackupRetentionPeriod={retention}d (<7)",
                risk="MEDIUM", phase="instance", catalogue_id="DB-RDS-023",
                description=("BackupRetentionPeriod is set but below the 7-day "
                              "minimum recommended for recovery from delayed-"
                              "discovery incidents."),
                output=f"DB={ident} BackupRetentionPeriod={retention}",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")

        # 4. DeletionProtection
        if not inst.get("DeletionProtection", False):
            self.out.add_finding(
                title=f"RDS instance {ident}: deletion protection disabled",
                risk="MEDIUM", phase="instance", catalogue_id="DB-RDS-024",
                description=("Deletion protection prevents accidental DropTable / "
                              "DeleteInstance via IAM. Enable for any production / "
                              "regulated instance."),
                output=f"DB={ident} DeletionProtection=False",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")

        # 5. IAMDatabaseAuthenticationEnabled (PG/MySQL only)
        if engine.startswith(("mysql", "postgres", "mariadb", "aurora")) \
                and not inst.get("IAMDatabaseAuthenticationEnabled"):
            self.out.add_finding(
                title=f"RDS instance {ident}: IAM database authentication not enabled",
                risk="LOW", phase="instance", catalogue_id="DB-RDS-025",
                description=("IAMDatabaseAuthenticationEnabled=false. IAM auth "
                              "lets you grant DB access via IAM roles instead of "
                              "long-lived passwords, simplifying credential rotation."),
                output=f"DB={ident} Engine={engine}",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")

        # 6. PerformanceInsights + CloudWatch Logs export
        if not inst.get("PerformanceInsightsEnabled"):
            self.out.add_finding(
                title=f"RDS instance {ident}: Performance Insights disabled",
                risk="INFO", phase="instance", catalogue_id="DB-RDS-026",
                description=("Performance Insights enables retrospective analysis "
                              "of query load — useful for diagnosing suspicious "
                              "query patterns."),
                output=f"DB={ident}",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")
        if not inst.get("EnabledCloudwatchLogsExports"):
            self.out.add_finding(
                title=f"RDS instance {ident}: no CloudWatch log exports configured",
                risk="MEDIUM", phase="instance", catalogue_id="DB-RDS-027",
                description=("EnabledCloudwatchLogsExports is empty — DB logs are "
                              "not shipped to CloudWatch. PCI DSS 10.x and HIPAA "
                              "audit requirements typically require centralised "
                              "log retention."),
                output=f"DB={ident}",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")

        # 7. AutoMinorVersionUpgrade
        if not inst.get("AutoMinorVersionUpgrade", True):
            self.out.add_finding(
                title=f"RDS instance {ident}: AutoMinorVersionUpgrade disabled",
                risk="LOW", phase="instance", catalogue_id="DB-RDS-028",
                description=("AutoMinorVersionUpgrade=false — minor patches that "
                              "include CVE fixes will NOT auto-apply. Verify a "
                              "monthly patch process is in place."),
                output=f"DB={ident}",
                command=f"aws rds describe-db-instances --db-instance-identifier {ident}")

    # ── Per-cluster checks (Aurora) ──

    def _check_cluster(self, cluster: dict) -> None:
        ident = cluster.get("DBClusterIdentifier", "?")
        if not cluster.get("StorageEncrypted"):
            self.out.add_finding(
                title=f"Aurora cluster {ident}: storage NOT encrypted at rest",
                risk="HIGH", phase="cluster", catalogue_id="DB-RDS-040",
                description=("Aurora cluster has StorageEncrypted=false. As with "
                              "RDS instances, encryption cannot be enabled in-place."),
                output=f"Cluster={ident}",
                command=f"aws rds describe-db-clusters --db-cluster-identifier {ident}")
        retention = cluster.get("BackupRetentionPeriod", 0) or 0
        if retention < 7:
            self.out.add_finding(
                title=f"Aurora cluster {ident}: BackupRetentionPeriod={retention}d (<7)",
                risk="MEDIUM", phase="cluster", catalogue_id="DB-RDS-041",
                description="See DB-RDS-023.",
                output=f"Cluster={ident} BackupRetentionPeriod={retention}",
                command=f"aws rds describe-db-clusters --db-cluster-identifier {ident}")
        if not cluster.get("DeletionProtection", False):
            self.out.add_finding(
                title=f"Aurora cluster {ident}: deletion protection disabled",
                risk="MEDIUM", phase="cluster", catalogue_id="DB-RDS-042",
                description="See DB-RDS-024.",
                output=f"Cluster={ident} DeletionProtection=False",
                command=f"aws rds describe-db-clusters --db-cluster-identifier {ident}")

    # ── Snapshots check ──

    def _check_snapshots(self) -> None:
        try:
            paginator = self._rds.get_paginator("describe_db_snapshots")
            for page in paginator.paginate(SnapshotType="manual"):
                for snap in page.get("DBSnapshots", []):
                    if not snap.get("Encrypted"):
                        self.out.add_finding(
                            title=f"RDS snapshot {snap.get('DBSnapshotIdentifier')} NOT encrypted",
                            risk="HIGH", phase="snapshots", catalogue_id="DB-RDS-050",
                            description="Manual snapshot is unencrypted; if shared "
                                        "or copied across accounts, the underlying "
                                        "data is exposed.",
                            output=str({k: snap.get(k) for k in
                                         ("DBSnapshotIdentifier","Encrypted","Status")}),
                            command="aws rds describe-db-snapshots --snapshot-type manual")
        except Exception:
            pass

    def close(self) -> None:
        self._rds = None
        self._cloudwatch = None


# ---------------------------------------------------------------------------
# Generic network / TLS phase (all database types)
# ---------------------------------------------------------------------------
def run_network_phase(host: str, port: int, out: AugerOutput) -> None:
    _console.status("network", label="Network / TLS", step="tls_probe", status="running")
    tls = _tls_info(host, port)
    if not tls["tls_ok"]:
        pass  # DB-specific auditors report no-TLS from config checks
    else:
        if tls.get("weak_version"):
            out.add_finding(
                title="Insecure Protocol Detected: Weak TLS Version (TLS 1.0 or TLS 1.1)",
                risk="MEDIUM", phase="network", catalogue_id="DB-002",
                description=f"Database negotiated {tls['version']} which is deprecated.",
                output=f"TLS version={tls['version']} cipher={tls['cipher']}",
                command=f"openssl s_client -connect {host}:{port}"
            )
        if tls.get("weak_cipher"):
            out.add_finding(
                title="SSL/TLS Ciphers: Weak Cipher Suites Accepted",
                risk="MEDIUM", phase="network", catalogue_id="DB-017",
                description=f"Weak cipher suite negotiated: {tls['cipher']}",
                output=f"cipher={tls['cipher']} version={tls['version']}",
                command=f"nmap --script ssl-enum-ciphers -p {port} {host}"
            )
        if tls.get("self_signed"):
            out.add_finding(
                title="SSL/TLS Certificate: Self-Signed or Expired TLS Certificate",
                risk="MEDIUM", phase="network", catalogue_id="DB-003",
                description=f"Self-signed certificate: subject={tls['cert_subject']} issuer={tls['cert_issuer']}",
                output=f"subject={tls['cert_subject']} issuer={tls['cert_issuer']}",
                command=f"openssl s_client -connect {host}:{port} | openssl x509 -noout -text"
            )
        if tls.get("cert_expired"):
            out.add_finding(
                title="SSL/TLS Certificate: Expired TLS Certificate",
                risk="MEDIUM", phase="network", catalogue_id="DB-003",
                description="The database TLS certificate has expired.",
                output=f"cert_subject={tls['cert_subject']}",
                command=f"openssl s_client -connect {host}:{port} | openssl x509 -noout -dates"
            )


# ---------------------------------------------------------------------------
# Sensitive data column scan  (universal)
# ---------------------------------------------------------------------------
_SENSITIVE_PATTERNS = re.compile(
    r'(ssn|social.?security|credit.?card|card.?number|cvv|ccv|cvc|pan|'
    r'password|passwd|pwd|secret|token|api.?key|auth.?key|private.?key|'
    r'dob|date.?of.?birth|birth.?date|phone|email|address|'
    r'health|diagnosis|medical|patient|prescription|'
    r'salary|income|bank.?account|routing.?number|iban|swift)',
    re.IGNORECASE
)

def scan_sensitive_columns_mysql(conn, out: AugerOutput, db_version: str) -> None:
    try:
        import pymysql
        with conn.cursor() as cur:
            cur.execute(
                "SELECT table_schema, table_name, column_name, data_type "
                "FROM information_schema.columns "
                "WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') "
                "ORDER BY table_schema, table_name, column_name"
            )
            rows = cur.fetchall()
        hits = [(r[0], r[1], r[2], r[3]) for r in rows
                if _SENSITIVE_PATTERNS.search(r[2])]
        if hits:
            summary = [f"{r[0]}.{r[1]}.{r[2]}" for r in hits[:20]]
            out.add_finding(
                title="Sensitive Data Columns Identified (Potential PII/PHI/PCI Scope)",
                risk="INFO", phase="data", catalogue_id="DB-015",
                description=f"Columns with sensitive-pattern names found: {summary}",
                output="\n".join(summary[:20]),
                command="SELECT table_schema,table_name,column_name FROM information_schema.columns",
                db_version=db_version
            )
    except Exception as e:
        out.log_error("sensitive_columns_mysql", str(e))


def scan_sensitive_columns_pg(conn, out: AugerOutput, db_version: str) -> None:
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT table_schema, table_name, column_name, data_type "
                "FROM information_schema.columns "
                "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
                "ORDER BY table_schema, table_name, column_name"
            )
            rows = cur.fetchall()
        hits = [r for r in rows if _SENSITIVE_PATTERNS.search(r[2])]
        if hits:
            summary = [f"{r[0]}.{r[1]}.{r[2]}" for r in hits[:20]]
            out.add_finding(
                title="Sensitive Data Columns Identified (Potential PII/PHI/PCI Scope)",
                risk="INFO", phase="data", catalogue_id="DB-015",
                description=f"Columns with sensitive-pattern names: {summary}",
                output="\n".join(summary[:20]),
                command="SELECT table_schema,table_name,column_name FROM information_schema.columns",
                db_version=db_version
            )
    except Exception as e:
        out.log_error("sensitive_columns_pg", str(e))


# ---------------------------------------------------------------------------
# Schema enumeration helpers
# ---------------------------------------------------------------------------
_SENSITIVE_COL_RE = _SENSITIVE_PATTERNS  # alias used by schema enumerators


def _col_sensitive(name: str) -> bool:
    return bool(_SENSITIVE_COL_RE.search(name))


def enumerate_schema_mysql(conn, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": out.db_type, "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        import pymysql
        with conn.cursor() as cur:
            cur.execute(
                "SELECT TABLE_SCHEMA,TABLE_NAME,TABLE_ROWS,COLUMN_NAME,DATA_TYPE,"
                "IS_NULLABLE,COLUMN_KEY "
                "FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema',"
                "'performance_schema','sys') "
                "ORDER BY TABLE_SCHEMA,TABLE_NAME,ORDINAL_POSITION"
            )
            rows = cur.fetchall()
        dbs: dict = {}
        for (db, tbl, row_count, col, dtype, nullable, key) in rows:
            dbs.setdefault(db, {})
            dbs[db].setdefault(tbl, {"row_count": row_count or 0, "columns": []})
            dbs[db][tbl]["columns"].append({
                "name": col, "type": dtype,
                "nullable": nullable == "YES", "key": key or "",
                "sensitive": _col_sensitive(col)
            })
        for db_name, tables in dbs.items():
            tbl_list = []
            for tbl_name, tinfo in tables.items():
                sens_cols = [c["name"] for c in tinfo["columns"] if c["sensitive"]]
                tbl_list.append({
                    "name": tbl_name,
                    "row_count": tinfo["row_count"],
                    "columns": tinfo["columns"],
                    "sensitive": bool(sens_cols),
                    "sensitive_columns": sens_cols,
                })
            schema["databases"].append({"name": db_name, "tables": tbl_list})
    except Exception as e:
        out.log_error("enumerate_schema_mysql", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_pg(conn, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": out.db_type, "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT table_schema,table_name,column_name,data_type,"
                "is_nullable,'' "
                "FROM information_schema.columns "
                "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
                "ORDER BY table_schema,table_name,ordinal_position"
            )
            rows = cur.fetchall()
        tables: dict = {}
        for (sch, tbl, col, dtype, nullable, _) in rows:
            key = f"{sch}.{tbl}"
            tables.setdefault(key, {"schema": sch, "table": tbl, "columns": []})
            tables[key]["columns"].append({
                "name": col, "type": dtype,
                "nullable": nullable == "YES", "key": "",
                "sensitive": _col_sensitive(col)
            })
        db_entry: dict = {}
        for key, tinfo in tables.items():
            sch = tinfo["schema"]
            db_entry.setdefault(sch, [])
            sens_cols = [c["name"] for c in tinfo["columns"] if c["sensitive"]]
            db_entry[sch].append({
                "name": tinfo["table"],
                "row_count": 0,
                "columns": tinfo["columns"],
                "sensitive": bool(sens_cols),
                "sensitive_columns": sens_cols,
            })
        for sch_name, tbl_list in db_entry.items():
            schema["databases"].append({"name": sch_name, "tables": tbl_list})
    except Exception as e:
        out.log_error("enumerate_schema_pg", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_mssql(conn, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": out.db_type, "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME,"
            "DATA_TYPE,IS_NULLABLE "
            "FROM INFORMATION_SCHEMA.COLUMNS "
            "ORDER BY TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME,ORDINAL_POSITION"
        )
        rows = cur.fetchall()
        tables: dict = {}
        for (catalog, sch, tbl, col, dtype, nullable) in rows:
            key = f"{catalog}.{sch}.{tbl}"
            tables.setdefault(key, {"catalog": catalog, "schema": sch, "table": tbl, "columns": []})
            tables[key]["columns"].append({
                "name": col, "type": dtype,
                "nullable": nullable == "YES", "key": "",
                "sensitive": _col_sensitive(col)
            })
        db_map: dict = {}
        for key, tinfo in tables.items():
            db_key = f"{tinfo['catalog']}.{tinfo['schema']}"
            db_map.setdefault(db_key, [])
            sens_cols = [c["name"] for c in tinfo["columns"] if c["sensitive"]]
            db_map[db_key].append({
                "name": tinfo["table"],
                "row_count": 0,
                "columns": tinfo["columns"],
                "sensitive": bool(sens_cols),
                "sensitive_columns": sens_cols,
            })
        for db_name, tbl_list in db_map.items():
            schema["databases"].append({"name": db_name, "tables": tbl_list})
    except Exception as e:
        out.log_error("enumerate_schema_mssql", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_oracle(conn, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": "oracle", "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT OWNER,TABLE_NAME,COLUMN_NAME,DATA_TYPE,NULLABLE "
            "FROM ALL_TAB_COLUMNS "
            "WHERE OWNER NOT IN ('SYS','SYSTEM','OUTLN','MDSYS','CTXSYS',"
            "'EXFSYS','WMSYS','ORDSYS','ORDDATA','XDB') "
            "ORDER BY OWNER,TABLE_NAME,COLUMN_ID"
        )
        rows = cur.fetchall()
        tables: dict = {}
        for (owner, tbl, col, dtype, nullable) in rows:
            key = f"{owner}.{tbl}"
            tables.setdefault(key, {"owner": owner, "table": tbl, "columns": []})
            tables[key]["columns"].append({
                "name": col, "type": dtype,
                "nullable": nullable == "Y", "key": "",
                "sensitive": _col_sensitive(col)
            })
        owners: dict = {}
        for key, tinfo in tables.items():
            owners.setdefault(tinfo["owner"], [])
            sens_cols = [c["name"] for c in tinfo["columns"] if c["sensitive"]]
            owners[tinfo["owner"]].append({
                "name": tinfo["table"],
                "row_count": 0,
                "columns": tinfo["columns"],
                "sensitive": bool(sens_cols),
                "sensitive_columns": sens_cols,
            })
        for owner_name, tbl_list in owners.items():
            schema["databases"].append({"name": owner_name, "tables": tbl_list})
    except Exception as e:
        out.log_error("enumerate_schema_oracle", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_mongodb(client, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": "mongodb", "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        for db_name in client.list_database_names():
            if db_name in ("admin", "local", "config"):
                continue
            db = client[db_name]
            tbl_list = []
            for coll_name in db.list_collection_names():
                doc = db[coll_name].find_one({})
                fields = []
                if doc:
                    for fname, fval in doc.items():
                        fields.append({
                            "name": fname,
                            "type": type(fval).__name__,
                            "nullable": True, "key": "_id" if fname == "_id" else "",
                            "sensitive": _col_sensitive(fname)
                        })
                count = db[coll_name].estimated_document_count()
                sens_cols = [f["name"] for f in fields if f["sensitive"]]
                tbl_list.append({
                    "name": coll_name,
                    "row_count": count,
                    "columns": fields,
                    "sensitive": bool(sens_cols),
                    "sensitive_columns": sens_cols,
                })
            schema["databases"].append({"name": db_name, "tables": tbl_list})
    except Exception as e:
        out.log_error("enumerate_schema_mongodb", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_redis(client, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": "redis", "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        info = client.info("keyspace")
        dbs_data = []
        for db_name, db_info in info.items():
            sample_keys = []
            try:
                cursor = 0
                cursor, keys = client.scan(cursor, count=20)
                sample_keys = [k.decode() if isinstance(k, bytes) else k for k in keys[:20]]
            except Exception:
                pass
            sens_cols = [k for k in sample_keys if _col_sensitive(k)]
            dbs_data.append({
                "name": db_name,
                "tables": [{
                    "name": "keyspace_sample",
                    "row_count": db_info.get("keys", 0),
                    "columns": [{"name": k, "type": "key", "nullable": False,
                                 "key": "", "sensitive": _col_sensitive(k)}
                                for k in sample_keys],
                    "sensitive": bool(sens_cols),
                    "sensitive_columns": sens_cols,
                }]
            })
        schema["databases"] = dbs_data
    except Exception as e:
        out.log_error("enumerate_schema_redis", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_cassandra(session, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": "cassandra", "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        rows = session.execute(
            "SELECT keyspace_name,table_name,column_name,type "
            "FROM system_schema.columns"
        )
        tables: dict = {}
        for row in rows:
            if row.keyspace_name in ("system", "system_schema", "system_auth", "system_distributed"):
                continue
            key = f"{row.keyspace_name}.{row.table_name}"
            tables.setdefault(key, {"ks": row.keyspace_name, "table": row.table_name, "columns": []})
            tables[key]["columns"].append({
                "name": row.column_name, "type": row.type,
                "nullable": True, "key": "",
                "sensitive": _col_sensitive(row.column_name)
            })
        ks_map: dict = {}
        for key, tinfo in tables.items():
            ks_map.setdefault(tinfo["ks"], [])
            sens_cols = [c["name"] for c in tinfo["columns"] if c["sensitive"]]
            ks_map[tinfo["ks"]].append({
                "name": tinfo["table"],
                "row_count": 0,
                "columns": tinfo["columns"],
                "sensitive": bool(sens_cols),
                "sensitive_columns": sens_cols,
            })
        for ks_name, tbl_list in ks_map.items():
            schema["databases"].append({"name": ks_name, "tables": tbl_list})
    except Exception as e:
        out.log_error("enumerate_schema_cassandra", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_elasticsearch(auditor, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": "elasticsearch", "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        mapping = auditor._get("/_mapping")
        if "_error" in mapping:
            out.write_schema(schema)
            return schema
        tbl_list = []
        for index_name, idx_data in mapping.items():
            if index_name.startswith("."):
                continue
            props = idx_data.get("mappings", {}).get("properties", {})
            columns = []
            for field_name, field_info in props.items():
                columns.append({
                    "name": field_name,
                    "type": field_info.get("type", "object"),
                    "nullable": True, "key": "",
                    "sensitive": _col_sensitive(field_name)
                })
            sens_cols = [c["name"] for c in columns if c["sensitive"]]
            tbl_list.append({
                "name": index_name,
                "row_count": 0,
                "columns": columns,
                "sensitive": bool(sens_cols),
                "sensitive_columns": sens_cols,
            })
        if tbl_list:
            schema["databases"].append({"name": "indices", "tables": tbl_list})
    except Exception as e:
        out.log_error("enumerate_schema_elasticsearch", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_couchdb(auditor, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": "couchdb", "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        code, dbs = auditor._get("/_all_dbs")
        if code != 200 or not isinstance(dbs, list):
            out.write_schema(schema)
            return schema
        tbl_list = []
        for db_name in dbs:
            if db_name.startswith("_"):
                continue
            code2, info = auditor._get(f"/{db_name}/_all_docs?limit=1&include_docs=true")
            columns = []
            if code2 == 200:
                rows_data = info.get("rows", [])
                if rows_data:
                    doc = rows_data[0].get("doc", {})
                    for fname in doc.keys():
                        if fname.startswith("_"):
                            continue
                        columns.append({
                            "name": fname, "type": "field",
                            "nullable": True, "key": "",
                            "sensitive": _col_sensitive(fname)
                        })
            count = info.get("total_rows", 0) if code2 == 200 else 0
            sens_cols = [c["name"] for c in columns if c["sensitive"]]
            tbl_list.append({
                "name": db_name,
                "row_count": count,
                "columns": columns,
                "sensitive": bool(sens_cols),
                "sensitive_columns": sens_cols,
            })
        schema["databases"].append({"name": "couchdb", "tables": tbl_list})
    except Exception as e:
        out.log_error("enumerate_schema_couchdb", str(e))
    out.write_schema(schema)
    return schema


def enumerate_schema_neo4j(driver, out: AugerOutput, db_version: str) -> dict:
    schema = {"tool": "auger", "db_type": "neo4j", "db_version": db_version,
              "host": out.host, "port": out.port,
              "generated_at": out._ts(), "databases": []}
    try:
        with driver.session() as sess:
            label_rows = list(sess.run("CALL db.labels() YIELD label"))
            labels = [r["label"] for r in label_rows]
            rel_rows = list(sess.run("CALL db.relationshipTypes() YIELD relationshipType"))
            rel_types = [r["relationshipType"] for r in rel_rows]

        node_tables = []
        for label in labels[:50]:
            try:
                with driver.session() as sess:
                    result = sess.run(
                        f"MATCH (n:`{label}`) WITH n LIMIT 1 "
                        "RETURN keys(n) AS props, count(n) AS cnt"
                    )
                    row = result.single()
                    props = row["props"] if row else []
                    cnt = row["cnt"] if row else 0
                columns = [{"name": p, "type": "property",
                            "nullable": True, "key": "",
                            "sensitive": _col_sensitive(p)} for p in props]
                sens_cols = [c["name"] for c in columns if c["sensitive"]]
                node_tables.append({
                    "name": f":{label}",
                    "row_count": cnt,
                    "columns": columns,
                    "sensitive": bool(sens_cols),
                    "sensitive_columns": sens_cols,
                })
            except Exception:
                pass
        schema["databases"].append({"name": "node_labels", "tables": node_tables})
        schema["databases"].append({
            "name": "relationship_types",
            "tables": [{"name": rt, "row_count": 0, "columns": [],
                        "sensitive": False, "sensitive_columns": []}
                       for rt in rel_types[:50]]
        })
    except Exception as e:
        out.log_error("enumerate_schema_neo4j", str(e))
    out.write_schema(schema)
    return schema


# ---------------------------------------------------------------------------
# NVD CVE updater
# ---------------------------------------------------------------------------
def _update_cves_from_nvd(catalogue_dir: Path, db_type: str) -> None:
    import urllib.request
    import urllib.parse
    cache_file = catalogue_dir / "cve_cache.json"
    try:
        cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    except Exception:
        cache = {}

    keywords = {
        "mysql": "MySQL", "mariadb": "MariaDB", "postgresql": "PostgreSQL",
        "mssql": "SQL Server", "oracle": "Oracle Database",
        "mongodb": "MongoDB", "redis": "Redis", "cassandra": "Apache Cassandra",
        "elasticsearch": "Elasticsearch", "couchdb": "CouchDB",
        "influxdb": "InfluxDB", "neo4j": "Neo4j", "memcached": "Memcached",
    }
    kw = keywords.get(db_type, db_type)
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
           f"keywordSearch={urllib.parse.quote_plus(kw)}&resultsPerPage=20")
    _console.log(f"Fetching CVEs for {kw} from NVD...", "INFO")
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", f"Auger/{VERSION}")
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        fetched = []
        for v in vulns:
            cve_id = v.get("cve", {}).get("id", "")
            metrics = v.get("cve", {}).get("metrics", {})
            cvss = 0.0
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in metrics and metrics[k]:
                    cvss = metrics[k][0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            desc_list = v.get("cve", {}).get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")
            fetched.append({"cve": cve_id, "cvss": cvss, "desc": desc[:200]})
        cache[db_type] = {"updated_at": datetime.now().isoformat(), "cves": fetched}
        cache_file.write_text(json.dumps(cache, indent=2))
        _console.log(f"  Fetched {len(fetched)} CVEs for {kw}", "SUCCESS")
    except Exception as e:
        _console.log(f"  NVD fetch failed: {e}", "WARNING")


# ---------------------------------------------------------------------------
# Settings file builder
# ---------------------------------------------------------------------------
def _build_settings_from_args(args) -> dict:
    cfg = {
        "engagement": {
            "consultant": "", "client_name": "", "client_short": "",
            "consultant_email": "", "start_date": "", "end_date": ""
        },
        "scan": {
            "project": args.project or "auger_output",
            "host": args.host or "",
            "port": args.port or 0,
            "db_type": args.db_type or "",
            "username": args.username or "",
            "password": args.password or "",
            "database": args.database or "",
            "jdbc": args.jdbc or "",
            "auth_type": args.auth_type or "password",
            "ssl": args.ssl,
            "ssl_ca": args.ssl_ca or "",
            "ssl_cert": args.ssl_cert or "",
            "ssl_key": args.ssl_key or "",
            "ssl_verify": args.ssl_verify,
            "aws_profile": args.aws_profile or "",
            "aws_region": args.aws_region or "",
            "timeout": args.timeout,
            "threads": args.threads,
            "cred_delay": getattr(args, "cred_delay", 0.5),
            "update_cves": getattr(args, "update_cves", False),
        }
    }
    if getattr(args, "db_file", None):
        cfg["db_file"] = args.db_file
    return cfg


# ---------------------------------------------------------------------------
# Universal meta dual-write (Tier 1 migration)
# ---------------------------------------------------------------------------
def _u_augment_findings(findings_json_path, *, tool, scope=None, phase=""):
    """Read findings.json, fill missing universal fields, atomic-write back."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        return 0
    try:
        return _us.augment_findings_file(findings_json_path,
                                          tool=tool, scope=scope, phase=phase)
    except Exception:
        return 0


def _u_dual_write_meta(project_dir, *, tool, version,
                       client_short="", client_name="",
                       engagement_name="", target=""):
    """Dual-write universal meta.json (schema 1.0). Graceful no-op when
    /opt/pr0t31n/shared/pr0t31n_schema.py is not installed."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        return False
    try:
        meta = _us.make_meta(
            tool=tool, version=version,
            client_short=client_short or "unknown",
            client_name=client_name or client_short or "unknown",
            engagement_name=engagement_name or f"{tool} run",
            target=target or "",
        )
        _us.atomic_write_json(Path(project_dir) / "meta.json", meta)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main audit orchestrator
# ---------------------------------------------------------------------------
def run_audit(cfg: dict) -> int:
    scan = cfg.get("scan", {})

    # Parse JDBC if provided
    jdbc_str = scan.get("jdbc", "")
    if jdbc_str:
        jdbc = _parse_jdbc(jdbc_str)
        scan.setdefault("host",     jdbc["host"])
        scan.setdefault("port",     jdbc["port"])
        scan.setdefault("db_type",  jdbc["db_type"])
        scan.setdefault("database", jdbc["database"])

    host        = scan.get("host", "")
    port        = int(scan.get("port", 0))
    db_type     = scan.get("db_type", "").lower().strip()
    username    = scan.get("username", "")
    password    = scan.get("password", "")
    database    = scan.get("database", "")
    ssl_en      = bool(scan.get("ssl", False))
    timeout     = int(scan.get("timeout", 10))
    project     = scan.get("project", "auger_output")
    cred_delay  = float(scan.get("cred_delay", 0.5))
    update_cves = bool(scan.get("update_cves", False))
    auth_type   = scan.get("auth_type", "password")
    aws_profile = scan.get("aws_profile", "")
    aws_region  = scan.get("aws_region", "us-east-1")

    # Normalise db_type aliases
    _aliases = {
        "postgres": "postgresql", "pg": "postgresql",
        "mysql": "mysql", "mariadb": "mariadb",
        "sqlserver": "mssql", "mssql": "mssql",
        "oracle": "oracle",
        "mongo": "mongodb", "mongodb": "mongodb",
        "redis": "redis",
        "cassandra": "cassandra",
        "elasticsearch": "elasticsearch", "elastic": "elasticsearch",
        "es": "elasticsearch",
        "couchdb": "couchdb", "couch": "couchdb",
        "influxdb": "influxdb", "influx": "influxdb",
        "neo4j": "neo4j",
        "memcached": "memcached",
        "redshift": "redshift",
    }
    db_type = _aliases.get(db_type, db_type)

    if not port:
        port = _default_port(db_type)

    if not host:
        _console.error("No target host specified.")
        return 1
    if not db_type:
        _console.error("No database type specified (--db-type).")
        return 1

    out = AugerOutput(project, db_type, host, port)

    # Dual-write universal meta.json (schema 1.0) for Prometheus UniversalParser.
    _eng = cfg.get("engagement", {})
    _u_dual_write_meta(
        out.root, tool="auger", version=VERSION,
        client_short=_eng.get("client_short", ""),
        client_name=_eng.get("client_name", ""),
        engagement_name=_eng.get("engagement_name", ""),
        target=f"{db_type}://{host}:{port}",
    )

    global _PAUSE
    if _pp is not None:
        _PAUSE = _pp.PauseManager(str(out.root), "auger")
        _PAUSE.start_watcher(grace_period=60)
        _resumed = os.environ.get("CRUCIBLE_RESUME") == "1"
        _PAUSE.log_run_type(resumed=_resumed)
        if _resumed:
            _PAUSE.cleanup_incomplete()

    # Optional: update CVEs from NVD before audit
    if update_cves:
        catalogue_dir = Path(__file__).parent / "catalogue"
        _update_cves_from_nvd(catalogue_dir, db_type)

    # Load checkpoint for resume support
    cp = out.load_checkpoint()
    if cp.get("host") == host and cp.get("port") == port and cp.get("db_type") == db_type:
        _console.log(f"Resuming from checkpoint: {cp.get('completed_phases', [])}", "INFO")

    _console.log(f"Auger v{VERSION} — {db_type.upper()} audit of {host}:{port}", "INFO")
    _console.status("connectivity", label="Connectivity", step="tcp_probe", status="running")

    # Phase 1: Connectivity check
    if not _tcp_open(host, port, timeout=5.0):
        _console.error(f"Port {port} on {host} is not reachable.")
        out.log_step(f"FAIL: TCP {host}:{port} unreachable")
        return 2

    _console.log(f"TCP {host}:{port} open", "SUCCESS")
    out.log_step(f"TCP {host}:{port} open")

    # Network / TLS checks
    run_network_phase(host, port, out)

    if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

    _console.status("connectivity", label="Connectivity", status="complete")

    # Phase 2: DB-type specific audit
    db_version   = ""
    phases_run   = ["connectivity", "network"]
    auth_success = False

    # Crucible prompt before default credential checks (when Crucible-managed)
    def _cred_prompt():
        if _CRUCIBLE_MANAGED:
            entry = json.dumps({
                "message": "About to test default credentials. Proceed?",
                "choices": ["yes", "no"], "default": "yes"
            })
            sys.stdout.write(_CP_PROMPT + entry + "\n")
            sys.stdout.flush()
        if cred_delay > 0:
            time.sleep(cred_delay)

    if db_type in ("mysql", "mariadb"):
        auditor = MySQLAuditor(host, port, username, password, database, out,
                               ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor.check_version()
            scan_sensitive_columns_mysql(auditor._conn, out, db_version)
            enumerate_schema_mysql(auditor._conn, out, db_version)
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor._conn.close()
        else:
            _console.error("MySQL authentication failed.")

    elif db_type == "postgresql":
        auditor = PostgreSQLAuditor(host, port, username, password, database, out,
                                     ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor.check_version()
            scan_sensitive_columns_pg(auditor._conn, out, db_version)
            enumerate_schema_pg(auditor._conn, out, db_version)
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor._conn.close()
        else:
            _console.error("PostgreSQL authentication failed.")

    elif db_type == "redshift":
        # AWS Redshift: IAM auth token generation if auth_type == "iam"
        if auth_type == "iam":
            try:
                import boto3
                session = boto3.Session(
                    profile_name=aws_profile or None,
                    region_name=aws_region
                )
                rds = session.client("rds", region_name=aws_region)
                password = rds.generate_db_auth_token(
                    DBHostname=host, Port=port,
                    DBUsername=username, Region=aws_region
                )
                _console.log("Redshift IAM token generated", "SUCCESS")
            except Exception as e:
                _console.log(f"Redshift IAM token generation failed: {e}", "WARNING")
        # Redshift uses PostgreSQL wire protocol
        auditor = PostgreSQLAuditor(host, port, username, password, database, out,
                                     ssl_enabled=True, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor.check_version()
            enumerate_schema_pg(auditor._conn, out, db_version)
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor._conn.close()
        else:
            _console.error("Redshift authentication failed.")

    elif db_type == "mssql":
        auditor = MSSQLAuditor(host, port, username, password, database, out, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = ""
            enumerate_schema_mssql(auditor._conn, out, db_version)
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor._conn.close()
        else:
            _console.error("MSSQL authentication failed.")

    elif db_type == "oracle":
        auditor = OracleAuditor(host, port, username, password, database, out,
                                ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor.check_version()
            enumerate_schema_oracle(auditor._conn, out, db_version)
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor._conn.close()
        else:
            _cred_prompt()
            _console.error("Oracle authentication failed.")

    elif db_type == "mongodb":
        auditor = MongoDBauditor(host, port, username, password, database, out,
                                  ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor.check_version()
            enumerate_schema_mongodb(auditor._client, out, db_version)
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor._client.close()
        else:
            _console.error("MongoDB authentication failed.")

    elif db_type == "redis":
        auditor = RedisAuditor(host, port, password, out, ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            extra = auditor.run("")
            db_version = auditor._version
            enumerate_schema_redis(auditor._client, out, db_version)
            phases_run.extend(extra)
        else:
            _console.error("Redis authentication failed.")

    elif db_type == "cassandra":
        auditor = CassandraAuditor(host, port, username, password, database, out,
                                    ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            extra = auditor.run("")
            db_version = auditor._version
            enumerate_schema_cassandra(auditor._session, out, db_version)
            phases_run.extend(extra)
        else:
            _console.error("Cassandra authentication failed.")

    elif db_type == "elasticsearch":
        auditor = ElasticsearchAuditor(host, port, username, password, out,
                                        ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            extra = auditor.run("")
            db_version = auditor._version
            enumerate_schema_elasticsearch(auditor, out, db_version)
            phases_run.extend(extra)
        else:
            _console.error("Elasticsearch connection failed.")

    elif db_type == "couchdb":
        auditor = CouchDBAuditor(host, port, username, password, out,
                                  ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor._version
            enumerate_schema_couchdb(auditor, out, db_version)
            _cred_prompt()
            extra = auditor.run(db_version)
            phases_run.extend(extra)
        else:
            _console.error("CouchDB connection failed.")

    elif db_type == "influxdb":
        auditor = InfluxDBAuditor(host, port, username, password, out,
                                   ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor._version
            _cred_prompt()
            extra = auditor.run(db_version)
            phases_run.extend(extra)
        else:
            _console.error("InfluxDB connection failed.")

    elif db_type == "neo4j":
        auditor = Neo4jAuditor(host, port, username, password, out,
                                ssl_enabled=ssl_en, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor._version
            enumerate_schema_neo4j(auditor._driver, out, db_version)
            _cred_prompt()
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor.close()
        else:
            _console.error("Neo4j authentication failed.")

    elif db_type == "memcached":
        auditor = MemcachedAuditor(host, port, out, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor._version
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor.close()
        else:
            _console.error("Memcached connection failed.")

    elif db_type == "dynamodb":
        # Fixes the 2026-06-11 review HIGH finding: DynamoDB was declared
        # in argparse choices but had no auditor class. Now wired through
        # boto3 against the AWS DynamoDB control plane.
        auditor = DynamoDBAuditor(
            aws_profile=ns.aws_profile, aws_region=ns.aws_region,
            out=out, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor._version
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor.close()
        else:
            _console.error("DynamoDB connect failed (check AWS credentials / region).")

    elif db_type == "rds":
        # 2026-06-11 review round 4: native AWS RDS control-plane audit.
        # Complements the existing engine-specific auditors (MySQL/PG/...) —
        # those handle the in-DB checks via direct connection; RDSAuditor
        # handles the AWS account / parameter-group / snapshot surface.
        auditor = RDSAuditor(
            aws_profile=ns.aws_profile, aws_region=ns.aws_region,
            out=out, timeout=timeout)
        if auditor.connect():
            auth_success = True
            db_version = auditor._version
            extra = auditor.run(db_version)
            phases_run.extend(extra)
            auditor.close()
        else:
            _console.error("RDS connect failed (check AWS credentials / region).")

    else:
        _console.error(f"Database type '{db_type}' not supported.")
        return 3

    # Write checkpoint and summary
    out.write_checkpoint(db_version, db_type, list(set(phases_run)), auth_success)
    out.write_summary(db_version, db_type, auth_success, list(set(phases_run)))
    # Augment findings.json with universal-required fields (idempotent).
    _u_augment_findings(out.findings_json, tool="auger", scope=None)

    try:
        findings = json.loads(out.findings_json.read_text())
    except Exception:
        findings = []
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = f.get("risk", "INFO").upper()
        risk_counts[r] = risk_counts.get(r, 0) + 1
    needs_validation = sum(1 for f in findings if f.get("validation_required"))

    _console.log("=" * 60, "INFO")
    _console.log(f"Audit complete — {db_type.upper()} {host}:{port}", "SUCCESS")
    _console.log(f"Findings: {len(findings)} total | "
                 f"CRITICAL={risk_counts['CRITICAL']} HIGH={risk_counts['HIGH']} "
                 f"MEDIUM={risk_counts['MEDIUM']} LOW={risk_counts['LOW']} "
                 f"INFO={risk_counts['INFO']}", "INFO")
    if needs_validation:
        _console.log(f"Findings requiring manual validation: {needs_validation}", "WARNING")
    _console.log(f"Output: {out.root}", "INFO")

    if _PAUSE:
        _PAUSE.write_stop_reason("completed", "all_phases_done")

    _console.status("complete", label="Audit Complete", status="complete",
                    progress=len(findings), total=len(findings))
    return 0


# ---------------------------------------------------------------------------
# Database file analysis (--db-file mode)
# ---------------------------------------------------------------------------

_FILE_EXT_MAP = {
    ".db": "sqlite", ".sqlite": "sqlite", ".sqlite3": "sqlite",
    ".sqlitedb": "sqlite", ".s3db": "sqlite",
    ".sql": "sqldump", ".dump": "sqldump",
    ".rdb": "redis_rdb",
}

_SQLITE_MAGIC = b"SQLite format 3"
_REDIS_MAGIC  = b"REDIS"

_SENS_COL_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api_key|apikey|access_key|"
    r"private_key|ssn|social_security|credit_card|card_number|cvv|"
    r"auth_token|session_token|refresh_token|encryption_key|"
    r"pin|tax_id|bank_account|routing_number|dob|date_of_birth|"
    r"medical_record|diagnosis|prescription)", re.IGNORECASE
)

_SENS_DATA_PATS = {
    "email":         re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"),
    "ssn":           re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card":   re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b"),
    "api_key":       re.compile(r"(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36})"),
    "private_key":   re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "password_hash": re.compile(r"\$(?:2[aby]|5|6|argon2[id]?)\$[./a-zA-Z0-9]+"),
}

_SQL_CRED_RES = [
    re.compile(r"(?:CREATE\s+USER|CREATE\s+ROLE)\s+['\"]?(\S+?)['\"]?\s+.*?(?:PASSWORD|IDENTIFIED\s+BY)\s+['\"]([^'\"]+)['\"]", re.IGNORECASE | re.DOTALL),
    re.compile(r"GRANT\s+.*?\s+TO\s+['\"]?(\S+?)['\"]?\s+.*?(?:PASSWORD|IDENTIFIED\s+BY)\s+['\"]([^'\"]+)['\"]", re.IGNORECASE | re.DOTALL),
    re.compile(r"ALTER\s+(?:USER|ROLE)\s+['\"]?(\S+?)['\"]?\s+.*?(?:PASSWORD|IDENTIFIED\s+BY)\s+['\"]([^'\"]+)['\"]", re.IGNORECASE | re.DOTALL),
]
_SQL_GRANT_ALL_RE = re.compile(r"GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+[*.]", re.IGNORECASE)
_SQL_SENS_INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+[`'\"]?(\w+)[`'\"]?\s*\(([^)]+)\)\s*VALUES", re.IGNORECASE
)


def _detect_file_type(fp: Path) -> str:
    name = fp.name.lower()
    if name.endswith(".h2.db") or name.endswith(".mv.db"):
        return "h2"
    ext = fp.suffix.lower()
    detected = _FILE_EXT_MAP.get(ext, "")
    if detected:
        return detected
    try:
        with open(fp, "rb") as f:
            hdr = f.read(16)
        if hdr.startswith(_SQLITE_MAGIC):
            return "sqlite"
        if hdr.startswith(_REDIS_MAGIC):
            return "redis_rdb"
    except OSError:
        pass
    return ""


def _run_file_audit(db_file: str, cfg: dict) -> int:
    fp = Path(db_file).resolve()
    if not fp.exists():
        _console.error(f"Database file not found: {db_file}")
        return 1
    if not fp.is_file():
        _console.error(f"Not a file: {db_file}")
        return 1

    file_type = _detect_file_type(fp)
    scan = cfg.get("scan", {})
    override = scan.get("db_type", "").strip().lower()
    if override:
        _fa = {"sqldump": "sqldump", "sql": "sqldump", "dump": "sqldump",
               "sqlite": "sqlite", "redis_rdb": "redis_rdb", "redis": "redis_rdb",
               "h2": "h2"}
        file_type = _fa.get(override, override)
    if not file_type:
        _console.error(
            f"Cannot determine file type for: {fp.name}. "
            "Use --db-type to specify (sqlite, sqldump, redis_rdb, h2).")
        return 1

    project = scan.get("project", "auger_output")
    out = AugerOutput(project, file_type, str(fp), 0)

    eng = cfg.get("engagement", {})
    _u_dual_write_meta(
        out.root, tool="auger", version=VERSION,
        client_short=eng.get("client_short", ""),
        client_name=eng.get("client_name", ""),
        engagement_name=eng.get("engagement_name", ""),
        target=f"file://{fp}",
    )

    _console.log(f"Auger v{VERSION} — File analysis: {fp.name} ({file_type})", "INFO")
    _console.status("file_analysis", label="File Analysis", step="detect", status="running")
    out.log_step(f"EVENT Auger v{VERSION} started — file analysis mode")
    out.log_step(f"File: {fp} | Type: {file_type} | Size: {fp.stat().st_size} bytes")

    phases_run = ["file_detection"]

    # File permissions check (Unix)
    try:
        import stat as _stat_mod
        st = fp.stat()
        mode = st.st_mode
        if mode & _stat_mod.S_IROTH:
            risk = "MEDIUM" if (mode & _stat_mod.S_IWOTH) else "LOW"
            perms = oct(mode)[-3:]
            out.add_finding(
                title="Database File — Insecure File Permissions",
                risk=risk,
                description=(
                    f"The database file {fp.name} has overly permissive file permissions "
                    f"(mode {perms}). "
                    + ("World-writable: any local user can modify the database contents. "
                       if mode & _stat_mod.S_IWOTH else
                       "World-readable: any local user can read the database contents. ")
                    + "Database files should be restricted to the owning user/group."),
                phase="file_permissions",
                command=f"ls -la {fp}",
                output=f"Permissions: {perms} | Owner UID: {st.st_uid} | Group GID: {st.st_gid}",
                catalogue_id="AU-FILE-001",
                remediation="Restrict file permissions: chmod 600 or 640 for the database file.",
                nist="AC-6",
            )
    except Exception:
        pass
    phases_run.append("file_permissions")

    if file_type == "sqlite":
        _fa_sqlite(fp, out)
        phases_run.append("sqlite_analysis")
    elif file_type == "sqldump":
        _fa_sqldump(fp, out)
        phases_run.append("sqldump_analysis")
    elif file_type == "redis_rdb":
        _fa_redis_rdb(fp, out)
        phases_run.append("redis_rdb_analysis")
    elif file_type == "h2":
        _fa_h2(fp, out)
        phases_run.append("h2_analysis")

    out.write_checkpoint("file", file_type, list(set(phases_run)), True)
    out.write_summary("file", file_type, True, list(set(phases_run)))
    _u_augment_findings(out.findings_json, tool="auger", scope=None)

    try:
        findings = json.loads(out.findings_json.read_text())
    except Exception:
        findings = []
    rc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = f.get("risk", "INFO").upper()
        rc[r] = rc.get(r, 0) + 1

    _console.log("=" * 60, "INFO")
    _console.log(f"File analysis complete — {fp.name} ({file_type})", "SUCCESS")
    _console.log(
        f"Findings: {len(findings)} total | "
        f"CRITICAL={rc['CRITICAL']} HIGH={rc['HIGH']} "
        f"MEDIUM={rc['MEDIUM']} LOW={rc['LOW']} INFO={rc['INFO']}", "INFO")
    _console.log(f"Output: {out.root}", "INFO")

    if _PAUSE:
        _PAUSE.write_stop_reason("completed", "all_phases_done")

    _console.status("complete", label="File Analysis Complete", status="complete",
                    progress=len(findings), total=len(findings))
    return 0


def _fa_sqlite(fp: Path, out: AugerOutput) -> None:
    import sqlite3 as _sql3
    _console.status("file_analysis", label="SQLite Analysis",
                    step="schema", status="running")
    out.log_step("EVENT SQLite analysis started")

    try:
        conn = _sql3.connect(f"file:{fp}?mode=ro", uri=True)
    except Exception as exc:
        out.add_finding(
            title="SQLite Database — Cannot Open (Possibly Encrypted)",
            risk="INFO",
            description=(
                f"The SQLite database {fp.name} could not be opened: {exc}. "
                "This may indicate encryption (e.g. SQLCipher) or corruption."),
            phase="sqlite_analysis", command=f"sqlite3 {fp} .tables",
            catalogue_id="AU-FILE-002",
        )
        return

    try:
        cur = conn.cursor()
        cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = cur.fetchall()
        schema = {"tables": [], "total_rows": 0}
        sens_tables = []

        for tname, create_sql in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{tname}"')
                rows = cur.fetchone()[0]
            except Exception:
                rows = 0
            schema["tables"].append({"name": tname, "rows": rows, "sql": create_sql or ""})
            schema["total_rows"] += rows
            if create_sql and _SENS_COL_RE.search(create_sql):
                sens_tables.append({"table": tname,
                                    "columns": _SENS_COL_RE.findall(create_sql),
                                    "rows": rows})

        out.write_schema(schema)
        out.log_step(f"Schema: {len(tables)} tables, {schema['total_rows']} total rows")

        if schema["tables"]:
            out.add_finding(
                title="SQLite Database — Schema Enumerated",
                risk="INFO",
                description=(
                    f"SQLite database {fp.name} contains {len(tables)} table(s) "
                    f"with {schema['total_rows']} total row(s)."),
                phase="sqlite_analysis",
                command=f"sqlite3 {fp} '.tables'",
                output=", ".join(t["name"] for t in schema["tables"]),
                catalogue_id="AU-FILE-003",
            )

        if sens_tables:
            details = "; ".join(
                f"{st['table']} ({', '.join(st['columns'][:5])}, {st['rows']} rows)"
                for st in sens_tables)
            out.add_finding(
                title="SQLite Database — Sensitive Data Columns Detected",
                risk="HIGH",
                description=(
                    f"Tables with columns matching sensitive data patterns "
                    f"(passwords, tokens, PII) were found in {fp.name}: {details}. "
                    "Data stored in SQLite files is unencrypted by default."),
                phase="sqlite_analysis",
                command=f"sqlite3 {fp} '.schema'",
                output=details,
                catalogue_id="AU-FILE-004",
                remediation="Encrypt sensitive data at rest. Use SQLCipher or application-level encryption.",
                nist="SC-28",
            )

        # Sample data scan
        _console.status("file_analysis", label="SQLite Analysis",
                        step="data_scan", status="running")
        for st in sens_tables[:10]:
            try:
                cur.execute(f'SELECT * FROM "{st["table"]}" LIMIT 100')
                rows = cur.fetchall()
                col_names = [d[0] for d in cur.description] if cur.description else []
                blob = "\n".join(" | ".join(str(c) for c in r) for r in rows)
                for label, pat in _SENS_DATA_PATS.items():
                    hits = pat.findall(blob)
                    if hits:
                        sample = hits[:3]
                        risk = "CRITICAL" if label in ("private_key", "api_key") else "HIGH"
                        out.add_finding(
                            title=f"SQLite — {label.replace('_', ' ').title()} Data Exposed in {st['table']}",
                            risk=risk,
                            description=(
                                f"Table '{st['table']}' contains {len(hits)} instance(s) of "
                                f"{label.replace('_', ' ')} data in plaintext. "
                                f"Sample (redacted): {', '.join(s[:8] + '...' for s in sample)}."),
                            phase="sqlite_analysis",
                            command=f'sqlite3 {fp} "SELECT * FROM {st["table"]} LIMIT 100"',
                            output=f"Pattern: {label} | Hits: {len(hits)} | Columns: {', '.join(col_names[:10])}",
                            catalogue_id="AU-FILE-005",
                            remediation=f"Encrypt or hash {label.replace('_', ' ')} data. Remove unnecessary data.",
                            nist="SC-28",
                        )
            except Exception:
                pass

        # Triggers
        cur.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger'")
        triggers = cur.fetchall()
        if triggers:
            out.add_finding(
                title="SQLite Database — Triggers Present",
                risk="LOW",
                description=(
                    f"The database contains {len(triggers)} trigger(s): "
                    f"{', '.join(t[0] for t in triggers)}. "
                    "Review triggers for unintended side effects."),
                phase="sqlite_analysis",
                command=f"sqlite3 {fp} \"SELECT name,sql FROM sqlite_master WHERE type='trigger'\"",
                output="\n".join(f"{t[0]}: {t[1]}" for t in triggers[:5]),
                catalogue_id="AU-FILE-006",
            )

        # WAL file check
        try:
            cur.execute("PRAGMA journal_mode")
            jmode = cur.fetchone()
            if jmode and jmode[0].lower() == "wal":
                wal = fp.parent / f"{fp.name}-wal"
                if wal.exists() and wal.stat().st_size > 0:
                    out.add_finding(
                        title="SQLite Database — WAL File Contains Uncommitted Data",
                        risk="LOW",
                        description=(
                            f"A WAL file exists ({wal.name}, {wal.stat().st_size} bytes). "
                            "It may contain recently written data including sensitive records."),
                        phase="sqlite_analysis",
                        command=f"ls -la {wal}",
                        catalogue_id="AU-FILE-007",
                    )
        except Exception:
            pass
    except Exception as exc:
        _console.error(f"SQLite analysis error: {exc}")
        out.log_error("sqlite3", str(exc))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _fa_sqldump(fp: Path, out: AugerOutput) -> None:
    _console.status("file_analysis", label="SQL Dump Analysis",
                    step="parse", status="running")
    out.log_step("EVENT SQL dump analysis started")

    max_bytes = 200 * 1024 * 1024
    if fp.stat().st_size > max_bytes:
        _console.log(f"SQL dump is large ({fp.stat().st_size // 1048576} MB). "
                     "Analyzing first 200 MB.", "WARNING")

    try:
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
    except Exception as exc:
        _console.error(f"Cannot read SQL dump: {exc}")
        out.log_error("sqldump", str(exc))
        return

    # Credential detection
    creds = []
    for pat in _SQL_CRED_RES:
        for m in pat.finditer(content):
            creds.append({"user": m.group(1), "password": m.group(2)[:4] + "***"})
    if creds:
        detail = "; ".join(f"{c['user']}:{c['password']}" for c in creds[:10])
        out.add_finding(
            title="SQL Dump — Plaintext Credentials in Database Statements",
            risk="HIGH",
            description=(
                f"The SQL dump {fp.name} contains {len(creds)} "
                f"CREATE USER / GRANT / ALTER USER statement(s) with plaintext passwords. "
                f"Accounts (redacted): {detail}."),
            phase="sqldump_analysis",
            command=f"grep -Ei 'CREATE USER|GRANT.*PASSWORD' {fp.name}",
            output=f"Credential statements found: {len(creds)}",
            catalogue_id="AU-FILE-010",
            remediation="Remove plaintext passwords from SQL dumps. Rotate exposed credentials.",
            nist="IA-5",
        )

    # GRANT ALL
    ga = _SQL_GRANT_ALL_RE.findall(content)
    if ga:
        out.add_finding(
            title="SQL Dump — Excessive GRANT ALL Privileges",
            risk="MEDIUM",
            description=(
                f"The SQL dump contains {len(ga)} GRANT ALL statement(s), "
                "violating least privilege."),
            phase="sqldump_analysis",
            command=f"grep -i 'GRANT ALL' {fp.name}",
            output="\n".join(m.strip()[:120] for m in ga[:5]),
            catalogue_id="AU-FILE-011",
            remediation="Replace GRANT ALL with specific privileges.",
            nist="AC-6",
        )

    # Sensitive data in INSERT
    _console.status("file_analysis", label="SQL Dump Analysis",
                    step="data_scan", status="running")
    si = []
    for m in _SQL_SENS_INSERT_RE.finditer(content):
        if _SENS_COL_RE.search(m.group(2)):
            si.append(m.group(1))
    if si:
        uniq = list(dict.fromkeys(si))[:20]
        out.add_finding(
            title="SQL Dump — Sensitive Data in INSERT Statements",
            risk="MEDIUM",
            description=(
                f"INSERT statements targeting tables with sensitive columns "
                f"found: {', '.join(uniq[:10])}. Total: {len(si)} statement(s)."),
            phase="sqldump_analysis",
            command=f"grep -Ei 'INSERT INTO.*(password|token|ssn)' {fp.name}",
            output=f"Tables: {', '.join(uniq[:10])}",
            catalogue_id="AU-FILE-012",
            remediation="Sanitize SQL dumps. Mask sensitive column values in exports.",
            nist="SC-28",
        )

    # Sensitive data patterns
    for label, pat in _SENS_DATA_PATS.items():
        hits = pat.findall(content[:50_000_000])
        if len(hits) > 2:
            risk = "CRITICAL" if label in ("private_key", "api_key") else "HIGH"
            out.add_finding(
                title=f"SQL Dump — {label.replace('_', ' ').title()} Data Detected",
                risk=risk,
                description=(
                    f"The SQL dump contains {len(hits)} instance(s) of "
                    f"{label.replace('_', ' ')} data in plaintext."),
                phase="sqldump_analysis",
                command=f"grep -cE '{pat.pattern[:60]}' {fp.name}",
                output=f"Pattern: {label} | Count: {len(hits)}",
                catalogue_id="AU-FILE-013",
                remediation=f"Remove or encrypt {label.replace('_', ' ')} data in exports.",
                nist="SC-28",
            )

    # DB type detection from header
    hdr = content[:5000].lower()
    hints = []
    if "mysql" in hdr or "mariadb" in hdr:   hints.append("MySQL/MariaDB")
    if "postgresql" in hdr or "pg_dump" in hdr: hints.append("PostgreSQL")
    if "microsoft sql server" in hdr:         hints.append("MSSQL")
    if "oracle" in hdr or "pl/sql" in hdr:    hints.append("Oracle")
    if hints:
        out.add_finding(
            title=f"SQL Dump — Database Type Identified: {', '.join(hints)}",
            risk="INFO",
            description=(
                f"The SQL dump appears to originate from {', '.join(hints)}. "
                f"File size: {fp.stat().st_size // 1024} KB."),
            phase="sqldump_analysis",
            command=f"head -20 {fp.name}",
            output=content[:500],
            catalogue_id="AU-FILE-014",
        )


def _fa_redis_rdb(fp: Path, out: AugerOutput) -> None:
    _console.status("file_analysis", label="Redis RDB Analysis",
                    step="header", status="running")
    out.log_step("EVENT Redis RDB analysis started")

    try:
        with open(fp, "rb") as f:
            hdr = f.read(16)
    except Exception as exc:
        _console.error(f"Cannot read RDB file: {exc}")
        out.log_error("redis_rdb", str(exc))
        return

    if not hdr.startswith(_REDIS_MAGIC):
        out.add_finding(
            title="Redis RDB — Invalid or Corrupted File",
            risk="INFO",
            description=f"The file {fp.name} does not have a valid Redis RDB header.",
            phase="redis_rdb_analysis", catalogue_id="AU-FILE-020",
        )
        return

    ver = hdr[5:9].decode("ascii", errors="replace")
    sz = fp.stat().st_size
    out.add_finding(
        title=f"Redis RDB — Dump File Identified (RDB v{ver})",
        risk="INFO",
        description=(
            f"Redis RDB dump: {fp.name} (version {ver}, {sz // 1024} KB). "
            "Contains a snapshot of all Redis data at a point in time."),
        phase="redis_rdb_analysis",
        command=f"xxd -l 16 {fp.name}",
        output=f"Magic: REDIS | Version: {ver} | Size: {sz} bytes",
        catalogue_id="AU-FILE-021",
    )

    try:
        with open(fp, "rb") as f:
            raw = f.read(min(sz, 100 * 1024 * 1024))
        text = raw.decode("utf-8", errors="replace")
        for label, pat in _SENS_DATA_PATS.items():
            hits = pat.findall(text)
            if hits:
                risk = "HIGH" if label in ("private_key", "api_key", "password_hash") else "MEDIUM"
                out.add_finding(
                    title=f"Redis RDB — {label.replace('_', ' ').title()} Data in Dump",
                    risk=risk,
                    description=(
                        f"The Redis RDB dump contains {len(hits)} instance(s) of "
                        f"{label.replace('_', ' ')} data. Redis stores data unencrypted."),
                    phase="redis_rdb_analysis",
                    output=f"Pattern: {label} | Hits: {len(hits)}",
                    catalogue_id="AU-FILE-022",
                    remediation="Encrypt Redis RDB files at rest. Rotate exposed credentials.",
                    nist="SC-28",
                )
    except Exception as exc:
        out.log_error("redis_rdb", f"Binary scan error: {exc}")


def _fa_h2(fp: Path, out: AugerOutput) -> None:
    _console.status("file_analysis", label="H2 Database Analysis",
                    step="detect", status="running")
    out.log_step("EVENT H2 database analysis started")

    sz = fp.stat().st_size
    out.add_finding(
        title="H2 Database File Identified",
        risk="MEDIUM",
        description=(
            f"H2 database file: {fp.name} ({sz // 1024} KB). "
            "H2 databases have been associated with critical vulnerabilities "
            "including CVE-2021-42392 (JNDI injection/RCE) and CVE-2022-23221 "
            "(JDBC URL injection)."),
        phase="h2_analysis",
        command=f"file {fp.name}",
        output=f"File: {fp.name} | Size: {sz} bytes",
        cves="CVE-2021-42392,CVE-2022-23221",
        catalogue_id="AU-FILE-030",
        remediation="Ensure H2 Console is not exposed. Update H2 to latest version.",
        nist="SI-2",
    )

    try:
        with open(fp, "rb") as f:
            raw = f.read(min(sz, 50 * 1024 * 1024))
        text = raw.decode("utf-8", errors="replace")
        for label, pat in _SENS_DATA_PATS.items():
            hits = pat.findall(text)
            if hits:
                risk = "HIGH" if label in ("private_key", "api_key") else "MEDIUM"
                out.add_finding(
                    title=f"H2 Database — {label.replace('_', ' ').title()} Data Detected",
                    risk=risk,
                    description=(
                        f"The H2 database contains {len(hits)} instance(s) of "
                        f"{label.replace('_', ' ')} data."),
                    phase="h2_analysis",
                    output=f"Pattern: {label} | Hits: {len(hits)}",
                    catalogue_id="AU-FILE-031",
                    remediation=f"Encrypt H2 database. Rotate exposed {label.replace('_', ' ')} data.",
                    nist="SC-28",
                )
    except Exception as exc:
        out.log_error("h2", f"Binary scan error: {exc}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="auger.py",
        description=f"Auger v{VERSION} — Database Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported database types:
  mysql, mariadb, postgresql, mssql, oracle, mongodb, redis,
  cassandra, elasticsearch, couchdb, influxdb, neo4j, memcached

Examples:
  python3 auger.py --host 10.0.0.1 --db-type mysql --username root --password secret
  python3 auger.py --jdbc "jdbc:postgresql://db.example.com:5432/prod" -U postgres -P pass
  python3 auger.py --host redis.example.com --db-type redis --password supersecret --ssl
  python3 auger.py --settings /path/to/auger_settings.json
  python3 auger.py --db-file /path/to/database.sqlite3
  python3 auger.py --db-file /path/to/backup.sql --db-type sqldump
  python3 auger.py --db-file /path/to/dump.rdb
"""
    )
    p.add_argument("--settings",    metavar="FILE",   help="JSON settings file (Crucible mode)")
    p.add_argument("--host",        metavar="HOST",   help="Target host/IP")
    p.add_argument("--db-file",     metavar="PATH",   dest="db_file",
                   help="Local database file to analyze (SQLite, SQL dump, Redis RDB, H2)")
    p.add_argument("--port",        metavar="PORT",   type=int, default=0)
    p.add_argument("--db-type",     metavar="TYPE",   help="Database type",
                   choices=["mysql","mariadb","postgresql","postgres","mssql","oracle",
                            "mongodb","redis","cassandra","elasticsearch","elastic","es",
                            "couchdb","influxdb","neo4j","memcached","redshift","dynamodb",
                            "rds",
                            "sqlite","sqldump","redis_rdb","h2"])
    p.add_argument("-U", "--username", metavar="USER", default="")
    p.add_argument("-P", "--password", metavar="PASS", default="")
    p.add_argument("--database",    metavar="DB",     default="",  help="Database/schema name")
    p.add_argument("--jdbc",        metavar="URL",    default="",  help="JDBC connection string")
    p.add_argument("--auth-type",   metavar="TYPE",   default="password",
                   choices=["password","ssl","kerberos","ldap","iam"])
    p.add_argument("--ssl",         action="store_true", help="Enable SSL/TLS")
    p.add_argument("--ssl-ca",      metavar="FILE",   default="")
    p.add_argument("--ssl-cert",    metavar="FILE",   default="")
    p.add_argument("--ssl-key",     metavar="FILE",   default="")
    p.add_argument("--ssl-verify",  action="store_true")
    p.add_argument("--aws-profile", metavar="PROFILE", default="")
    p.add_argument("--aws-region",  metavar="REGION",  default="")
    p.add_argument("--timeout",     type=int, default=10)
    p.add_argument("--threads",     type=int, default=4)
    p.add_argument("--project",     metavar="DIR",    default="auger_output",
                   help="Output directory")
    p.add_argument("--cred-delay",  type=float, default=0.5, dest="cred_delay",
                   help="Seconds to pause between credential attempts (default: 0.5)")
    p.add_argument("--update-cves", action="store_true", dest="update_cves",
                   help="Fetch latest CVEs from NVD before audit")
    p.add_argument("--version",     action="version", version=f"Auger v{VERSION}")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    args = _parse_args()

    if args.settings:
        cfg_path = Path(args.settings)
        if not cfg_path.exists():
            _console.error(f"Settings file not found: {args.settings}")
            return 1
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception as e:
            _console.error(f"Failed to parse settings: {e}")
            return 1
    else:
        cfg = _build_settings_from_args(args)

    db_file = cfg.get("db_file", "")
    if db_file:
        return _run_file_audit(db_file, cfg)

    return run_audit(cfg)


if __name__ == "__main__":
    sys.exit(main())
