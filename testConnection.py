#!/usr/bin/env python3
"""
testConnection.py — Auger database connection tester.
Used by Crucible to verify credentials before launching a full audit.

Outputs Crucible protocol tokens on stdout:
  __CRUCIBLE_STATUS__:{"phase":"connect","step":"ok","label":"Connected","db_version":"..."}
  __CRUCIBLE_ERR__:{"message":"..."}

Exit codes: 0 = success, 1 = connection failed, 2 = bad arguments
"""

import sys
import os
import json
import argparse
import ssl
from pathlib import Path

_CP_STATUS = "__CRUCIBLE_STATUS__:"
_CP_ERR    = "__CRUCIBLE_ERR__:"

_DEFAULT_PORTS = {
    "mysql": 3306, "mariadb": 3306, "postgresql": 5432, "postgres": 5432,
    "mssql": 1433, "oracle": 1521, "mongodb": 27017, "redis": 6379,
    "cassandra": 9042, "elasticsearch": 9200, "couchdb": 5984,
    "influxdb": 8086, "neo4j": 7687, "memcached": 11211, "redshift": 5439,
}


def _ok(db_version: str, db_type: str) -> None:
    sys.stdout.write(_CP_STATUS + json.dumps({
        "phase": "connect", "step": "ok",
        "label": f"Connected ({db_type})",
        "db_version": db_version,
    }) + "\n")
    sys.stdout.flush()


def _err(message: str) -> None:
    sys.stderr.write(_CP_ERR + json.dumps({"message": message}) + "\n")
    sys.stderr.flush()


def _test_mysql(host, port, username, password, database, ssl_en, timeout):
    try:
        import pymysql
        conn = pymysql.connect(
            host=host, port=port, user=username, password=password,
            database=database or None, connect_timeout=timeout,
            ssl={"ssl": {}} if ssl_en else None,
        )
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION()")
            ver = cur.fetchone()[0]
        conn.close()
        return ver, None
    except ImportError:
        return None, "pymysql not installed"
    except Exception as e:
        return None, str(e)


def _test_postgresql(host, port, username, password, database, ssl_en, timeout):
    try:
        import psycopg2
        sslmode = "require" if ssl_en else "prefer"
        conn = psycopg2.connect(
            host=host, port=port, user=username, password=password,
            dbname=database or "postgres", connect_timeout=timeout,
            sslmode=sslmode,
        )
        cur = conn.cursor()
        cur.execute("SELECT version()")
        ver = cur.fetchone()[0]
        conn.close()
        return ver, None
    except ImportError:
        return None, "psycopg2 not installed"
    except Exception as e:
        return None, str(e)


def _test_mssql(host, port, username, password, database, timeout):
    try:
        import pymssql
        conn = pymssql.connect(
            server=host, port=str(port), user=username, password=password,
            database=database or "master", login_timeout=timeout,
        )
        cur = conn.cursor()
        cur.execute("SELECT @@VERSION")
        ver = cur.fetchone()[0].split("\n")[0]
        conn.close()
        return ver, None
    except ImportError:
        return None, "pymssql not installed"
    except Exception as e:
        return None, str(e)


def _test_oracle(host, port, username, password, database, timeout):
    try:
        import oracledb
        dsn = f"{host}:{port}/{database or 'ORCL'}"
        conn = oracledb.connect(user=username, password=password, dsn=dsn)
        cur = conn.cursor()
        cur.execute("SELECT BANNER FROM V$VERSION WHERE ROWNUM=1")
        ver = cur.fetchone()[0]
        conn.close()
        return ver, None
    except ImportError:
        return None, "oracledb not installed"
    except Exception as e:
        return None, str(e)


def _test_mongodb(host, port, username, password, database, ssl_en, timeout):
    try:
        from pymongo import MongoClient
        from urllib.parse import quote_plus
        auth = f"{quote_plus(username)}:{quote_plus(password)}@" if username else ""
        tls = "/?tls=true" if ssl_en else ""
        uri = f"mongodb://{auth}{host}:{port}/{database or 'admin'}{tls}"
        client = MongoClient(uri, serverSelectionTimeoutMS=timeout * 1000)
        info = client.server_info()
        ver = info.get("version", "")
        client.close()
        return ver, None
    except ImportError:
        return None, "pymongo not installed"
    except Exception as e:
        return None, str(e)


def _test_redis(host, port, password, ssl_en, timeout):
    try:
        import redis
        r = redis.Redis(host=host, port=port, password=password or None,
                        ssl=ssl_en, socket_connect_timeout=timeout)
        info = r.info("server")
        ver = info.get("redis_version", "")
        return ver, None
    except ImportError:
        return None, "redis not installed"
    except Exception as e:
        return None, str(e)


def _test_cassandra(host, port, username, password, keyspace, ssl_en, timeout):
    try:
        from cassandra.cluster import Cluster
        from cassandra.auth import PlainTextAuthProvider
        auth = PlainTextAuthProvider(username=username, password=password) if username else None
        ssl_opts = {"ssl_version": ssl.PROTOCOL_TLS} if ssl_en else None
        cluster = Cluster(
            contact_points=[host], port=port,
            auth_provider=auth, ssl_options=ssl_opts,
            connect_timeout=timeout,
        )
        session = cluster.connect(keyspace or None)
        rows = session.execute("SELECT release_version FROM system.local")
        ver = rows[0].release_version if rows else ""
        cluster.shutdown()
        return ver, None
    except ImportError:
        return None, "cassandra-driver not installed"
    except Exception as e:
        return None, str(e)


def _test_elasticsearch(host, port, username, password, ssl_en, timeout):
    try:
        import urllib.request, base64
        scheme = "https" if ssl_en else "http"
        url = f"{scheme}://{host}:{port}/"
        req = urllib.request.Request(url)
        if username:
            tok = base64.b64encode(f"{username}:{password}".encode()).decode()
            req.add_header("Authorization", f"Basic {tok}")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout,
                                      context=ctx if ssl_en else None)
        data = json.loads(resp.read())
        ver = data.get("version", {}).get("number", "")
        return ver, None
    except Exception as e:
        return None, str(e)


def _test_couchdb(host, port, username, password, ssl_en, timeout):
    try:
        import urllib.request, base64
        scheme = "https" if ssl_en else "http"
        url = f"{scheme}://{host}:{port}/"
        req = urllib.request.Request(url)
        if username:
            tok = base64.b64encode(f"{username}:{password}".encode()).decode()
            req.add_header("Authorization", f"Basic {tok}")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout,
                                      context=ctx if ssl_en else None)
        data = json.loads(resp.read())
        if "couchdb" not in data:
            return None, "Not a CouchDB instance"
        return data.get("version", ""), None
    except Exception as e:
        return None, str(e)


def _test_influxdb(host, port, ssl_en, timeout):
    try:
        import urllib.request
        scheme = "https" if ssl_en else "http"
        url = f"{scheme}://{host}:{port}/health"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(url, timeout=timeout,
                                      context=ctx if ssl_en else None)
        data = json.loads(resp.read())
        if data.get("status") != "pass":
            return None, f"InfluxDB health: {data.get('status')}"
        return data.get("version", ""), None
    except Exception as e:
        return None, str(e)


def _test_neo4j(host, port, username, password, ssl_en, timeout):
    try:
        from neo4j import GraphDatabase
        scheme = "bolt+s" if ssl_en else "bolt"
        uri = f"{scheme}://{host}:{port}"
        driver = GraphDatabase.driver(uri, auth=(username, password),
                                       connection_timeout=timeout)
        with driver.session() as sess:
            result = sess.run("CALL dbms.components() YIELD versions")
            row = result.single()
            ver = row["versions"][0] if row and row["versions"] else ""
        driver.close()
        return ver, None
    except ImportError:
        return None, "neo4j not installed"
    except Exception as e:
        return None, str(e)


def _test_memcached(host, port, timeout):
    import socket
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(b"version\r\n")
        sock.settimeout(3.0)
        resp = sock.recv(256).decode(errors="replace").strip()
        sock.close()
        if resp.startswith("VERSION"):
            return resp.split()[-1], None
        return None, f"Unexpected response: {resp}"
    except Exception as e:
        return None, str(e)


def _parse_args():
    p = argparse.ArgumentParser(prog="testConnection.py",
                                description="Auger DB connection tester (Crucible integration)")
    p.add_argument("--settings",  metavar="FILE", help="JSON settings file")
    p.add_argument("--host",      metavar="HOST")
    p.add_argument("--port",      metavar="PORT", type=int, default=0)
    p.add_argument("--db-type",   metavar="TYPE", dest="db_type")
    p.add_argument("-U", "--username", metavar="USER", default="")
    p.add_argument("-P", "--password", metavar="PASS", default="")
    p.add_argument("--database",  metavar="DB",   default="")
    p.add_argument("--ssl",       action="store_true")
    p.add_argument("--timeout",   type=int, default=10)
    return p.parse_args()


def main() -> int:
    args = _parse_args()

    if args.settings:
        try:
            cfg = json.loads(Path(args.settings).read_text())
            scan = cfg.get("scan", {})
        except Exception as e:
            _err(f"Failed to read settings: {e}")
            return 2
        host     = scan.get("host", args.host or "")
        port     = int(scan.get("port", args.port or 0))
        db_type  = scan.get("db_type", args.db_type or "").lower().strip()
        username = scan.get("username", args.username or "")
        password = scan.get("password", args.password or "")
        database = scan.get("database", args.database or "")
        ssl_en   = bool(scan.get("ssl", args.ssl))
        timeout  = int(scan.get("timeout", args.timeout))
    else:
        host     = args.host or ""
        port     = args.port
        db_type  = (args.db_type or "").lower().strip()
        username = args.username
        password = args.password
        database = args.database
        ssl_en   = args.ssl
        timeout  = args.timeout

    _aliases = {
        "postgres": "postgresql", "pg": "postgresql",
        "sqlserver": "mssql", "elastic": "elasticsearch", "es": "elasticsearch",
        "couch": "couchdb", "influx": "influxdb", "mongo": "mongodb",
    }
    db_type = _aliases.get(db_type, db_type)

    if not host:
        _err("No host specified.")
        return 2
    if not db_type:
        _err("No db_type specified.")
        return 2
    if not port:
        port = _DEFAULT_PORTS.get(db_type, 0)

    ver, err = None, "Unsupported db_type"

    if db_type in ("mysql", "mariadb"):
        ver, err = _test_mysql(host, port, username, password, database, ssl_en, timeout)
    elif db_type in ("postgresql", "redshift"):
        ver, err = _test_postgresql(host, port, username, password, database, ssl_en, timeout)
    elif db_type == "mssql":
        ver, err = _test_mssql(host, port, username, password, database, timeout)
    elif db_type == "oracle":
        ver, err = _test_oracle(host, port, username, password, database, timeout)
    elif db_type == "mongodb":
        ver, err = _test_mongodb(host, port, username, password, database, ssl_en, timeout)
    elif db_type == "redis":
        ver, err = _test_redis(host, port, password, ssl_en, timeout)
    elif db_type == "cassandra":
        ver, err = _test_cassandra(host, port, username, password, database, ssl_en, timeout)
    elif db_type == "elasticsearch":
        ver, err = _test_elasticsearch(host, port, username, password, ssl_en, timeout)
    elif db_type == "couchdb":
        ver, err = _test_couchdb(host, port, username, password, ssl_en, timeout)
    elif db_type == "influxdb":
        ver, err = _test_influxdb(host, port, ssl_en, timeout)
    elif db_type == "neo4j":
        ver, err = _test_neo4j(host, port, username, password, ssl_en, timeout)
    elif db_type == "memcached":
        ver, err = _test_memcached(host, port, timeout)

    if err:
        _err(f"Connection failed ({db_type} {host}:{port}): {err}")
        return 1

    _ok(ver or "", db_type)
    return 0


if __name__ == "__main__":
    sys.exit(main())
