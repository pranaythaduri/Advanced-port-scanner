"""
╔══════════════════════════════════════════════════════════════════╗
║   ADVANCED PORT SCANNER  v4.0  —  SUPRAJA TECHNOLOGIES          ║
║   Enterprise Security Assessment Platform                        ║
╚══════════════════════════════════════════════════════════════════╝

INSTALL (one command):
    pip install requests reportlab google-generativeai

GEMINI AI SETUP:
    Create ".env" file next to this script:
        GOOGLE_API_KEY=your_key_here
    Free key: https://makersuite.google.com/app/apikey

RUN:
    python advanced_port_scanner.py

v4.0 CHANGES:
  ✔ Fixed: only OPEN ports shown (UDP false-positive bug eliminated)
  ✔ Fixed: Automated mode fully end-to-end (scan→vuln→Nmap AI→LLM report)
  ✔ Knock-2 AI: cybersecurity-only chatbot sidebar
  ✔ LLM-generated Nmap commands per open port
  ✔ Professional PDF report (CVSS, risks, mitigations, assessor details)
  ✔ About page: full Supraja Technologies company profile
  ✔ Prompt-based LLM scan ("scan google.com 80-443")
"""

# ─── stdlib ────────────────────────────────────────────────────────────────────
import os, sys, re, json, csv, socket, platform, threading, webbrowser
import sqlite3, datetime, subprocess, concurrent.futures
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog

# ─── optional ──────────────────────────────────────────────────────────────────
try:    import requests;                          REQUESTS_OK = True
except: REQUESTS_OK = False

try:    import ftplib;                            FTP_OK = True
except: FTP_OK = False

try:    import smtplib;                           SMTP_OK = True
except: SMTP_OK = False

try:    import google.generativeai as genai;      GEMINI_OK = True
except: GEMINI_OK = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Table,
                                     TableStyle, Spacer, HRFlowable, KeepTogether)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors as rlc
    from reportlab.lib.units import cm
    REPORTLAB_OK = True
except: REPORTLAB_OK = False

# ─── .env loader ───────────────────────────────────────────────────────────────
def _load_env():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
_load_env()

# ─── theme ─────────────────────────────────────────────────────────────────────
BG         = "#0d1117"
SIDEBAR_BG = "#161b22"
CARD_BG    = "#21262d"
ACCENT     = "#00ff88"
ACCENT2    = "#58a6ff"
TEXT       = "#c9d1d9"
TEXT_DIM   = "#8b949e"
RED        = "#f85149"
YELLOW     = "#e3b341"
GREEN      = "#3fb950"
ORANGE     = "#d29922"
BORDER     = "#30363d"
PURPLE     = "#bc8cff"
KNOCK_BG   = "#0a0f1a"
KNOCK_ACC  = "#00d4ff"

SEV_CLR = {"Critical": RED, "High": ORANGE,
           "Medium": YELLOW, "Low": GREEN, "Info": ACCENT2}

# CVSS base scores per severity
CVSS_MAP = {"Critical": "9.0–10.0", "High": "7.0–8.9",
            "Medium": "4.0–6.9",   "Low": "0.1–3.9", "Info": "0.0"}

# ─── paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.join(os.path.expanduser("~"), "Documents",
                          "Advanced_Port_Scanner")
SCANS_DIR = os.path.join(BASE_DIR, "scans")
DB_PATH   = os.path.join(BASE_DIR, "scanner_history.db")
os.makedirs(SCANS_DIR, exist_ok=True)

COMPANY = {
    "name":    "Supraja Technologies",
    "unit":    "a unit of CHSMRLSS Technologies Pvt. Ltd.",
    "city":    "Vijayawada, Andhra Pradesh, India",
    "web":     "www.suprajatechnologies.com",
    "product": "Advanced Port Scanner — Security Assessment Platform",
    "cell":    "Supraja Technologies Cyber Security Cell",
    "rating":  "4.8 ⭐ Google Rated",
    "students":"68,500+ students trained",
}

# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_name TEXT, target TEXT, ip TEXT,
        port_range TEXT, protocol TEXT,
        open_ports TEXT, vulnerabilities TEXT,
        ai_report TEXT, scan_folder TEXT, timestamp TEXT,
        assessor TEXT)""")
    existing = {r[1] for r in conn.execute("PRAGMA table_info(scans)")}
    for col in ["scan_name","ip","port_range","protocol","open_ports",
                "vulnerabilities","ai_report","scan_folder","timestamp","assessor"]:
        if col not in existing:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")
    conn.commit(); conn.close()

def db_save(name, target, ip, pr, proto, rows, vulns, ai, folder, assessor=""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scans(scan_name,target,ip,port_range,protocol,"
        "open_ports,vulnerabilities,ai_report,scan_folder,timestamp,assessor)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (name, target, ip, pr, proto,
         json.dumps([[r[0],r[1],r[2],r[3],r[4]] for r in rows]),
         json.dumps(vulns), ai, folder,
         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), assessor))
    conn.commit(); conn.close()

def db_all():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id,scan_name,target,ip,port_range,protocol,timestamp"
        " FROM scans ORDER BY id DESC LIMIT 300").fetchall()
    conn.close(); return rows

def db_one(sid):
    conn = sqlite3.connect(DB_PATH)
    r = conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    conn.close(); return r

def db_clear():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans"); conn.commit(); conn.close()

# ══════════════════════════════════════════════════════════════════════════════
#  ARTIFACT FOLDER
# ══════════════════════════════════════════════════════════════════════════════
def make_folder(target: str) -> str:
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^\w\-.]", "_", target)
    path = os.path.join(SCANS_DIR, f"{safe}_{ts}")
    os.makedirs(path, exist_ok=True)
    return path

def write_file(folder: str, fname: str, content: str):
    try:
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK UTILITIES
# ══════════════════════════════════════════════════════════════════════════════
def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

def resolve(domain: str):
    try: return socket.gethostbyname(domain.strip())
    except: return None

def tcp_open(host, port, timeout=1.2) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except: return False

def udp_probe(host, port, timeout=2.0) -> bool:
    """
    More reliable UDP check: send a probe, expect a response.
    If ICMP port-unreachable → closed. Timeout → open|filtered.
    Only mark as open if we actually get a UDP response back.
    """
    UDP_PROBES = {
        53:  b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
        123: b"\x1b" + 47 * b"\x00",
        161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    }
    probe = UDP_PROBES.get(port, b"\x00")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(probe, (host, port))
            data, _ = s.recvfrom(1024)
            return len(data) > 0   # got a real UDP response
    except socket.timeout:
        return False   # ← KEY FIX: timeout = unknown, not open
    except ConnectionRefusedError:
        return False   # ICMP port unreachable = definitely closed
    except Exception:
        return False

def grab_banner(host, port) -> str:
    try:
        if port in (80, 8000, 8080, 8888) and REQUESTS_OK:
            r = requests.get(f"http://{host}:{port}", timeout=3, allow_redirects=False)
            srv = r.headers.get("Server", "")
            pw  = r.headers.get("X-Powered-By", "")
            return " | ".join(filter(None, [srv, pw])) or f"HTTP {r.status_code}"
        if port in (443, 8443) and REQUESTS_OK:
            import urllib3; urllib3.disable_warnings()
            r = requests.get(f"https://{host}:{port}", timeout=3,
                             verify=False, allow_redirects=False)
            return r.headers.get("Server", f"HTTPS {r.status_code}")
        if port == 21 and FTP_OK:
            ftp = ftplib.FTP(); ftp.connect(host, 21, timeout=3)
            b = ftp.getwelcome(); ftp.quit(); return b
        if port == 25 and SMTP_OK:
            sm = smtplib.SMTP(host, 25, timeout=3)
            b  = sm.ehlo()[1].decode(errors="ignore"); sm.quit()
            return b.split("\n")[0][:100]
        if port == 22:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3); s.connect((host, 22))
                return s.recv(256).decode(errors="ignore").strip()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2); s.connect((host, port))
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            raw = s.recv(512).decode(errors="ignore").strip()
            return raw.split("\n")[0][:120]
    except: return ""

def svc_name(port, proto="tcp") -> str:
    try: return socket.getservbyport(port, proto)
    except:
        T = {20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",
             53:"dns",67:"dhcp",80:"http",110:"pop3",135:"msrpc",
             137:"netbios",139:"netbios-ssn",143:"imap",443:"https",
             445:"smb",465:"smtps",587:"smtp-sub",993:"imaps",
             995:"pop3s",1433:"mssql",1521:"oracle",3306:"mysql",
             3389:"rdp",5432:"postgresql",5900:"vnc",5985:"winrm",
             6379:"redis",6443:"k8s-api",8000:"http-dev",
             8080:"http-alt",8443:"https-alt",8888:"jupyter",
             9090:"prometheus",9200:"elasticsearch",27017:"mongodb"}
        return T.get(port, "unknown")

# ══════════════════════════════════════════════════════════════════════════════
#  VULNERABILITY DATABASE (port → list of vuln dicts)
# ══════════════════════════════════════════════════════════════════════════════
VULN_DB = {
    21: [{"severity":"High","cve":"CVE-2010-4221","cvss":"7.5",
          "description":"FTP — unencrypted, anonymous login risk",
          "risk":"Credentials transmitted in cleartext; anonymous access may expose files",
          "mitigation":"Use SFTP/FTPS; disable anonymous login; enforce strong passwords; firewall port 21"}],
    22: [{"severity":"High","cve":"CVE-2023-48795","cvss":"5.9",
          "description":"SSH Terrapin attack — handshake security degraded",
          "risk":"Man-in-the-middle can downgrade encryption during SSH handshake",
          "mitigation":"Patch OpenSSH ≥9.6; disable chacha20-poly1305 MAC; enforce key-based auth; disable root login"}],
    23: [{"severity":"Critical","cve":"N/A","cvss":"9.8",
          "description":"Telnet — cleartext credentials over network",
          "risk":"All traffic including passwords interceptable by network sniffers",
          "mitigation":"Disable Telnet IMMEDIATELY; replace with SSH 2.0; block port 23 at firewall"}],
    25: [{"severity":"High","cve":"Multiple","cvss":"7.5",
          "description":"SMTP exposed — open relay and user enumeration risk",
          "risk":"Spam distribution, phishing campaigns, user enumeration via VRFY/EXPN",
          "mitigation":"Require SMTP AUTH; configure SPF/DKIM/DMARC; disable VRFY/EXPN; rate-limit connections"}],
    53: [{"severity":"Medium","cve":"CVE-2023-50868","cvss":"5.3",
          "description":"DNS — amplification and cache poisoning risk",
          "risk":"DDoS amplification, DNS hijacking, cache poisoning attacks",
          "mitigation":"Enable DNSSEC; restrict recursive queries to internal IPs; rate-limit DNS responses"}],
    80: [{"severity":"High","cve":"Multiple","cvss":"7.5",
          "description":"HTTP — unencrypted web service",
          "risk":"All data including credentials interceptable; session hijacking via MITM",
          "mitigation":"Migrate to HTTPS (443); implement HSTS; redirect all HTTP to HTTPS"}],
    110:[{"severity":"High","cve":"N/A","cvss":"7.5",
          "description":"POP3 — cleartext email retrieval",
          "risk":"Email content and credentials readable on network",
          "mitigation":"Replace with POP3S on port 995; enforce TLS; disable plaintext auth"}],
    135:[{"severity":"Critical","cve":"CVE-2023-23397","cvss":"9.8",
          "description":"MS-RPC endpoint mapper — remote code execution vector",
          "risk":"Full system compromise possible via RPC vulnerability exploitation",
          "mitigation":"Block port 135 at firewall; apply all Windows security patches; disable unnecessary RPC services"}],
    139:[{"severity":"High","cve":"CVE-2021-1675","cvss":"7.8",
          "description":"NetBIOS-SSN — SMB relay and null session attacks",
          "risk":"Lateral movement, credential harvesting, share enumeration",
          "mitigation":"Disable NetBIOS over TCP/IP; block ports 137-139; use SMB3 only"}],
    143:[{"severity":"High","cve":"N/A","cvss":"7.5",
          "description":"IMAP — cleartext email protocol",
          "risk":"Email content and login credentials visible on network",
          "mitigation":"Replace with IMAPS on port 993; enforce TLS 1.2+; disable plaintext"}],
    443:[{"severity":"Medium","cve":"Multiple","cvss":"5.9",
          "description":"HTTPS — verify TLS version and cipher configuration",
          "risk":"MITM attacks if TLS 1.0/1.1 or weak ciphers enabled",
          "mitigation":"Enforce TLS 1.2+ (prefer 1.3); use strong cipher suites; enable HSTS; valid cert required"}],
    445:[{"severity":"Critical","cve":"MS17-010 / CVE-2021-1675","cvss":"9.8",
          "description":"SMB — EternalBlue and PrintNightmare RCE vulnerabilities",
          "risk":"Remote code execution, ransomware deployment, complete system takeover",
          "mitigation":"Block SMB externally (firewall); apply MS17-010 patch; use SMB 3.1.1+; disable SMBv1"}],
    1433:[{"severity":"Critical","cve":"Multiple","cvss":"9.8",
           "description":"MSSQL exposed — SQL injection and authentication bypass",
           "risk":"Full database compromise, data exfiltration, server takeover",
           "mitigation":"Firewall port 1433; use Windows Authentication; disable 'sa' account; enable encryption"}],
    3306:[{"severity":"Critical","cve":"CVE-2021-2122","cvss":"9.1",
           "description":"MySQL exposed on network — potential unauthenticated root access",
           "risk":"Full database read/write/delete; data theft; possible OS command execution",
           "mitigation":"Bind MySQL to 127.0.0.1 only; require SSL; strong root password; firewall port 3306"}],
    3389:[{"severity":"Critical","cve":"CVE-2019-0708 BlueKeep","cvss":"9.8",
           "description":"RDP — remote code execution and brute force attacks",
           "risk":"Complete remote system takeover; credential spraying attacks",
           "mitigation":"Require VPN for RDP; enable NLA; block port 3389 publicly; apply BlueKeep patch"}],
    5432:[{"severity":"Critical","cve":"Multiple","cvss":"9.1",
           "description":"PostgreSQL on network — trust authentication and injection risks",
           "risk":"Data breach, arbitrary SQL execution, privilege escalation",
           "mitigation":"Restrict pg_hba.conf; enforce SSL; strong passwords; block port 5432 externally"}],
    5900:[{"severity":"Critical","cve":"N/A","cvss":"9.8",
           "description":"VNC — weak/no authentication, unencrypted sessions",
           "risk":"Full remote desktop access; screen surveillance; file transfer",
           "mitigation":"Strong VNC password; tunnel through SSH/VPN; block port 5900 externally"}],
    5985:[{"severity":"High","cve":"N/A","cvss":"8.1",
           "description":"WinRM — PowerShell remoting exposed to network",
           "risk":"Remote command execution, lateral movement, privilege escalation",
           "mitigation":"Restrict WinRM to known hosts; require HTTPS (5986); use firewall rules"}],
    6379:[{"severity":"Critical","cve":"N/A","cvss":"9.8",
           "description":"Redis — no authentication by default, RCE via config write",
           "risk":"Full data access; write arbitrary files; potential OS command execution",
           "mitigation":"Enable requirepass; bind to 127.0.0.1; firewall port 6379; rename CONFIG command"}],
    8080:[{"severity":"High","cve":"Multiple","cvss":"7.5",
           "description":"HTTP-alt — admin consoles (Tomcat/Jenkins/etc.) often exposed",
           "risk":"Default credentials, admin panel access, web application vulnerabilities",
           "mitigation":"Change default credentials; restrict access; move behind reverse proxy with auth"}],
    9200:[{"severity":"Critical","cve":"N/A","cvss":"9.8",
           "description":"Elasticsearch — no authentication in default configuration",
           "risk":"All indexed data publicly readable; cluster commands executable",
           "mitigation":"Enable Elasticsearch security (xpack); firewall port 9200; use TLS"}],
    27017:[{"severity":"Critical","cve":"N/A","cvss":"9.8",
            "description":"MongoDB — no authentication in older default config",
            "risk":"Full database read/write/delete access without credentials",
            "mitigation":"Enable MongoDB auth; bind to localhost; firewall port 27017; update to latest"}],
}

# Nmap command templates per port (for AI/manual reference)
NMAP_CMDS = {
    21:  ["nmap -sV -p 21 {ip}",
          "nmap --script ftp-anon,ftp-bounce,ftp-brute -p 21 {ip}"],
    22:  ["nmap -sV -p 22 {ip}",
          "nmap --script ssh-brute,ssh2-enum-algos,ssh-auth-methods -p 22 {ip}"],
    23:  ["nmap -sV -p 23 {ip}",
          "nmap --script telnet-brute,telnet-ntlm-info -p 23 {ip}"],
    25:  ["nmap -sV -p 25 {ip}",
          "nmap --script smtp-open-relay,smtp-enum-users,smtp-commands -p 25 {ip}"],
    53:  ["nmap -sV -p 53 {ip}",
          "nmap --script dns-zone-transfer,dns-recursion,dns-nsid -p 53 {ip}"],
    80:  ["nmap -sV -p 80 {ip}",
          "nmap --script http-methods,http-headers,http-sql-injection,http-stored-xss -p 80 {ip}",
          "nmap --script http-vuln* -p 80 {ip}"],
    110: ["nmap -sV -p 110 {ip}",
          "nmap --script pop3-brute -p 110 {ip}"],
    135: ["nmap -sV -p 135 {ip}",
          "nmap --script msrpc-enum -p 135 {ip}"],
    139: ["nmap -sV -p 139 {ip}",
          "nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery -p 139 {ip}"],
    143: ["nmap -sV -p 143 {ip}",
          "nmap --script imap-brute -p 143 {ip}"],
    443: ["nmap -sV -p 443 {ip}",
          "nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle -p 443 {ip}",
          "nmap --script http-vuln* -p 443 {ip}"],
    445: ["nmap -sV -p 445 {ip}",
          "nmap --script smb-vuln-ms17-010,smb-security-mode,smb-protocols -p 445 {ip}",
          "nmap --script smb-brute,smb-enum-shares,smb-enum-users -p 445 {ip}"],
    1433:["nmap -sV -p 1433 {ip}",
          "nmap --script ms-sql-info,ms-sql-brute,ms-sql-empty-password -p 1433 {ip}"],
    3306:["nmap -sV -p 3306 {ip}",
          "nmap --script mysql-brute,mysql-empty-password,mysql-info -p 3306 {ip}"],
    3389:["nmap -sV -p 3389 {ip}",
          "nmap --script rdp-vuln-ms12-020,rdp-enum-encryption -p 3389 {ip}"],
    5432:["nmap -sV -p 5432 {ip}",
          "nmap --script pgsql-brute -p 5432 {ip}"],
    5900:["nmap -sV -p 5900 {ip}",
          "nmap --script vnc-brute,vnc-info -p 5900 {ip}"],
    6379:["nmap -sV -p 6379 {ip}",
          "nmap --script redis-info -p 6379 {ip}"],
    8080:["nmap -sV -p 8080 {ip}",
          "nmap --script http-methods,http-open-proxy,http-auth-finder -p 8080 {ip}"],
    9200:["nmap -sV -p 9200 {ip}",
          "nmap --script http-methods -p 9200 {ip}"],
    27017:["nmap -sV -p 27017 {ip}",
           "nmap --script mongodb-info,mongodb-databases -p 27017 {ip}"],
}
DEFAULT_NMAP = ["nmap -sV -p {port} {ip}", "nmap -A -p {port} {ip}"]

MANUAL_CHECKS = {
    21: [("Anonymous Login","ftp {ip}  → user: anonymous  pass: (blank)"),
         ("FTP Version","Connect and read welcome banner")],
    22: [("SSH Banner","ssh -v {ip}  → check version string"),
         ("Key Auth Only","Verify PasswordAuthentication=no in sshd_config")],
    23: [("Telnet Connect","telnet {ip}  → ALL TRAFFIC IS CLEARTEXT"),
         ("Disable Now","Replace with SSH immediately")],
    25: [("SMTP Banner","telnet {ip} 25  →  EHLO test"),
         ("Open Relay","MAIL FROM:<x@x.com>  RCPT TO:<z@z.com>"),
         ("VRFY Enum","VRFY root  VRFY admin")],
    53: [("Zone Transfer","nslookup -type=AXFR domain.com {ip}"),
         ("Open Resolver","nslookup google.com {ip}")],
    80: [("HTTP Headers","curl -I http://{ip}/"),
         ("Admin Paths","Try /admin /login /wp-admin /phpmyadmin in browser"),
         ("Default Creds","admin:admin  admin:password  root:root")],
    443:[("TLS Version","curl -vI https://{ip}/  → check TLS version"),
         ("Cert Check","Verify certificate validity and expiry in browser")],
    445:[("SMB Null Session","net use \\\\{ip}\\IPC$  (Windows)"),
         ("EternalBlue","Verify MS17-010 patch applied")],
    3306:[("MySQL Root","mysql -h {ip} -u root  (try blank password)"),
          ("MySQL Version","mysql -h {ip} -u root -e 'SELECT version()'")],
    3389:[("RDP Connect","mstsc /v:{ip}  (Windows built-in RDP client)"),
          ("NLA Check","Verify NLA required before credential prompt")],
    6379:[("Redis PING","redis-cli -h {ip}  →  PING"),
          ("Redis Config","redis-cli -h {ip} CONFIG GET *")],
    8080:[("Admin Console","http://{ip}:8080/manager  /admin  /console"),
          ("Default Creds","tomcat:tomcat  admin:admin")],
}
DEFAULT_CHECKS = [
    ("Version Detect","Connect and read banner from {ip}:{port}"),
    ("Default Creds","Try common username/password combinations"),
    ("CVE Search","https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={service}"),
]

# ══════════════════════════════════════════════════════════════════════════════
#  PROMPT PARSER
# ══════════════════════════════════════════════════════════════════════════════
def parse_prompt(text: str):
    t = text.strip().lower()
    tm = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9\-]+\.[a-z]{2,})", t)
    target = tm.group(1) if tm else None
    rm = re.search(r"(\d+)\s*[-–to]+\s*(\d+)", t)
    if rm: sp, ep = int(rm.group(1)), int(rm.group(2))
    else:
        sm = re.search(r"port[s]?\s+(\d+)", t)
        sp = ep = int(sm.group(1)) if sm else None
    return target, sp, ep

# ══════════════════════════════════════════════════════════════════════════════
#  GEMINI HELPER
# ══════════════════════════════════════════════════════════════════════════════
def gemini_ask(prompt: str, system: str = "") -> str:
    """Call Gemini API. Returns response text or error string."""
    api_key = os.getenv("GOOGLE_API_KEY", "")
    if not GEMINI_OK:
        return "❌ google-generativeai not installed.\nRun: pip install google-generativeai"
    if not api_key:
        return ("❌ GOOGLE_API_KEY not set.\n"
                "Create .env file with: GOOGLE_API_KEY=your_key\n"
                "Get free key: https://makersuite.google.com/app/apikey")
    import time, random
    models = ["gemini-2.5-flash","gemini-2.0-flash","gemini-1.5-flash","gemini-1.5-pro"]
    for attempt in range(4):
        try:
            genai.configure(api_key=api_key)
            model = None
            for m in models:
                try: model = genai.GenerativeModel(m); break
                except: continue
            if model is None: return "❌ No Gemini model available."
            full_prompt = f"{system}\n\n{prompt}" if system else prompt
            resp = model.generate_content(full_prompt)
            return resp.text or "No response from Gemini."
        except Exception as exc:
            es = str(exc).lower()
            if ("429" in es or "quota" in es) and attempt < 3:
                delay = min(2**(attempt+1) + random.uniform(0,1), 45)
                time.sleep(delay)
            else:
                return f"❌ Gemini error: {exc}"
    return "❌ Gemini quota exceeded. Try again later."

# ══════════════════════════════════════════════════════════════════════════════
#  TOOLTIP
# ══════════════════════════════════════════════════════════════════════════════
class ToolTip:
    def __init__(self, widget, text):
        self._tip = None
        widget.bind("<Enter>", lambda _: self._show(widget, text))
        widget.bind("<Leave>", lambda _: self._hide())
    def _show(self, w, text):
        x = w.winfo_rootx()+20; y = w.winfo_rooty()+28
        self._tip = tk.Toplevel(w); self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self._tip, text=text, bg=CARD_BG, fg=TEXT,
                 relief="solid", borderwidth=1, padx=8, pady=4,
                 font=("Segoe UI",9)).pack()
    def _hide(self):
        if self._tip: self._tip.destroy(); self._tip = None

# ══════════════════════════════════════════════════════════════════════════════
#  ERROR ASSISTANT
# ══════════════════════════════════════════════════════════════════════════════
class ErrAssist:
    def __init__(self, root):
        self.root = root; self._win = None
    def report(self, msg, fix=""):
        try:
            if self._win and self._win.winfo_exists(): self._win.destroy()
            self._win = tk.Toplevel(self.root)
            self._win.title("⚠ Error Assistant")
            rx = self.root.winfo_x()+self.root.winfo_width()-385
            ry = self.root.winfo_y()+self.root.winfo_height()-215
            self._win.geometry(f"370x190+{rx}+{ry}")
            self._win.configure(bg=CARD_BG)
            self._win.attributes("-topmost", True)
            tk.Label(self._win, text="⚠ Error Assistant",
                     fg=RED, bg=CARD_BG, font=("Segoe UI",9,"bold")).pack(
                         anchor="w", padx=10, pady=(8,2))
            tk.Label(self._win, text=msg, fg=TEXT, bg=CARD_BG,
                     font=("Segoe UI",9), wraplength=350,
                     justify="left").pack(anchor="w", padx=10)
            if fix:
                tk.Label(self._win, text=f"Fix: {fix}", fg=GREEN, bg=CARD_BG,
                         font=("Segoe UI",9), wraplength=350,
                         justify="left").pack(anchor="w", padx=10, pady=(3,0))
            tk.Button(self._win, text="Dismiss", bg=BORDER, fg=TEXT,
                      bd=0, padx=10, pady=3, cursor="hand2",
                      command=self._win.destroy).pack(pady=6)
            self.root.after(8000, lambda: self._win.destroy()
                            if self._win and self._win.winfo_exists() else None)
        except: pass

# ══════════════════════════════════════════════════════════════════════════════
#  KNOCK-2 AI CHATBOT WINDOW
# ══════════════════════════════════════════════════════════════════════════════
KNOCK2_SYSTEM = """You are Knock-2 AI, a specialized cybersecurity assistant built into the
Advanced Port Scanner by Supraja Technologies.

YOUR STRICT BOUNDARIES:
- You ONLY answer cybersecurity-related questions
- Topics allowed: port scanning, vulnerabilities, CVEs, network security, penetration testing,
  nmap commands, firewall rules, security hardening, threat analysis, OSINT, ethical hacking,
  malware analysis, incident response, CTF challenges, security tools
- If asked anything outside cybersecurity, politely decline and redirect to security topics
- Never help with: general coding, cooking, relationships, entertainment, math homework, etc.
- Always recommend ethical and legal security practices
- Sign your responses as: — Knock-2 AI | Supraja Technologies Cyber Security Cell

Be concise, technical, and actionable. Use bullet points for lists."""

class Knock2Window:
    def __init__(self, parent):
        self.parent = parent
        self.win = tk.Toplevel(parent)
        self.win.title("Knock-2 AI — Cybersecurity Assistant")
        self.win.geometry("480x680")
        self.win.configure(bg=KNOCK_BG)
        self.win.resizable(True, True)
        self.history = []
        self._build()

    def _build(self):
        # Header
        hdr = tk.Frame(self.win, bg="#0f1824", pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔐 Knock-2 AI",
                 font=("Segoe UI", 14, "bold"),
                 fg=KNOCK_ACC, bg="#0f1824").pack(side="left", padx=14)
        tk.Label(hdr, text="Cybersecurity Assistant",
                 font=("Segoe UI", 9),
                 fg=TEXT_DIM, bg="#0f1824").pack(side="left")
        tk.Label(hdr, text="Supraja Technologies",
                 font=("Segoe UI", 8),
                 fg=ACCENT, bg="#0f1824").pack(side="right", padx=14)

        tk.Frame(self.win, bg=BORDER, height=1).pack(fill="x")

        # Chat area
        self.chat = scrolledtext.ScrolledText(
            self.win, bg="#080e18", fg=TEXT,
            font=("Segoe UI", 9), bd=0, padx=12, pady=10,
            insertbackground=KNOCK_ACC, wrap="word",
            state="disabled")
        self.chat.pack(fill="both", expand=True, padx=0, pady=0)
        self.chat.tag_configure("user", foreground=KNOCK_ACC,
                                font=("Segoe UI", 9, "bold"))
        self.chat.tag_configure("ai",   foreground=TEXT)
        self.chat.tag_configure("sys",  foreground=TEXT_DIM,
                                font=("Segoe UI", 8, "italic"))
        self.chat.tag_configure("err",  foreground=RED)

        # Quick prompts
        qf = tk.Frame(self.win, bg=KNOCK_BG); qf.pack(fill="x", padx=8, pady=(4,0))
        tk.Label(qf, text="Quick:", fg=TEXT_DIM, bg=KNOCK_BG,
                 font=("Segoe UI", 8)).pack(side="left")
        for q in ["nmap for SMB", "fix RDP exposure", "CVE-2023-48795",
                  "harden SSH", "Redis security"]:
            tk.Button(qf, text=q, bg=CARD_BG, fg=KNOCK_ACC,
                      font=("Segoe UI", 8), bd=0, padx=6, pady=2,
                      cursor="hand2",
                      command=lambda t=q: self._send(t)).pack(
                          side="left", padx=2, pady=3)

        # Input bar
        inf = tk.Frame(self.win, bg="#0f1824", pady=8)
        inf.pack(fill="x", padx=0)
        self.inp = tk.Entry(inf, bg=CARD_BG, fg=TEXT, font=("Segoe UI", 10),
                             insertbackground=KNOCK_ACC, relief="flat",
                             highlightthickness=1,
                             highlightbackground=BORDER,
                             highlightcolor=KNOCK_ACC)
        self.inp.pack(side="left", fill="x", expand=True, padx=(12,6))
        self.inp.bind("<Return>", lambda _: self._send())
        tk.Button(inf, text="Ask →", bg=KNOCK_ACC, fg="#000",
                  font=("Segoe UI", 10, "bold"), bd=0,
                  padx=12, pady=5, cursor="hand2",
                  command=self._send).pack(side="right", padx=(0,12))

        # Welcome message
        self._append("sys", "Knock-2 AI ready. Ask me anything about cybersecurity.\n"
                             "I only answer security-related questions.\n")

    def _append(self, tag: str, text: str):
        self.chat.configure(state="normal")
        self.chat.insert("end", text + "\n", tag)
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def _send(self, text=None):
        msg = text or self.inp.get().strip()
        if not msg: return
        self.inp.delete(0, "end")
        self._append("user", f"You: {msg}")
        self._append("sys", "Knock-2 thinking…")
        self.history.append({"role": "user", "content": msg})
        threading.Thread(target=self._ask, args=(msg,), daemon=True).start()

    def _ask(self, msg: str):
        resp = gemini_ask(msg, KNOCK2_SYSTEM)
        self.win.after(0, lambda: (
            self._append("ai", f"Knock-2: {resp}\n")))

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class AdvancedPortScanner:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Advanced Port Scanner  v4.0  |  Supraja Technologies")
        self.root.geometry("1340x900")
        self.root.minsize(1000, 680)
        self.root.configure(bg=BG)

        self.scanning     = False
        self.scan_results = []          # (port, svc, proto, status, banner)
        self.vuln_results = {}          # str(port) → {service, protocol, banner, vulnerabilities}
        self.nmap_cmds    = {}          # str(port) → [cmd, ...]
        self.ai_text      = ""
        self.scan_folder  = ""
        self.log_lines    = []
        self.err_lines    = []
        self._open_ct     = 0
        self._err_ct      = 0
        self.assessor_var = tk.StringVar(value="Security Analyst")
        self.err_asst     = ErrAssist(root)

        init_db()
        self._styles()
        self._build_ui()

    # ── TTK styles ──────────────────────────────────────────────────────────
    def _styles(self):
        s = ttk.Style(); s.theme_use("default")
        for n in ("Scanner","History","Vuln"):
            s.configure(f"{n}.Treeview", background=CARD_BG, foreground=TEXT,
                        rowheight=26, fieldbackground=CARD_BG, borderwidth=0,
                        font=("Segoe UI",9))
            s.configure(f"{n}.Treeview.Heading", background=SIDEBAR_BG,
                        foreground=ACCENT, font=("Segoe UI",9,"bold"), relief="flat")
            s.map(f"{n}.Treeview",
                  background=[("selected",ACCENT2)], foreground=[("selected","#000")])
        s.configure("Horizontal.TProgressbar", troughcolor=CARD_BG, background=ACCENT)
        s.configure("TCombobox", fieldbackground=CARD_BG, background=CARD_BG,
                    foreground=TEXT, arrowcolor=TEXT)
        s.map("TCombobox", fieldbackground=[("readonly",CARD_BG)])

    # ── Layout ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        sb = tk.Frame(self.root, bg=SIDEBAR_BG, width=185)
        sb.pack(side="left", fill="y"); sb.pack_propagate(False)
        tk.Label(sb, text="⚡ APS", font=("Segoe UI",16,"bold"),
                 fg=ACCENT, bg=SIDEBAR_BG, pady=16).pack()
        tk.Frame(sb, bg=BORDER, height=1).pack(fill="x", padx=12)

        self._nav = {}
        for key, icon, lbl in [("scanner","🔍"," Scanner"),
                                ("history","📋"," History"),
                                ("tools",  "🛠"," Tools"),
                                ("about",  "🏢"," About")]:
            b = tk.Button(sb, text=f"  {icon}{lbl}", anchor="w",
                          bg=SIDEBAR_BG, fg=TEXT, bd=0, padx=18, pady=12,
                          font=("Segoe UI",10), cursor="hand2",
                          activebackground=CARD_BG, activeforeground=ACCENT,
                          command=lambda k=key: self._show(k))
            b.pack(fill="x"); self._nav[key] = b

        # Knock-2 AI button at sidebar bottom
        tk.Frame(sb, bg=BORDER, height=1).pack(fill="x", padx=12, pady=6)
        tk.Button(sb, text="🤖 Knock-2 AI\nCyber Assistant",
                  bg="#0f1824", fg=KNOCK_ACC,
                  font=("Segoe UI",9,"bold"), bd=0, padx=10, pady=10,
                  cursor="hand2", justify="center",
                  command=self._open_knock2).pack(fill="x", padx=8, pady=4)
        tk.Frame(sb, bg=BORDER, height=1).pack(
            fill="x", padx=12, side="bottom", pady=4)
        tk.Label(sb, text=f"Local IP\n{local_ip()}",
                 font=("Segoe UI",8), fg=TEXT_DIM,
                 bg=SIDEBAR_BG, pady=8).pack(side="bottom")

        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(side="right", fill="both", expand=True)
        self._pages = {
            "scanner": self._page_scanner(),
            "history": self._page_history(),
            "tools":   self._page_tools(),
            "about":   self._page_about(),
        }
        self._show("scanner")

    def _show(self, page: str):
        for f in self._pages.values(): f.pack_forget()
        self._pages[page].pack(fill="both", expand=True)
        for k, b in self._nav.items():
            b.configure(bg=CARD_BG if k==page else SIDEBAR_BG,
                        fg=ACCENT  if k==page else TEXT)

    def _open_knock2(self):
        Knock2Window(self.root)

    # ══════════════════════════════════════════════════════════════════════
    #  SCANNER PAGE
    # ══════════════════════════════════════════════════════════════════════
    def _page_scanner(self):
        frame = tk.Frame(self.content, bg=BG)

        # heading
        hdr = tk.Frame(frame, bg=BG); hdr.pack(fill="x", padx=20, pady=(12,4))
        tk.Label(hdr, text="Advanced Port Scanner",
                 font=("Segoe UI",17,"bold"), fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(hdr, text="Enterprise v4.0  |  Supraja Technologies",
                 font=("Segoe UI",9), fg=TEXT_DIM, bg=BG).pack(side="left", padx=12)

        # Prompt bar with LLM parse
        pf = tk.Frame(frame, bg=CARD_BG); pf.pack(fill="x", padx=20, pady=(0,6))
        pi = tk.Frame(pf, bg=CARD_BG, padx=12, pady=8); pi.pack(fill="x")
        tk.Label(pi, text="💬 Prompt (LLM):", fg=KNOCK_ACC, bg=CARD_BG,
                 font=("Segoe UI",9,"bold")).pack(side="left")
        self.prompt_e = tk.Entry(pi, bg="#0d1117", fg=TEXT, font=("Segoe UI",9),
                                  insertbackground=ACCENT, relief="flat",
                                  highlightthickness=1, highlightbackground=BORDER,
                                  highlightcolor=KNOCK_ACC)
        self.prompt_e.insert(0, 'e.g. "scan 192.168.1.1 ports 80-443"')
        self.prompt_e.bind("<FocusIn>",
            lambda _: self.prompt_e.delete(0,"end")
            if "e.g." in self.prompt_e.get() else None)
        self.prompt_e.pack(side="left", fill="x", expand=True, padx=8)
        tk.Button(pi, text="🤖 AI Parse", bg=KNOCK_ACC, fg="#000",
                  font=("Segoe UI",9,"bold"), bd=0, padx=10, pady=3,
                  cursor="hand2", command=self._ai_parse_prompt).pack(side="left", padx=(0,4))
        tk.Button(pi, text="Parse", bg=CARD_BG, fg=TEXT_DIM,
                  font=("Segoe UI",9), bd=1, relief="solid",
                  padx=8, pady=3, cursor="hand2",
                  command=self._parse_prompt).pack(side="left")

        # input card
        card  = tk.Frame(frame, bg=CARD_BG); card.pack(fill="x", padx=20, pady=(0,6))
        inner = tk.Frame(card, bg=CARD_BG, padx=20, pady=12); inner.pack(fill="x")

        # row1: domain / ip
        r1 = tk.Frame(inner, bg=CARD_BG); r1.pack(fill="x", pady=3)
        tk.Label(r1, text="Domain:", fg=TEXT_DIM, bg=CARD_BG,
                 font=("Segoe UI",9), width=10, anchor="w").grid(row=0, column=0)
        self.domain_e = self._ent(r1)
        self.domain_e.grid(row=0, column=1, sticky="ew", padx=(8,8))
        rb = tk.Button(r1, text="Resolve →", bg=ACCENT2, fg="#000",
                       font=("Segoe UI",9,"bold"), bd=0, padx=9, pady=3,
                       cursor="hand2", command=self._resolve)
        rb.grid(row=0, column=2, padx=(0,20)); ToolTip(rb, "Domain → IP")
        tk.Label(r1, text="IP:", fg=TEXT_DIM, bg=CARD_BG,
                 font=("Segoe UI",9), width=4, anchor="w").grid(row=0, column=3)
        self.ip_e = self._ent(r1)
        self.ip_e.grid(row=0, column=4, sticky="ew", padx=(8,0))
        r1.columnconfigure(1, weight=2); r1.columnconfigure(4, weight=2)

        # row2: ports + assessor
        r2 = tk.Frame(inner, bg=CARD_BG); r2.pack(fill="x", pady=3)
        tk.Label(r2, text="Start Port:", fg=TEXT_DIM, bg=CARD_BG,
                 font=("Segoe UI",9), width=10, anchor="w").grid(row=0, column=0)
        self.sp_e = self._ent(r2, "1"); self.sp_e.grid(row=0, column=1, sticky="ew", padx=(8,8))
        tk.Label(r2, text="End Port:", fg=TEXT_DIM, bg=CARD_BG,
                 font=("Segoe UI",9), width=8, anchor="w").grid(row=0, column=2)
        self.ep_e = self._ent(r2, "1024"); self.ep_e.grid(row=0, column=3, sticky="ew", padx=(8,20))
        tk.Label(r2, text="Assessor:", fg=TEXT_DIM, bg=CARD_BG,
                 font=("Segoe UI",9), width=8, anchor="w").grid(row=0, column=4)
        ae = self._ent(r2); ae.config(textvariable=self.assessor_var)
        ae.grid(row=0, column=5, sticky="ew", padx=(8,0))
        r2.columnconfigure(1, weight=2); r2.columnconfigure(3, weight=2)
        r2.columnconfigure(5, weight=1)

        # row3: controls
        r3 = tk.Frame(inner, bg=CARD_BG); r3.pack(fill="x", pady=6)
        tk.Label(r3, text="Protocol:", fg=TEXT_DIM, bg=CARD_BG,
                 font=("Segoe UI",9)).pack(side="left")
        self.proto_var = tk.StringVar(value="TCP")        # ← independent
        ttk.Combobox(r3, textvariable=self.proto_var,
                     values=["TCP","UDP","BOTH"],
                     width=7, state="readonly").pack(side="left", padx=(5,14))
        tk.Label(r3, text="Mode:", fg=TEXT_DIM, bg=CARD_BG,
                 font=("Segoe UI",9)).pack(side="left")
        self.mode_var = tk.StringVar(value="Traditional")  # ← independent
        ttk.Combobox(r3, textvariable=self.mode_var,
                     values=["Traditional","Automated"],
                     width=12, state="readonly").pack(side="left", padx=(5,14))
        self.allports_var = tk.BooleanVar(value=False)
        tk.Checkbutton(r3, text="Scan All Ports (0–65535)",
                       variable=self.allports_var,
                       bg=CARD_BG, fg=TEXT, selectcolor=CARD_BG,
                       activebackground=CARD_BG, activeforeground=ACCENT,
                       font=("Segoe UI",9), cursor="hand2").pack(side="left")
        self.stop_btn = tk.Button(r3, text="■ Stop", bg=RED, fg="white",
                                   font=("Segoe UI",10,"bold"), bd=0,
                                   padx=14, pady=5, cursor="hand2",
                                   state="disabled", command=self._stop)
        self.stop_btn.pack(side="right", padx=(6,0))
        self.scan_btn = tk.Button(r3, text="▶ Start Scan", bg=ACCENT, fg="#000",
                                   font=("Segoe UI",10,"bold"), bd=0,
                                   padx=18, pady=5, cursor="hand2",
                                   command=self._start)
        self.scan_btn.pack(side="right")
        tk.Button(r3, text="⬇ CSV", bg=CARD_BG, fg=TEXT_DIM,
                  font=("Segoe UI",9), bd=1, relief="solid",
                  padx=9, pady=4, cursor="hand2",
                  command=self._export_csv).pack(side="right", padx=(0,8))

        # status strip
        ss = tk.Frame(frame, bg=SIDEBAR_BG); ss.pack(fill="x", padx=20, pady=(0,3))
        self.status_var  = tk.StringVar(value="Ready — enter target and click ▶ Start Scan")
        self.curport_var = tk.StringVar(value="Port: —")
        self.openct_var  = tk.StringVar(value="Open: 0")
        self.errct_var   = tk.StringVar(value="Errors: 0")
        tk.Label(ss, textvariable=self.status_var, fg=TEXT_DIM, bg=SIDEBAR_BG,
                 font=("Segoe UI",9), anchor="w").pack(
                     side="left", fill="x", expand=True, padx=8, pady=4)
        for var, fg in [(self.openct_var,GREEN),(self.errct_var,RED),(self.curport_var,ACCENT2)]:
            tk.Label(ss, textvariable=var, fg=fg, bg=SIDEBAR_BG,
                     font=("Segoe UI",9)).pack(side="right", padx=8)

        self.prog_var = tk.DoubleVar()
        ttk.Progressbar(frame, variable=self.prog_var, maximum=100,
                        style="Horizontal.TProgressbar").pack(
                            fill="x", padx=20, pady=(0,4))

        # results table
        tf = tk.Frame(frame, bg=BG); tf.pack(fill="both", expand=True, padx=20, pady=(0,5))
        cols = ("Port","Service","Protocol","Status","Banner / Version")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings",
                                  style="Scanner.Treeview")
        for col, w in zip(cols, [72,110,80,68,0]):
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort(c))
            self.tree.column(col, width=w, stretch=(col=="Banner / Version"))
        self.tree.tag_configure("open", foreground=GREEN)
        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1); tf.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self._on_dbl)
        ToolTip(self.tree, "Double-click for deep analysis, Nmap AI commands & vulnerability details")

        self.empty_lbl = tk.Label(frame, text="No open ports found on target.",
                                   fg=TEXT_DIM, bg=BG, font=("Segoe UI",11))

        # vuln summary bar
        vs = tk.Frame(frame, bg=CARD_BG); vs.pack(fill="x", padx=20, pady=(0,3))
        tk.Label(vs, text="🔴 Vuln Summary:", fg=RED, bg=CARD_BG,
                 font=("Segoe UI",9,"bold"), padx=10, pady=5).pack(side="left")
        self.vuln_sum_var = tk.StringVar(value="Run a scan to see vulnerability summary.")
        tk.Label(vs, textvariable=self.vuln_sum_var, fg=TEXT, bg=CARD_BG,
                 font=("Segoe UI",9)).pack(side="left")
        tk.Button(vs, text="View All Vulns", bg=CARD_BG, fg=ORANGE,
                  font=("Segoe UI",9), bd=1, relief="solid",
                  padx=8, pady=3, cursor="hand2",
                  command=self._show_vulns).pack(side="right", padx=10, pady=4)

        # AI panel
        aih = tk.Frame(frame, bg=CARD_BG); aih.pack(fill="x", padx=20)
        tk.Label(aih, text="🤖 AI Security Report (Google Gemini)",
                 fg=ACCENT, bg=CARD_BG, font=("Segoe UI",10,"bold"),
                 padx=12, pady=6).pack(side="left")
        for txt, cmd, bg_c, fg_c in [
            ("Save PDF",         self._save_pdf,    CARD_BG, TEXT_DIM),
            ("Save Mitigation",  self._save_mit,    CARD_BG, TEXT_DIM),
            ("Generate Report",  self._ai_report,   ACCENT2, "#000"),
        ]:
            tk.Button(aih, text=txt, bg=bg_c, fg=fg_c,
                      font=("Segoe UI",9,"bold" if bg_c==ACCENT2 else "normal"),
                      bd=0 if bg_c==ACCENT2 else 1,
                      relief="flat" if bg_c==ACCENT2 else "solid",
                      padx=10, pady=3, cursor="hand2",
                      command=cmd).pack(side="right", padx=(4,0) if txt!="Generate Report" else (10,0), pady=5)

        self.ai_out = scrolledtext.ScrolledText(
            frame, height=6, bg=SIDEBAR_BG, fg=TEXT,
            font=("Consolas",9), insertbackground=ACCENT,
            bd=0, padx=12, pady=8)
        self.ai_out.pack(fill="x", padx=20, pady=(0,12))
        self._ai_write("AI security report will appear here after scanning.\n"
                       "Set GOOGLE_API_KEY in .env for Gemini  |  Automated mode = fully hands-free")
        return frame

    def _ent(self, parent, default=""):
        e = tk.Entry(parent, bg="#0d1117", fg=TEXT, insertbackground=ACCENT,
                     font=("Segoe UI",10), relief="flat", highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=ACCENT)
        e.insert(0, default); return e

    def _ai_write(self, text: str):
        self.ai_out.configure(state="normal")
        self.ai_out.delete("1.0","end")
        self.ai_out.insert("end", text)
        self.ai_out.configure(state="disabled")

    def _sort(self, col):
        items = [(self.tree.set(i,col), i) for i in self.tree.get_children()]
        try: items.sort(key=lambda x: int(x[0]))
        except: items.sort()
        for idx, (_,i) in enumerate(items): self.tree.move(i,"",idx)

    # ══════════════════════════════════════════════════════════════════════
    #  HISTORY PAGE
    # ══════════════════════════════════════════════════════════════════════
    def _page_history(self):
        frame = tk.Frame(self.content, bg=BG)
        tk.Label(frame, text="Scan History",
                 font=("Segoe UI",17,"bold"), fg=ACCENT, bg=BG, pady=14).pack()
        bf = tk.Frame(frame, bg=BG); bf.pack(fill="x", padx=20, pady=(0,10))
        tk.Button(bf, text="🔄 Refresh", bg=CARD_BG, fg=TEXT,
                  font=("Segoe UI",9), bd=0, padx=12, pady=5, cursor="hand2",
                  command=self._load_hist).pack(side="left")
        tk.Button(bf, text="🗑 Clear All", bg=RED, fg="white",
                  font=("Segoe UI",9), bd=0, padx=12, pady=5, cursor="hand2",
                  command=self._clear_hist).pack(side="left", padx=6)
        tk.Button(bf, text="➕ New Scan", bg=ACCENT, fg="#000",
                  font=("Segoe UI",9,"bold"), bd=0, padx=14, pady=5, cursor="hand2",
                  command=self._new_scan).pack(side="left", padx=6)
        tk.Label(bf, text="Double-click a row to restore full scan session",
                 fg=TEXT_DIM, bg=BG, font=("Segoe UI",9)).pack(side="right")

        cols = ("ID","Name","Target","IP","Range","Protocol","Timestamp")
        self.hist_tree = ttk.Treeview(frame, columns=cols, show="headings",
                                       style="History.Treeview")
        ws = [40,140,140,120,80,70,150]
        for col, w in zip(cols, ws):
            self.hist_tree.heading(col, text=col)
            self.hist_tree.column(col, width=w)
        vsb2 = ttk.Scrollbar(frame, orient="vertical", command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=vsb2.set)
        self.hist_tree.pack(side="left", fill="both", expand=True, padx=(20,0))
        vsb2.pack(side="left", fill="y", padx=(0,20))
        self.hist_tree.bind("<Double-1>", self._restore)
        self._load_hist()
        return frame

    def _load_hist(self):
        self.hist_tree.delete(*self.hist_tree.get_children())
        for row in db_all(): self.hist_tree.insert("","end", values=row)

    def _clear_hist(self):
        if messagebox.askyesno("Confirm","Delete all scan history?"):
            db_clear(); self._load_hist()

    def _new_scan(self):
        self.scan_results=[]; self.vuln_results={}
        self.ai_text=""; self.scan_folder=""
        self.log_lines=[]; self.err_lines=[]
        self._open_ct=0; self._err_ct=0
        self.domain_e.delete(0,"end"); self.ip_e.delete(0,"end")
        self.sp_e.delete(0,"end"); self.sp_e.insert(0,"1")
        self.ep_e.delete(0,"end"); self.ep_e.insert(0,"1024")
        self.tree.delete(*self.tree.get_children())
        self.empty_lbl.pack_forget()
        self.status_var.set("Ready — enter target and click ▶ Start Scan")
        self.openct_var.set("Open: 0"); self.errct_var.set("Errors: 0")
        self.curport_var.set("Port: —"); self.prog_var.set(0)
        self.vuln_sum_var.set("Run a scan to see vulnerability summary.")
        self._ai_write("AI security report will appear here after scanning.")
        self._show("scanner")

    def _restore(self, _event):
        sel = self.hist_tree.selection()
        if not sel: return
        sid = int(self.hist_tree.item(sel[0],"values")[0])
        row = db_one(sid)
        if not row: return
        (_,sname,target,ip,pr,proto,opj,vj,ai,sf,ts,*_rest) = row
        try: self.scan_results = [tuple(r) for r in json.loads(opj or "[]")]
        except: self.scan_results = []
        try: self.vuln_results = json.loads(vj or "{}")
        except: self.vuln_results = {}
        self.ai_text=ai or ""; self.scan_folder=sf or ""
        self._show("scanner")
        self.domain_e.delete(0,"end"); self.domain_e.insert(0, target or "")
        self.ip_e.delete(0,"end");     self.ip_e.insert(0, ip or "")
        if pr and "-" in str(pr):
            s,e = str(pr).split("-",1)
            self.sp_e.delete(0,"end"); self.sp_e.insert(0,s)
            self.ep_e.delete(0,"end"); self.ep_e.insert(0,e)
        self.tree.delete(*self.tree.get_children())
        self.empty_lbl.pack_forget()
        for r in self.scan_results:
            self.tree.insert("","end", values=r, tags=("open",))
        if self.ai_text: self._ai_write(self.ai_text)
        self._update_vuln_sum()
        self.status_var.set(f"✅ Restored: '{sname}'  [{ts}]")
        messagebox.showinfo("Restored", f"Scan '{sname}' from {ts} restored.\n"
                            "You can view results or generate a new AI report.")

    # ══════════════════════════════════════════════════════════════════════
    #  TOOLS PAGE
    # ══════════════════════════════════════════════════════════════════════
    def _page_tools(self):
        frame = tk.Frame(self.content, bg=BG)
        tk.Label(frame, text="🛠 OSINT & Security Tools",
                 font=("Segoe UI",17,"bold"), fg=ACCENT, bg=BG, pady=12).pack()

        outer = tk.Frame(frame, bg=BG); outer.pack(fill="both", expand=True, padx=20)
        canvas = tk.Canvas(outer, bg=BG, bd=0, highlightthickness=0)
        scb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scb.set)
        canvas.pack(side="left", fill="both", expand=True)
        scb.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1*(e.delta//120),"units"))

        TOOLS = [
            ("🔍 DNS & Domain Recon", ""),
            ("NSLookup.io",        "https://www.nslookup.io",               "DNS records: A, MX, NS, TXT, CNAME, SOA"),
            ("WHOIS DomainTools",  "https://whois.domaintools.com",          "Domain ownership, registrar, history"),
            ("ViewDNS.info",       "https://viewdns.info",                   "IP history, reverse DNS, traceroute, ping"),
            ("HackerTarget",       "https://hackertarget.com/dns-lookup",    "DNS lookup, reverse DNS, subnet tools"),
            ("DNSDumpster",        "https://dnsdumpster.com",                "Domain recon map & DNS enumeration"),
            ("Shrewdeye Subdomains","https://shrewdeye.app",                 "Passive subdomain enumeration"),

            ("🌐 IP & Geolocation", ""),
            ("IPGeolocation.io",   "https://ipgeolocation.io",              "IP: country, ISP, ASN, coordinates"),
            ("Reverse IP Lookup",  "https://viewdns.info/reverseip",        "All domains hosted on same IP"),
            ("Shodan.io",          "https://www.shodan.io",                 "Search engine for internet-connected devices"),
            ("Censys",             "https://search.censys.io",              "Internet-wide scanning & host data"),

            ("🕷 Web Tech Recon", ""),
            ("Wappalyzer",         "https://www.wappalyzer.com",            "Identify CMS, frameworks, analytics, CDN"),
            ("BuiltWith",          "https://builtwith.com",                 "Full tech stack profiler"),
            ("Webchecker",         "https://www.webchecker.org",            "Security headers, SSL, tech info"),
            ("Wayback Machine",    "https://web.archive.org",               "Historical website snapshots"),

            ("💀 Exploit & CVE Research", ""),
            ("Exploit-DB",         "https://www.exploit-db.com",            "Public exploit database — PoC code"),
            ("NVD / CVE Search",   "https://nvd.nist.gov/vuln/search",      "NIST National Vulnerability Database"),
            ("CVE Mitre",          "https://cve.mitre.org",                 "CVE identifiers and descriptions"),
            ("Google Dorks DB",    "https://www.exploit-db.com/google-hacking-database", "Google hacking advanced operators"),

            ("📧 OSINT & Social", ""),
            ("Hunter.io",          "https://hunter.io",                     "Find email addresses by domain"),
            ("Social Searcher",    "https://www.social-searcher.com",       "Cross-platform social media search"),
            ("LinkedIn",           "https://www.linkedin.com/search/results/companies", "Company & employee profiling"),
            ("Maltego CE",         "https://www.maltego.com/maltego-community", "Graph-based OSINT analysis"),

            ("🔐 SSL & Headers", ""),
            ("SSL Labs",           "https://www.ssllabs.com/ssltest",       "Deep SSL/TLS configuration grading"),
            ("Security Headers",   "https://securityheaders.com",           "HTTP security response header analysis"),
            ("Observatory Mozilla","https://observatory.mozilla.org",        "Website security: TLS, headers, CSP"),
        ]

        row_frame = None; col_count = 0
        for item in TOOLS:
            if len(item) == 2 and item[1] == "":
                tk.Label(inner, text=item[0], fg=ACCENT2, bg=BG,
                         font=("Segoe UI",11,"bold"), anchor="w").pack(
                             fill="x", padx=4, pady=(14,4))
                tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", padx=4, pady=(0,6))
                row_frame = tk.Frame(inner, bg=BG); row_frame.pack(fill="x")
                col_count = 0; continue
            name, url, desc = item
            c = tk.Frame(row_frame, bg=CARD_BG, padx=12, pady=10)
            c.grid(row=0, column=col_count, padx=5, pady=4, sticky="nsew")
            row_frame.columnconfigure(col_count, weight=1); col_count+=1
            tk.Label(c, text=name, fg=ACCENT, bg=CARD_BG,
                     font=("Segoe UI",10,"bold"), anchor="w").pack(anchor="w")
            tk.Label(c, text=desc, fg=TEXT_DIM, bg=CARD_BG,
                     font=("Segoe UI",8), wraplength=190,
                     justify="left").pack(anchor="w", pady=(2,6))
            tk.Button(c, text="Open in Browser →", bg=ACCENT2, fg="#000",
                      font=("Segoe UI",9,"bold"), bd=0, padx=8, pady=3,
                      cursor="hand2",
                      command=lambda u=url: webbrowser.open(u)).pack(anchor="w")
            if col_count >= 3:
                row_frame = tk.Frame(inner, bg=BG); row_frame.pack(fill="x")
                col_count = 0

        # Quick domain bar
        lk = tk.Frame(frame, bg=CARD_BG, padx=24, pady=12)
        lk.pack(padx=20, fill="x", pady=(6,14))
        tk.Label(lk, text="⚡ Quick Domain Tool", fg=ACCENT, bg=CARD_BG,
                 font=("Segoe UI",11,"bold")).pack(anchor="w")
        lr = tk.Frame(lk, bg=CARD_BG); lr.pack(fill="x", pady=8)
        self.td_e = tk.Entry(lr, bg="#0d1117", fg=TEXT, font=("Segoe UI",10),
                              relief="flat", highlightthickness=1,
                              highlightbackground=BORDER, highlightcolor=ACCENT,
                              width=28)
        self.td_e.insert(0,"example.com"); self.td_e.pack(side="left")
        for txt, url_t in [
            ("NSLookup","https://www.nslookup.io/dns-records/{d}/"),
            ("WHOIS","https://whois.domaintools.com/{d}"),
            ("Subdomains","https://shrewdeye.app/?q={d}"),
            ("Shodan","https://www.shodan.io/search?query={d}"),
            ("Exploit-DB","https://www.exploit-db.com/search?q={d}"),
        ]:
            tk.Button(lr, text=txt, bg=CARD_BG, fg=ACCENT2,
                      font=("Segoe UI",9), bd=1, relief="solid",
                      padx=7, pady=3, cursor="hand2",
                      command=lambda u=url_t: webbrowser.open(
                          u.replace("{d}", self.td_e.get().strip()))
                      ).pack(side="left", padx=3)
        self.td_lbl = tk.Label(lk, text="", fg=GREEN, bg=CARD_BG,
                                font=("Segoe UI",10,"bold"))
        self.td_lbl.pack(anchor="w")
        def do_res():
            d = self.td_e.get().strip(); ip = resolve(d)
            self.td_lbl.config(
                text=f"{d} → {ip}" if ip else "Cannot resolve",
                fg=GREEN if ip else RED)
        tk.Button(lr, text="Resolve IP", bg=ACCENT, fg="#000",
                  font=("Segoe UI",9,"bold"), bd=0, padx=10, pady=3,
                  cursor="hand2", command=do_res).pack(side="left", padx=8)
        return frame

    # ══════════════════════════════════════════════════════════════════════
    #  ABOUT PAGE — SUPRAJA TECHNOLOGIES
    # ══════════════════════════════════════════════════════════════════════
    def _page_about(self):
        frame = tk.Frame(self.content, bg=BG)

        # Company header
        hf = tk.Frame(frame, bg="#0f1824", pady=18)
        hf.pack(fill="x")
        tk.Label(hf, text="🏢  SUPRAJA TECHNOLOGIES",
                 font=("Segoe UI",20,"bold"), fg=ACCENT, bg="#0f1824").pack()
        tk.Label(hf, text="a unit of CHSMRLSS Technologies Pvt. Ltd.",
                 font=("Segoe UI",10), fg=TEXT_DIM, bg="#0f1824").pack(pady=2)
        tk.Label(hf, text="Vijayawada, Andhra Pradesh, India  |  4.8 ⭐ Google Rated",
                 font=("Segoe UI",10), fg=YELLOW, bg="#0f1824").pack()
        tk.Button(hf, text="🌐 www.suprajatechnologies.com",
                  bg="#0f1824", fg=ACCENT2, font=("Segoe UI",10,"bold"),
                  bd=0, cursor="hand2",
                  command=lambda: webbrowser.open("https://www.suprajatechnologies.com")
                  ).pack(pady=4)

        # Scrollable body
        outer = tk.Frame(frame, bg=BG); outer.pack(fill="both", expand=True, padx=20, pady=8)
        canvas = tk.Canvas(outer, bg=BG, bd=0, highlightthickness=0)
        scb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=BG)
        body.bind("<Configure>",
                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scb.set)
        canvas.pack(side="left", fill="both", expand=True)
        scb.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1*(e.delta//120),"units"))

        def section(title):
            tk.Label(body, text=title, fg=ACCENT2, bg=BG,
                     font=("Segoe UI",12,"bold"), anchor="w").pack(
                         fill="x", padx=4, pady=(14,4))
            tk.Frame(body, bg=BORDER, height=1).pack(fill="x", padx=4, pady=(0,6))

        def card(lines, fg_=TEXT):
            c = tk.Frame(body, bg=CARD_BG, padx=16, pady=12)
            c.pack(fill="x", padx=4, pady=3)
            for l in lines:
                tk.Label(c, text=l, fg=fg_, bg=CARD_BG,
                         font=("Segoe UI",9), anchor="w",
                         wraplength=900, justify="left").pack(anchor="w", pady=1)

        section("📌 About the Company")
        card([
            "Supraja Technologies is a leading Knowledge and Technical Solutions Provider and pioneer",
            "leader in IT industry. With its foundation pillars of Innovation, Information and Intelligence,",
            "Supraja Technologies operates as a Technology Service Provider (Corporate Consulting)",
            "and as a Training Organization (Ed-Tech).",
            "",
            "🔬 R&D Division: Supraja Technologies Cyber Security Cell (24×7 Research & Development)",
            f"🌐 Website: www.suprajatechnologies.com",
            f"📍 Base: Vijayawada, Andhra Pradesh, India",
            f"👨‍💼 CEO: Mr. Santosh Chaluvadi",
        ])

        section("🏆 Achievements & Recognition")
        card([
            "📖 LIMCA BOOK OF RECORDS 2017 — CEO Mr. Santosh Chaluvadi organised a 50-hour",
            "   Nonstop Marathon Training Workshop on Ethical Hacking & Cyber Security.",
            "",
            "🏅 Top 50 Tech Companies 2019 — Shortlisted at InterCon Dubai, UAE",
            "   (Selected by 45+ research analysts from thousands of companies worldwide)",
            "",
            "🛡️ CoE Launch — 17 Aug 2024: Ramco Institute of Technology, Rajapalayam",
            "🛡️ CoE Launch — 18 Sep 2024: SRM University, Ramapuram Campus, Chennai",
            "🛡️ CoE Launch — 20 Nov 2024: St. Joseph's Institute of Technology, Chennai",
            "",
            "🎬 Anti-Piracy Solution: Successfully deployed for Tollywood film industry;",
            "   kills up to 35% online piracy. First client: actor/producer Mr. Saptagiri (VAJRA KAVACHADARA GOVINDA)",
        ], fg_=GREEN)

        section("📚 Training Programs")
        rf = tk.Frame(body, bg=BG); rf.pack(fill="x", padx=4, pady=3)
        programs = [
            ("🎓 Classroom", ["Summer Training (30–45 days)","Winter Training (10–15 days)",
                              "Weekend Training (2 days)","1/3/6 Month Courses"]),
            ("🏫 On-site",   ["Value Added Courses for Colleges","Faculty Development Programs",
                              "Govt Agencies & Police Academies","Corporate Training"]),
            ("💼 Internships",["Engineering Students (30/45/60 days)",
                               "Graduates (6 months)","Cyber Security Focus"]),
            ("🔬 Workshops", ["Engineering Colleges","Corporate Companies (Startups & MNCs)",
                              "Government Organizations","Hackathons"]),
        ]
        for i, (title, items) in enumerate(programs):
            c = tk.Frame(rf, bg=CARD_BG, padx=14, pady=12)
            c.grid(row=0, column=i, padx=5, pady=4, sticky="nsew")
            rf.columnconfigure(i, weight=1)
            tk.Label(c, text=title, fg=ACCENT, bg=CARD_BG,
                     font=("Segoe UI",10,"bold")).pack(anchor="w")
            for itm in items:
                tk.Label(c, text=f"• {itm}", fg=TEXT, bg=CARD_BG,
                         font=("Segoe UI",8), anchor="w").pack(anchor="w")

        section("🌟 Why Choose Supraja Technologies")
        card([
            f"✔ 68,500+ Students trained by our expert trainers",
            "✔ Proven track record delivering quality cybersecurity services",
            "✔ Training partners of recognized institutions across India",
            "✔ Trainers with excellent R&D and corporate-standard pedagogy",
            "✔ Hands-on sessions with Study Material, Toolkit & immediate query handling",
            "✔ Self-Prepared Cyber Security Cell",
            "✔ Training provided to Govt. Officials, Corporate Houses and Colleges",
            "✔ R&D Engineers, Security Analysts, Security Consultants & Trainers on board",
        ])

        section("🔗 Connect with Us")
        lf = tk.Frame(body, bg=CARD_BG, padx=16, pady=12)
        lf.pack(fill="x", padx=4, pady=3)
        for lbl, url in [
            ("🌐 Company Website", "https://www.suprajatechnologies.com"),
            ("⭐ Google Reviews",  "https://bit.ly/SuprajaGoogle"),
            ("📸 CEO Instagram",   "https://www.instagram.com/chaluvadisantosh/"),
        ]:
            tk.Button(lf, text=lbl, bg=CARD_BG, fg=ACCENT2,
                      font=("Segoe UI",10), bd=0, cursor="hand2",
                      command=lambda u=url: webbrowser.open(u)).pack(
                          anchor="w", pady=3)

        section("🔧 System Information")
        gk = "✓ Key loaded" if os.getenv("GOOGLE_API_KEY") else "✗ Set GOOGLE_API_KEY in .env"
        card([
            f"Hostname   : {socket.gethostname()}",
            f"Local IP   : {local_ip()}",
            f"Platform   : {platform.system()} {platform.release()}",
            f"Python     : {sys.version.split()[0]}",
            f"Gemini API : {gk}",
            f"ReportLab  : {'Installed ✓' if REPORTLAB_OK else 'pip install reportlab'}",
            f"Scans Folder: {SCANS_DIR}",
        ])

        # Domain lookup at bottom
        lc = tk.Frame(frame, bg=CARD_BG, padx=24, pady=10)
        lc.pack(padx=20, fill="x", pady=(0,12))
        tk.Label(lc, text="Quick Domain Lookup:", fg=ACCENT, bg=CARD_BG,
                 font=("Segoe UI",10,"bold")).pack(side="left", padx=(0,12))
        self.abt_e = tk.Entry(lc, bg="#0d1117", fg=TEXT, font=("Segoe UI",10),
                               relief="flat", highlightthickness=1,
                               highlightbackground=BORDER, highlightcolor=ACCENT, width=28)
        self.abt_e.insert(0,"google.com"); self.abt_e.pack(side="left")
        self.abt_lbl = tk.Label(lc, text="", fg=GREEN, bg=CARD_BG,
                                 font=("Segoe UI",10,"bold"))
        self.abt_lbl.pack(side="left", padx=12)
        tk.Button(lc, text="Lookup", bg=ACCENT2, fg="#000",
                  font=("Segoe UI",9,"bold"), bd=0, padx=10, pady=4,
                  cursor="hand2",
                  command=lambda: self.abt_lbl.config(
                      text=f"{self.abt_e.get().strip()} → "
                           f"{resolve(self.abt_e.get().strip()) or 'N/A'}",
                      fg=GREEN)).pack(side="left")
        return frame

    # ══════════════════════════════════════════════════════════════════════
    #  PROMPT PARSING (local + AI)
    # ══════════════════════════════════════════════════════════════════════
    def _parse_prompt(self):
        raw = self.prompt_e.get().strip()
        target, sp, ep = parse_prompt(raw)
        if not target:
            self.err_asst.report("Could not parse target.",
                                 'Try: "scan 192.168.1.1 1-1000"'); return
        self._fill_target(target, sp, ep)

    def _ai_parse_prompt(self):
        raw = self.prompt_e.get().strip()
        if not raw or "e.g." in raw:
            self.err_asst.report("Enter a prompt first."); return
        self.status_var.set("🤖 AI parsing prompt…")
        def do():
            resp = gemini_ask(
                f"Extract from this text: target IP or domain, start port, end port.\n"
                f"Reply ONLY as JSON: {{\"target\":\"...\",\"start\":N,\"end\":N}}\n"
                f"Text: {raw}",
                "You are a network scanning assistant. Extract scan parameters only.")
            try:
                # find JSON in response
                m = re.search(r'\{[^}]+\}', resp)
                if m:
                    d = json.loads(m.group())
                    t=d.get("target"); sp=d.get("start"); ep=d.get("end")
                    self.root.after(0, lambda: self._fill_target(t,sp,ep))
                    return
            except: pass
            # fallback to local
            self.root.after(0, self._parse_prompt)
        threading.Thread(target=do, daemon=True).start()

    def _fill_target(self, target, sp, ep):
        if not target: return
        self.domain_e.delete(0,"end"); self.ip_e.delete(0,"end")
        if target and re.match(r"\d+\.\d+\.\d+\.\d+", target):
            self.ip_e.insert(0, target)
        else:
            self.domain_e.insert(0, target)
            ir = resolve(target)
            if ir: self.ip_e.insert(0, ir)
        if sp is not None:
            self.sp_e.delete(0,"end"); self.sp_e.insert(0, str(sp))
        if ep is not None:
            self.ep_e.delete(0,"end"); self.ep_e.insert(0, str(ep))
        self.status_var.set(f"Filled → {target}  ports {sp}–{ep}")

    # ══════════════════════════════════════════════════════════════════════
    #  SCAN FLOW
    # ══════════════════════════════════════════════════════════════════════
    def _resolve(self):
        d = self.domain_e.get().strip()
        if not d: messagebox.showwarning("Input","Enter a domain first."); return
        ip = resolve(d)
        if ip:
            self.ip_e.delete(0,"end"); self.ip_e.insert(0,ip)
            self.status_var.set(f"Resolved {d} → {ip}")
        else:
            self.err_asst.report(f"Cannot resolve: {d}","Check internet / typo")

    def _get_target(self):
        domain = self.domain_e.get().strip()
        ip     = self.ip_e.get().strip()
        if domain and not ip:
            ip = resolve(domain)
            if ip: self.ip_e.delete(0,"end"); self.ip_e.insert(0,ip)
        return domain or ip, ip or domain

    def _start(self):
        if self.scanning: return
        domain, ip = self._get_target()
        if not ip:
            messagebox.showerror("Error","Enter a Target IP or Domain."); return
        try:
            sp = int(self.sp_e.get()); ep = int(self.ep_e.get())
            if sp < 0 or ep > 65535 or sp > ep: raise ValueError
        except ValueError:
            messagebox.showerror("Error","Ports 0–65535, Start ≤ End."); return
        if self.allports_var.get(): sp, ep = 0, 65535

        self.scanning=True; self.scan_results=[]; self.vuln_results={}
        self.nmap_cmds={}; self.log_lines=[]; self.err_lines=[]
        self._open_ct=0; self._err_ct=0
        self.scan_folder = make_folder(domain or ip)
        self.tree.delete(*self.tree.get_children())
        self.empty_lbl.pack_forget()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.prog_var.set(0)
        self.openct_var.set("Open: 0"); self.errct_var.set("Errors: 0")
        self.vuln_sum_var.set("Scanning…")
        self.status_var.set(f"Starting scan on {ip}…")

        threading.Thread(
            target=self._run,
            args=(ip, sp, ep, self.proto_var.get(),
                  domain, self.mode_var.get()),
            daemon=True).start()

    def _stop(self):
        self.scanning = False
        self.status_var.set("Scan stopped.")
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _log(self, msg): self.log_lines.append(
        f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")

    def _err(self, msg, fix=""):
        self.err_lines.append(
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ERROR: {msg}")
        self._err_ct += 1
        self.root.after(0, lambda c=self._err_ct: self.errct_var.set(f"Errors: {c}"))

    # ── THE SCAN THREAD ─────────────────────────────────────────────────
    def _run(self, ip, sp, ep, proto, domain, mode):
        self._log(f"Scan start: {ip} {sp}-{ep} proto={proto} mode={mode}")
        self.root.after(0, lambda: self.status_var.set(
            f"Phase 1/2 — Sweeping {ip} ports {sp}–{ep}…"))

        protocols = (["TCP","UDP"] if proto=="BOTH" else [proto.upper()])
        total  = (ep-sp+1)*len(protocols)
        done   = 0
        open_pairs = []

        # ── fast sweep ────────────────────────────────────────────────────
        def chk(port, pproto):
            return (port, pproto) if (
                tcp_open(ip, port) if pproto=="TCP"
                else udp_probe(ip, port)   # ← fixed: no false positives
            ) else None

        workers = min(512, max(total,1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(chk, p, pp): (p,pp)
                    for p in range(sp, ep+1) for pp in protocols}
            for fut in concurrent.futures.as_completed(futs):
                if not self.scanning: break
                done += 1
                p, pp = futs[fut]
                pct = 60*done/total
                self.root.after(0, lambda v=pct: self.prog_var.set(v))
                self.root.after(0, lambda po=p,pr=pp: self.curport_var.set(
                    f"Port {po} ({pr})"))
                try:
                    r = fut.result()
                    if r: open_pairs.append(r)
                except Exception as exc:
                    self._err(f"Port {p}: {exc}")

        if not open_pairs:
            self.root.after(0, lambda: self._finish(ip,domain,[],sp,ep,proto,mode))
            return

        open_pairs.sort()
        self.root.after(0, lambda: self.status_var.set(
            f"Phase 2/2 — Banner grabbing {len(open_pairs)} open ports…"))

        # ── banner grab — only OPEN ports ─────────────────────────────────
        rows = []
        for i, (port, pproto) in enumerate(open_pairs):
            if not self.scanning: break
            pct = 60 + 40*i/len(open_pairs)
            self.root.after(0, lambda v=pct: self.prog_var.set(v))
            try:
                banner = grab_banner(ip, port)
                name   = svc_name(port, pproto.lower())
                row    = (port, name, pproto, "open", banner or "—")
                rows.append(row)
                self._open_ct += 1
                oc = self._open_ct
                # ← correct lambda: no keyword args in after()
                self.root.after(0, lambda r=row, c=oc: (
                    self.tree.insert("","end", values=r, tags=("open",)),
                    self.openct_var.set(f"Open: {c}")
                ))
                self._log(f"OPEN {port}/{pproto} ({name}) {banner}")
            except Exception as exc:
                self._err(f"Banner port {port}: {exc}")

        self.root.after(0, lambda: self.prog_var.set(100))
        self.root.after(0, lambda: self._finish(ip,domain,rows,sp,ep,proto,mode))

    def _finish(self, ip, domain, rows, sp, ep, proto, mode):
        self.scan_results = rows
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

        if not rows:
            self.empty_lbl.config(text=f"No open ports on {ip}  ({sp}–{ep})")
            self.empty_lbl.pack(pady=8)
            self.status_var.set("Scan complete — 0 open ports found.")
            self._artifacts(domain or ip, rows, {}, "")
            return

        # ── Vulnerability assessment (OPEN PORTS ONLY) ────────────────────
        self.vuln_results = {}; crit=hi=med=lo=0
        for r in rows:                          # rows = only open ports
            port, name, pproto, _, banner = r
            vulns = self._assess(port, name, pproto, banner)
            self.vuln_results[str(port)] = {
                "service":name, "protocol":pproto,
                "banner":banner, "vulnerabilities":vulns}
            # generate nmap commands for this port
            cmds = NMAP_CMDS.get(port, DEFAULT_NMAP)
            self.nmap_cmds[str(port)] = [
                c.replace("{ip}",ip).replace("{port}",str(port)) for c in cmds]
            for v in vulns:
                s = v["severity"]
                if s=="Critical": crit+=1
                elif s=="High":   hi+=1
                elif s=="Medium": med+=1
                else:             lo+=1

        summary = f"Critical:{crit}  High:{hi}  Medium:{med}  Low:{lo}"
        self.vuln_sum_var.set(summary)
        self.status_var.set(
            f"✅ Scan complete — {len(rows)} open port(s) | {summary}")
        self._update_vuln_sum()

        # ── Automated mode: full hands-free pipeline ───────────────────────
        if mode == "Automated":
            self.root.after(0, lambda: self._ai_write(
                "🤖 Automated mode: generating AI Nmap commands + full report…"))
            threading.Thread(target=self._automated_pipeline,
                             args=(ip,), daemon=True).start()
        else:
            self._artifacts(domain or ip, rows, self.vuln_results, "")

    def _automated_pipeline(self, ip: str):
        """Fully automated: Nmap AI commands per port → full LLM report → save."""
        # Step 1: Ask Gemini for Nmap commands for each open port
        self.root.after(0, lambda: self.status_var.set(
            "🤖 AI generating Nmap commands per open port…"))
        port_nmap_block = ""
        for port_str, d in self.vuln_results.items():
            port = int(port_str)
            svc  = d["service"]
            base_cmds = self.nmap_cmds.get(port_str, DEFAULT_NMAP)
            port_nmap_block += (f"\nPort {port_str} ({svc}):\n"
                                + "\n".join(f"  {c}" for c in base_cmds))

        nmap_prompt = (
            f"For a penetration test on target {ip}, the following ports are open:\n"
            f"{port_nmap_block}\n\n"
            "For each open port, provide:\n"
            "1. The most effective Nmap scan commands (with full flags and scripts)\n"
            "2. What each command reveals\n"
            "3. Expected output indicators of vulnerability\n"
            "Format clearly by port number."
        )
        nmap_advice = gemini_ask(nmap_prompt,
            "You are an expert penetration tester. Provide only nmap scan commands and expected results.")

        # Write nmap_commands.txt
        if self.scan_folder:
            write_file(self.scan_folder, "nmap_commands.txt",
                       f"AI-Generated Nmap Commands\nTarget: {ip}\n\n{nmap_advice}")

        # Step 2: Full LLM security report
        self.root.after(0, lambda: self.status_var.set(
            "🤖 AI generating full security report…"))
        report = self._build_ai_report(ip, nmap_advice)
        self.ai_text = report
        self.root.after(0, lambda: self._ai_write(report))
        self._artifacts(self.domain_e.get() or ip, self.scan_results,
                        self.vuln_results, report)
        self.root.after(0, lambda: self.status_var.set(
            "✅ Automated pipeline complete — report generated!"))

    def _assess(self, port, service, proto, banner) -> list:
        vulns = list(VULN_DB.get(port, []))
        if not vulns:
            vulns.append({
                "severity":"Info","cve":"N/A","cvss":"0.0",
                "description":f"Port {port} ({service}) is open on the network",
                "risk":"Service is accessible from external network",
                "mitigation":"Verify this port should be publicly accessible; consider firewall rules"})
        if banner:
            bl = banner.lower()
            for pat, desc, sev, cve, cvss in [
                ("apache/2.2","Outdated Apache 2.2","High","CVE-2017-7679","7.5"),
                ("nginx/1.0","Outdated Nginx 1.0","High","Multiple","7.5"),
                ("nginx/1.1","Outdated Nginx 1.1","High","Multiple","7.5"),
                ("openssh/6.","Outdated OpenSSH 6.x","High","Multiple","7.8"),
                ("openssh/7.0","Outdated OpenSSH 7.0","High","CVE-2016-0777","6.5"),
                ("php/5.","EOL PHP 5.x","Critical","Multiple","9.8"),
                ("php/7.0","EOL PHP 7.0","High","Multiple","7.5"),
                ("tomcat/7.","Outdated Tomcat 7","High","Multiple","7.5"),
                ("microsoft-iis/7","Outdated IIS 7","High","Multiple","7.5"),
            ]:
                if pat in bl:
                    vulns.append({
                        "severity":sev,"cve":cve,"cvss":cvss,
                        "description":f"Banner reveals {desc}: {banner[:60]}",
                        "risk":"Known unpatched vulnerabilities present in this version",
                        "mitigation":"Upgrade to the latest stable version immediately"})
        return vulns

    def _update_vuln_sum(self):
        if not self.vuln_results: return
        crit=hi=med=lo=0
        for d in self.vuln_results.values():
            for v in d.get("vulnerabilities",[]):
                s=v["severity"]
                if s=="Critical": crit+=1
                elif s=="High":   hi+=1
                elif s=="Medium": med+=1
                else:             lo+=1
        self.vuln_sum_var.set(
            f"Critical:{crit}  High:{hi}  Medium:{med}  Low:{lo}")

    def _artifacts(self, target, rows, vulns, ai):
        sf = self.scan_folder
        if not sf: return
        write_file(sf,"logs.txt","\n".join(self.log_lines))
        write_file(sf,"errors.txt","\n".join(self.err_lines))
        write_file(sf,"scan_info.json",json.dumps(
            {"target":target,
             "timestamp":datetime.datetime.now().isoformat(),
             "open_ports":len(rows),
             "assessor":self.assessor_var.get()},indent=2))
        write_file(sf,"open_ports.json",
                   json.dumps([[r[0],r[1],r[2],r[3],r[4]] for r in rows],indent=2))
        write_file(sf,"vulnerabilities.json",json.dumps(vulns,indent=2))
        write_file(sf,"nmap_commands.json",json.dumps(self.nmap_cmds,indent=2))
        if ai: write_file(sf,"ai_report.txt",ai)
        name = (f"{target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        try:
            db_save(name, target, self.ip_e.get(),
                    f"{self.sp_e.get()}-{self.ep_e.get()}",
                    self.proto_var.get(), rows, vulns, ai, sf,
                    self.assessor_var.get())
            self.root.after(0, self._load_hist)
        except Exception as exc:
            self._err(f"DB save: {exc}")

    # ══════════════════════════════════════════════════════════════════════
    #  VULNERABILITY PANEL
    # ══════════════════════════════════════════════════════════════════════
    def _show_vulns(self):
        if not self.vuln_results:
            messagebox.showinfo("No Data","Run a scan first."); return
        win = tk.Toplevel(self.root)
        win.title("Full Vulnerability Assessment")
        win.geometry("860x600"); win.configure(bg=BG)
        tk.Label(win, text="🔴 Full Vulnerability Assessment",
                 font=("Segoe UI",14,"bold"), fg=RED, bg=BG, pady=10).pack()
        cols = ("Port","Service","Severity","CVSS","CVE","Description")
        tv   = ttk.Treeview(win, columns=cols, show="headings",
                             style="Vuln.Treeview")
        for col,w in zip(cols,[60,90,80,60,130,0]):
            tv.heading(col, text=col); tv.column(col, width=w, stretch=(col=="Description"))
        for sev,cfg in SEV_CLR.items(): tv.tag_configure(sev, foreground=cfg)
        vsb3 = ttk.Scrollbar(win, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=vsb3.set)
        tv.pack(side="left",fill="both",expand=True,padx=(20,0),pady=(0,20))
        vsb3.pack(side="left",fill="y",padx=(0,20),pady=(0,20))
        for ps,d in self.vuln_results.items():
            for v in d["vulnerabilities"]:
                s = v["severity"]
                tv.insert("","end",
                          values=(ps, d["service"], s,
                                  v.get("cvss","N/A"), v["cve"],
                                  v["description"]),
                          tags=(s,))

    # ══════════════════════════════════════════════════════════════════════
    #  PORT DETAIL WINDOW
    # ══════════════════════════════════════════════════════════════════════
    def _on_dbl(self, _e):
        sel = self.tree.selection()
        if sel: self._detail(self.tree.item(sel[0],"values"))

    def _detail(self, data):
        port    = int(data[0]); service = data[1]
        ip      = self.ip_e.get() or self.domain_e.get()
        win = tk.Toplevel(self.root)
        win.title(f"Port {port}  /  {service.upper()}  —  {ip}")
        win.geometry("760x680"); win.configure(bg=BG)

        tk.Label(win, text=f"Port {port}  /  {service.upper()}",
                 font=("Segoe UI",14,"bold"), fg=ACCENT, bg=BG, pady=10).pack()
        tk.Label(win, text=f"Target: {ip}  |  Protocol: {data[2]}  |  Status: {data[3]}",
                 font=("Segoe UI",9), fg=TEXT_DIM, bg=BG).pack()
        tk.Label(win, text=f"Banner: {data[4] or 'N/A'}",
                 font=("Segoe UI",9), fg=YELLOW, bg=BG, pady=2).pack()
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=20, pady=8)

        nb = ttk.Notebook(win); nb.pack(fill="both", expand=True, padx=20, pady=(0,6))

        # Tab 1: Checks
        t1 = tk.Frame(nb, bg=BG); nb.add(t1, text="  Security Checks  ")
        cv = tk.Canvas(t1, bg=BG, bd=0, highlightthickness=0)
        scb_t1 = ttk.Scrollbar(t1, orient="vertical", command=cv.yview)
        inn = tk.Frame(cv, bg=BG)
        inn.bind("<Configure>",
                 lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.create_window((0,0), window=inn, anchor="nw")
        cv.configure(yscrollcommand=scb_t1.set)
        cv.pack(side="left",fill="both",expand=True); scb_t1.pack(side="right",fill="y")
        out_box = scrolledtext.ScrolledText(win, height=7, bg=SIDEBAR_BG, fg=GREEN,
                                             font=("Consolas",8), bd=0, padx=8, pady=6)
        out_box.pack(fill="x", padx=20, pady=(0,6)); win._out = out_box
        checks = MANUAL_CHECKS.get(port, DEFAULT_CHECKS)
        for clabel, cmd_t in checks:
            cmd = cmd_t.replace("{ip}",ip).replace("{port}",str(port)).replace(
                "{service}",service)
            row = tk.Frame(inn, bg=CARD_BG, pady=6, padx=12)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"  {clabel}", fg=TEXT, bg=CARD_BG,
                     font=("Segoe UI",9,"bold"), width=24, anchor="w").pack(side="left")
            tk.Label(row, text=cmd, fg=ACCENT2, bg=CARD_BG,
                     font=("Consolas",8), anchor="w").pack(side="left", padx=8)
            tk.Button(row, text="Copy", bg=CARD_BG, fg=TEXT_DIM,
                      font=("Segoe UI",8), bd=1, relief="solid",
                      padx=6, pady=2, cursor="hand2",
                      command=lambda c=cmd: self._copy(c)
                      ).pack(side="right", padx=(4,0))
            tk.Button(row, text="Test", bg=ACCENT, fg="#000",
                      font=("Segoe UI",8,"bold"), bd=0, padx=8, pady=2,
                      cursor="hand2",
                      command=lambda p=port, l=clabel, w=win: self._run_check(ip,p,l,w)
                      ).pack(side="right")

        # Tab 2: Vulnerabilities
        t2 = tk.Frame(nb, bg=BG); nb.add(t2, text="  Vulnerabilities  ")
        vd   = self.vuln_results.get(str(port), {})
        vlst = vd.get("vulnerabilities", [])
        if not vlst:
            tk.Label(t2, text="No vulnerability data.\nRun a full scan first.",
                     fg=TEXT_DIM, bg=BG, font=("Segoe UI",11)).pack(pady=30)
        else:
            vc = tk.Canvas(t2, bg=BG, bd=0, highlightthickness=0)
            vs = ttk.Scrollbar(t2, orient="vertical", command=vc.yview)
            vi = tk.Frame(vc, bg=BG)
            vi.bind("<Configure>",
                    lambda e: vc.configure(scrollregion=vc.bbox("all")))
            vc.create_window((0,0), window=vi, anchor="nw")
            vc.configure(yscrollcommand=vs.set)
            vc.pack(side="left",fill="both",expand=True); vs.pack(side="right",fill="y")
            for vuln in vlst:
                sev = vuln["severity"]; c = SEV_CLR.get(sev,TEXT)
                vrow = tk.Frame(vi, bg=CARD_BG, pady=8, padx=14)
                vrow.pack(fill="x", pady=3, padx=6)
                tk.Label(vrow, text=f"[{sev}]  CVSS: {vuln.get('cvss','N/A')}",
                         fg=c, bg=CARD_BG, font=("Segoe UI",9,"bold")).grid(
                             row=0,column=0,sticky="w")
                tk.Label(vrow, text=vuln["cve"], fg=PURPLE, bg=CARD_BG,
                         font=("Segoe UI",9)).grid(row=0,column=1,sticky="w",padx=10)
                tk.Label(vrow, text=vuln["description"], fg=TEXT, bg=CARD_BG,
                         font=("Segoe UI",9),wraplength=580,
                         justify="left").grid(row=1,column=0,columnspan=2,sticky="w",pady=2)
                tk.Label(vrow, text=f"⚠ Risk: {vuln['risk']}", fg=YELLOW, bg=CARD_BG,
                         font=("Segoe UI",8),wraplength=580,
                         justify="left").grid(row=2,column=0,columnspan=2,sticky="w")
                tk.Label(vrow, text=f"✅ Fix: {vuln['mitigation']}", fg=GREEN, bg=CARD_BG,
                         font=("Segoe UI",8,"bold"),wraplength=580,
                         justify="left").grid(row=3,column=0,columnspan=2,sticky="w")

        # Tab 3: Nmap AI Commands
        t3 = tk.Frame(nb, bg=BG); nb.add(t3, text="  🤖 Nmap AI Commands  ")
        ncv = tk.Canvas(t3, bg=BG, bd=0, highlightthickness=0)
        ncscb = ttk.Scrollbar(t3, orient="vertical", command=ncv.yview)
        ncinner = tk.Frame(ncv, bg=BG)
        ncinner.bind("<Configure>",
                     lambda e: ncv.configure(scrollregion=ncv.bbox("all")))
        ncv.create_window((0,0), window=ncinner, anchor="nw")
        ncv.configure(yscrollcommand=ncscb.set)
        ncv.pack(side="left",fill="both",expand=True); ncscb.pack(side="right",fill="y")

        cmds = self.nmap_cmds.get(str(port), [])
        if cmds:
            for cmd in cmds:
                nr = tk.Frame(ncinner, bg=CARD_BG, pady=7, padx=14)
                nr.pack(fill="x", pady=3)
                tk.Label(nr, text=cmd, fg=KNOCK_ACC, bg=CARD_BG,
                         font=("Consolas",9), anchor="w",
                         wraplength=600).pack(side="left", fill="x", expand=True)
                tk.Button(nr, text="Copy", bg=CARD_BG, fg=TEXT_DIM,
                          font=("Segoe UI",8), bd=1, relief="solid",
                          padx=8, pady=3, cursor="hand2",
                          command=lambda c=cmd: self._copy(c)).pack(side="right")
        else:
            tk.Label(ncinner,
                     text="No Nmap commands yet.\nRun scan in Automated mode for AI-generated commands.",
                     fg=TEXT_DIM, bg=BG, font=("Segoe UI",10)).pack(pady=20)

        # Ask AI button for Nmap
        ai_nmap_box = scrolledtext.ScrolledText(win, height=5,
                      bg=SIDEBAR_BG, fg=KNOCK_ACC,
                      font=("Consolas",8), bd=0, padx=8, pady=6)
        ai_nmap_box.pack(fill="x", padx=20, pady=(0,8))
        def ask_ai_nmap():
            ai_nmap_box.configure(state="normal")
            ai_nmap_box.delete("1.0","end")
            ai_nmap_box.insert("end","Asking Knock-2 AI for Nmap commands…\n")
            ai_nmap_box.configure(state="disabled")
            def do():
                resp = gemini_ask(
                    f"Provide the most effective Nmap commands for port {port} ({service}) on {ip}.\n"
                    "Include: version scan, script scan, vulnerability scan commands.\n"
                    "Format: one command per line with brief explanation.",
                    "You are an expert penetration tester.")
                ai_nmap_box.configure(state="normal")
                ai_nmap_box.insert("end", resp+"\n")
                ai_nmap_box.configure(state="disabled")
            threading.Thread(target=do, daemon=True).start()
        tk.Button(win, text="🤖 Ask AI for Nmap Commands",
                  bg=KNOCK_ACC, fg="#000",
                  font=("Segoe UI",9,"bold"), bd=0, padx=12, pady=4,
                  cursor="hand2", command=ask_ai_nmap).pack(padx=20, pady=(0,8))

    def _copy(self, text):
        self.root.clipboard_clear(); self.root.clipboard_append(text)

    def _run_check(self, ip, port, label, win):
        out = win._out
        out.configure(state="normal")
        out.insert("end", f"\n▶ {label}  on  {ip}:{port}\n{'─'*52}\n")
        out.configure(state="disabled")
        def do():
            lines = []
            try:
                ok = tcp_open(ip, port, 2)
                lines.append(f"Reachable : {'YES ✓' if ok else 'NO ✗'}")
                if not ok: raise ConnectionRefusedError
                b = grab_banner(ip, port)
                lines.append(f"Banner    : {b or '(none)'}")
                if port==21 and FTP_OK:
                    try:
                        ftp=ftplib.FTP(); ftp.connect(ip,21,timeout=4)
                        ftp.login("anonymous","x@x.com")
                        lines.append("Anonymous FTP : ALLOWED ⚠️"); ftp.quit()
                    except ftplib.error_perm: lines.append("Anonymous FTP : BLOCKED ✓")
                elif port in (80,8080,8000) and REQUESTS_OK:
                    r=requests.get(f"http://{ip}:{port}",timeout=4,allow_redirects=False)
                    lines+=[f"HTTP Status  : {r.status_code}",
                             f"Server       : {r.headers.get('Server','?')}",
                             f"X-Powered-By : {r.headers.get('X-Powered-By','?')}"]
                elif port==3306:
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                        s.settimeout(3); s.connect((ip,3306)); raw=s.recv(256)
                        ver=raw[5:].split(b"\x00")[0].decode(errors="ignore")
                        lines.append(f"MySQL Version: {ver}")
                elif port==6379:
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                        s.settimeout(3); s.connect((ip,6379))
                        s.sendall(b"PING\r\n")
                        resp=s.recv(128).decode(errors="ignore").strip()
                        lines.append("Redis Auth: NOT REQUIRED ⚠️"
                                     if "+PONG" in resp else f"Redis: {resp}")
            except ConnectionRefusedError: lines.append("Port closed or filtered.")
            except Exception as ex: lines.append(f"Error: {ex}")
            out.configure(state="normal")
            out.insert("end","\n".join(lines)+"\n")
            out.see("end"); out.configure(state="disabled")
        threading.Thread(target=do, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════
    #  AI REPORT (manual trigger)
    # ══════════════════════════════════════════════════════════════════════
    def _ai_report(self):
        if not self.scan_results:
            messagebox.showwarning("No Data","Run a scan first."); return
        ip = self.ip_e.get() or self.domain_e.get()
        self._ai_write("🔄 Generating Gemini security report…")
        def do():
            report = self._build_ai_report(ip)
            self.ai_text = report
            self.root.after(0, lambda: self._ai_write(report))
            if self.scan_folder:
                write_file(self.scan_folder, "ai_report.txt", report)
        threading.Thread(target=do, daemon=True).start()

    def _build_ai_report(self, ip: str, nmap_advice: str = "") -> str:
        stamp  = datetime.datetime.now().strftime("%B %d, %Y %H:%M")
        assessor = self.assessor_var.get()
        ports  = "\n".join(
            f"• Port {r[0]}/{r[2]} ({r[1]})  Banner: {r[4]}"
            for r in self.scan_results)
        vb = ""
        for ps, d in self.vuln_results.items():
            vb += f"\nPort {ps} ({d['service']}):\n"
            for v in d["vulnerabilities"]:
                vb += (f"  [{v['severity']}] CVSS:{v.get('cvss','N/A')} "
                       f"CVE:{v['cve']} — {v['description']}\n"
                       f"   Risk: {v['risk']}\n"
                       f"   Fix: {v['mitigation']}\n")
        nmap_section = f"\nNMAP COMMAND ADVICE:\n{nmap_advice}\n" if nmap_advice else ""

        prompt = f"""You are a senior cybersecurity analyst at Supraja Technologies Cyber Security Cell.
Generate a PROFESSIONAL, DETAILED security assessment report.

---SCAN METADATA---
Target      : {ip}
Date        : {stamp}
Assessed by : {assessor}
Company     : Supraja Technologies — Cyber Security Cell
Open Ports  : {len(self.scan_results)}

---PORT SCAN RESULTS---
{ports}

---VULNERABILITY FINDINGS---
{vb or 'No automated vulnerability data.'}
{nmap_section}

---REQUIRED REPORT SECTIONS---
Generate the report with EXACTLY these sections:

## 1. EXECUTIVE SUMMARY
(3-4 sentences for management. Include overall risk level.)

## 2. SCAN DETAILS
- Target: {ip}
- Date & Time: {stamp}
- Ports Scanned: (range)
- Open Ports Found: {len(self.scan_results)}
- Assessment By: {assessor} | Supraja Technologies Cyber Security Cell

## 3. OPEN PORTS — FULL LISTING
(Table format: Port | Service | Protocol | Banner | Risk Level)

## 4. VULNERABILITY SECTION
(For each vulnerability found, list:)
- Port & Service
- Severity + CVSS Score
- CVE Reference
- Description
- Risk/Impact

## 5. POTENTIAL RISKS
(List top risks this target faces based on findings. Be specific.)

## 6. MITIGATIONS — FULL LIST
(For EVERY vulnerability found, provide step-by-step mitigation.)

## 7. CVSS SCORE SUMMARY
(List CVSS scores for each finding; calculate overall risk score.)

## 8. NMAP RECOMMENDED COMMANDS
(List the Nmap commands to further validate each open port.)

## 9. CONCLUSION
(2-3 sentences summarizing priority actions.)

---
Assessed by: {assessor}
Supraja Technologies Cyber Security Cell
www.suprajatechnologies.com
---

Be technical, professional, and actionable. Use tables where appropriate."""

        return gemini_ask(prompt,
            "You are a professional cybersecurity report writer for Supraja Technologies.")

    # ══════════════════════════════════════════════════════════════════════
    #  EXPORT — CSV
    # ══════════════════════════════════════════════════════════════════════
    def _export_csv(self):
        if not self.scan_results:
            messagebox.showwarning("No Data","No results."); return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path,"w",newline="",encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Port","Service","Protocol","Status","Banner"])
            w.writerows(self.scan_results)
        messagebox.showinfo("Exported",f"Saved:\n{path}")

    # ══════════════════════════════════════════════════════════════════════
    #  PDF REPORTS
    # ══════════════════════════════════════════════════════════════════════
    def _save_pdf(self):
        if not REPORTLAB_OK:
            messagebox.showerror("Missing","pip install reportlab"); return
        if not self.scan_results:
            messagebox.showwarning("No Data","Run a scan first."); return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                             filetypes=[("PDF","*.pdf")],
                                             initialfile="security_report.pdf")
        if path: self._build_pdf(path,"summary")

    def _save_mit(self):
        if not REPORTLAB_OK:
            messagebox.showerror("Missing","pip install reportlab"); return
        if not self.scan_results:
            messagebox.showwarning("No Data","Run a scan first."); return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                             filetypes=[("PDF","*.pdf")],
                                             initialfile="mitigation_report.pdf")
        if path: self._build_pdf(path,"mitigation")

    def _build_pdf(self, path: str, mode: str):
        try:
            doc   = SimpleDocTemplate(path, pagesize=A4,
                                       leftMargin=2*cm, rightMargin=2*cm,
                                       topMargin=2*cm, bottomMargin=2*cm)
            stl   = getSampleStyleSheet()
            ip    = self.ip_e.get() or self.domain_e.get()
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            assessor = self.assessor_var.get()

            # Styles
            title_s = ParagraphStyle("T", parent=stl["Title"], fontSize=18,
                                      textColor=rlc.HexColor("#00ff88"), spaceAfter=4)
            sub_s   = ParagraphStyle("Sub", parent=stl["Normal"], fontSize=10,
                                      textColor=rlc.HexColor("#8b949e"), spaceAfter=2)
            h2_s    = ParagraphStyle("H2", parent=stl["Heading2"], fontSize=13,
                                      textColor=rlc.HexColor("#58a6ff"), spaceBefore=14)
            h3_s    = ParagraphStyle("H3", parent=stl["Heading3"], fontSize=11,
                                      textColor=rlc.HexColor("#e3b341"), spaceBefore=8)
            body    = stl["Normal"]
            bold_b  = ParagraphStyle("BB", parent=stl["Normal"],
                                      fontName="Helvetica-Bold")

            ttitle = ("Security Assessment Report" if mode=="summary"
                      else "Security Mitigation Report")
            elems = [
                Paragraph(f"Advanced Port Scanner — {ttitle}", title_s),
                Paragraph("Supraja Technologies Cyber Security Cell", sub_s),
                Spacer(1,6),
                # Info table
                Table([
                    ["Target",    ip,        "Date",    stamp],
                    ["Assessed by", assessor, "Company","Supraja Technologies"],
                    ["Open Ports", str(len(self.scan_results)),
                     "Protocol", self.proto_var.get()],
                ], colWidths=[3.5*cm,6*cm,3*cm,6*cm]),
                Spacer(1,8),
                HRFlowable(width="100%", thickness=1.5,
                           color=rlc.HexColor("#00ff88")),
                Spacer(1,10),
            ]

            # ── Section 1: Open Ports
            elems.append(Paragraph("1. Open Ports — Full Listing", h2_s))
            elems.append(Spacer(1,5))
            td = [["Port","Service","Protocol","Status","Banner / Version"]]
            for r in self.scan_results:
                td.append([str(x) for x in r])
            t = Table(td, colWidths=[45,75,60,50,None])
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),rlc.HexColor("#00ff88")),
                ("TEXTCOLOR",(0,0),(-1,0),rlc.black),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                ("FONTSIZE",(0,0),(-1,0),9),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),
                 [rlc.HexColor("#f5f5f5"),rlc.white]),
                ("GRID",(0,0),(-1,-1),0.3,rlc.grey),
                ("FONTSIZE",(0,1),(-1,-1),8),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ]))
            elems += [t, Spacer(1,12)]

            # ── Section 2: Vulnerabilities
            sev_c = {"Critical":rlc.HexColor("#f85149"),"High":rlc.HexColor("#d29922"),
                     "Medium":rlc.HexColor("#e3b341"),"Low":rlc.HexColor("#3fb950"),
                     "Info":rlc.HexColor("#58a6ff")}
            if self.vuln_results:
                elems.append(Paragraph("2. Vulnerability Section", h2_s))
                elems.append(Spacer(1,6))
                for ps, d in self.vuln_results.items():
                    elems.append(Paragraph(
                        f"Port {ps} — {d['service']} ({d['protocol']})", h3_s))
                    if d["banner"] and d["banner"] != "—":
                        elems.append(Paragraph(f"Banner: {d['banner']}", body))
                    for vuln in d["vulnerabilities"]:
                        sev = vuln["severity"]; c = sev_c.get(sev, rlc.grey)
                        elems += [
                            Paragraph(
                                f'<font color="{c.hexval()}"><b>[{sev}]</b></font> '
                                f'CVSS: {vuln.get("cvss","N/A")}  '
                                f'CVE: {vuln["cve"]}', body),
                            Paragraph(vuln["description"], body),
                        ]
                        elems.append(Spacer(1,4))
                elems.append(Spacer(1,10))

                # ── Section 3: Potential Risks
                elems.append(Paragraph("3. Potential Risks", h2_s))
                risk_data = [["Port","Service","Risk"]]
                for ps, d in self.vuln_results.items():
                    for vuln in d["vulnerabilities"]:
                        if vuln["severity"] in ("Critical","High"):
                            risk_data.append(
                                [ps, d["service"], vuln["risk"][:80]])
                if len(risk_data) > 1:
                    rt = Table(risk_data, colWidths=[40,70,None])
                    rt.setStyle(TableStyle([
                        ("BACKGROUND",(0,0),(-1,0),rlc.HexColor("#f85149")),
                        ("TEXTCOLOR",(0,0),(-1,0),rlc.white),
                        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                        ("FONTSIZE",(0,0),(-1,0),9),
                        ("ROWBACKGROUNDS",(0,1),(-1,-1),
                         [rlc.HexColor("#fff5f5"),rlc.white]),
                        ("GRID",(0,0),(-1,-1),0.3,rlc.grey),
                        ("FONTSIZE",(0,1),(-1,-1),8),
                    ]))
                    elems += [rt, Spacer(1,10)]

                # ── Section 4: Mitigations
                elems.append(Paragraph("4. Mitigations — Full List", h2_s))
                elems.append(Spacer(1,6))
                for ps, d in self.vuln_results.items():
                    for vuln in d["vulnerabilities"]:
                        elems += [
                            Paragraph(
                                f'Port {ps} ({d["service"]}) — '
                                f'<font color="{sev_c.get(vuln["severity"],rlc.grey).hexval()}">'
                                f'[{vuln["severity"]}]</font>', bold_b),
                            Paragraph(
                                f'<font color="#3fb950"><b>Fix:</b></font> '
                                f'{vuln["mitigation"]}', body),
                            Spacer(1,5),
                        ]
                elems.append(Spacer(1,10))

                # ── Section 5: CVSS Score Summary
                elems.append(Paragraph("5. CVSS Score Summary", h2_s))
                cvss_data = [["Port","Service","Severity","CVSS Score","CVE"]]
                for ps, d in self.vuln_results.items():
                    for vuln in d["vulnerabilities"]:
                        cvss_data.append([
                            ps, d["service"],
                            vuln["severity"], vuln.get("cvss","N/A"),
                            vuln["cve"]])
                ct = Table(cvss_data, colWidths=[40,75,70,60,None])
                ct.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(-1,0),rlc.HexColor("#21262d")),
                    ("TEXTCOLOR",(0,0),(-1,0),rlc.white),
                    ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                    ("FONTSIZE",(0,0),(-1,0),9),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),
                     [rlc.HexColor("#f5f5f5"),rlc.white]),
                    ("GRID",(0,0),(-1,-1),0.3,rlc.grey),
                    ("FONTSIZE",(0,1),(-1,-1),8),
                ]))
                elems += [ct, Spacer(1,10)]

            # ── Section 6: Nmap Commands
            if self.nmap_cmds:
                elems.append(Paragraph("6. Nmap Recommended Commands", h2_s))
                elems.append(Spacer(1,6))
                for ps, cmds in self.nmap_cmds.items():
                    elems.append(Paragraph(f"Port {ps}:", h3_s))
                    for cmd in cmds:
                        elems.append(Paragraph(f"  {cmd}",
                                               ParagraphStyle("code",parent=body,
                                                              fontName="Courier",fontSize=8)))
                    elems.append(Spacer(1,4))
                elems.append(Spacer(1,10))

            # ── AI Section
            ai_text = self.ai_out.get("1.0","end").strip()
            if ai_text and "AI analysis" not in ai_text[:20]:
                elems.append(Paragraph("7. AI Security Analysis", h2_s))
                elems.append(Spacer(1,6))
                for line in ai_text.split("\n"):
                    elems.append(Paragraph(line or "&nbsp;", body))
                    elems.append(Spacer(1,2))
                elems.append(Spacer(1,10))

            # ── Footer
            elems += [
                HRFlowable(width="100%",thickness=1,color=rlc.HexColor("#30363d")),
                Spacer(1,6),
                Paragraph(f"8. Done By", h2_s),
                Paragraph(f"Assessor         : {assessor}", body),
                Paragraph(f"Organization     : Supraja Technologies Cyber Security Cell", body),
                Paragraph(f"Unit             : a unit of CHSMRLSS Technologies Pvt. Ltd.", body),
                Paragraph(f"Website          : www.suprajatechnologies.com", body),
                Paragraph(f"Location         : Vijayawada, Andhra Pradesh, India", body),
                Paragraph(f"Date of Report   : {stamp}", body),
                Spacer(1,8),
                Paragraph("⚠ DISCLAIMER: This report is intended for authorized security assessment "
                          "purposes only. Unauthorized scanning is illegal.",
                          ParagraphStyle("disc",parent=body,fontSize=7,
                                         textColor=rlc.HexColor("#8b949e"))),
            ]

            doc.build(elems)
            messagebox.showinfo("PDF Saved", f"Report saved:\n{path}")
        except Exception as exc:
            messagebox.showerror("PDF Error", str(exc))


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    AdvancedPortScanner(root)
    root.mainloop()
