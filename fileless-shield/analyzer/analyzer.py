#!/usr/bin/env python3
"""
FilelessShield Layer 3 — Process & Memory Analyzer
Fills the gap Falco + auditd don't cover:
  - /proc RWX anonymous memory regions
  - pstree parent-child heuristics
  - baseline deviation
"""

import psutil, os, json, time, subprocess, logging

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler("/var/log/analyzer.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("FilelessShield")

# ── Heuristics ───────────────────────────────────────────────────────

# These are NOT covered by your existing Falco rules
SUSPICIOUS_PAIRS = {
    "nginx":    ["bash","sh","python3","perl","curl","wget","nc"],
    "apache2":  ["bash","sh","python3","perl","curl","wget"],
    "httpd":    ["bash","sh","python3","perl"],
    "node":     ["bash","sh","nc","ncat"],
    "java":     ["bash","sh","curl","wget"],
    "php-fpm":  ["bash","sh","python3"],
    "mysql":    ["bash","sh"],
    "postgres": ["bash","sh"],
}

ALWAYS_SUSPICIOUS = [
    "xmrig","minerd","kdevtmpfsi",  # crypto miners
    "ncat","socat",                  # raw netcat tools
]

SUSPICIOUS_PATHS = ["/tmp/","/dev/shm/","/var/tmp/","/run/shm/"]

# These overlap Falco — skip them here to avoid duplicate alerts
SKIP_CMDLINE_PATTERNS = [
    "curl","wget","base64"  # Falco rules 100100/100101 already catch these
]

# ── /proc Memory Scanner ─────────────────────────────────────────────

def scan_proc_memory():
    """
    Scans /proc/[pid]/maps for RWX anonymous regions and deleted-file
    execution. Falco catches the syscall; this catches what survives.
    """
    alerts = []
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        try:
            with open(f"/proc/{pid_dir}/maps") as f:
                maps = f.read()

            for line in maps.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue

                perms = parts[1]
                inode = parts[4] if len(parts) > 4 else "0"

                # RWX anonymous region = injected shellcode
                if perms == "rwxp" and inode == "0":
                    cmd = _cmdline(pid_dir)
                    alerts.append({
                        "type":     "ANON_RWX_REGION",
                        "pid":      pid_dir,
                        "cmd":      cmd,
                        "severity": "CRITICAL",
                        "mitre":    "T1055 - Process Injection",
                        "detail":   f"RWX anonymous memory region in pid {pid_dir}"
                    })
                    break

                # Deleted file execution = memfd_create artifact
                if "r-xp" in perms and "(deleted)" in line:
                    cmd = _cmdline(pid_dir)
                    alerts.append({
                        "type":     "DELETED_FILE_EXEC",
                        "pid":      pid_dir,
                        "cmd":      cmd,
                        "severity": "CRITICAL",
                        "mitre":    "T1620 - Reflective Code Loading",
                        "detail":   f"Executing deleted/memfd file in pid {pid_dir}"
                    })
                    break

        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue
    return alerts

# ── Process Tree Heuristics ──────────────────────────────────────────

def scan_process_tree():
    """
    Detects suspicious parent-child process relationships.
    Complements Falco which watches syscall chains — this watches
    the resulting process tree state.
    """
    alerts = []
    for proc in psutil.process_iter(
        ['pid','ppid','name','exe','cmdline','username']
    ):
        try:
            name    = proc.info['name'] or ""
            exe     = proc.info['exe'] or ""
            cmdline = " ".join(proc.info['cmdline'] or [])
            pid     = proc.info['pid']

            try:
                pname = psutil.Process(proc.info['ppid']).name()
            except Exception:
                pname = "unknown"

            # CHECK 1: Suspicious parent→child
            if pname in SUSPICIOUS_PAIRS and name in SUSPICIOUS_PAIRS[pname]:
                alerts.append({
                    "type":     "SUSPICIOUS_PARENT_CHILD",
                    "pid":      pid,
                    "cmd":      cmdline[:200],
                    "severity": "HIGH",
                    "mitre":    "T1059 - Command and Scripting Interpreter",
                    "detail":   f"Service '{pname}' spawned shell '{name}'"
                })

            # CHECK 2: Known miner / malicious binary
            if name in ALWAYS_SUSPICIOUS:
                alerts.append({
                    "type":     "KNOWN_MALICIOUS_BINARY",
                    "pid":      pid,
                    "cmd":      cmdline[:200],
                    "severity": "CRITICAL",
                    "mitre":    "T1496 - Resource Hijacking",
                    "detail":   f"Known malicious binary detected: {name}"
                })

            # CHECK 3: Binary running from /tmp or /dev/shm
            if exe and any(exe.startswith(p) for p in SUSPICIOUS_PATHS):
                alerts.append({
                    "type":     "EXEC_FROM_WRITABLE_PATH",
                    "pid":      pid,
                    "cmd":      cmdline[:200],
                    "severity": "HIGH",
                    "mitre":    "T1059 - Command and Scripting Interpreter",
                    "detail":   f"Binary executing from writable path: {exe}"
                })

            # CHECK 4: Orphan process with no exe (pure memory process)
            if not exe and proc.info['ppid'] == 1:
                if name not in ["systemd","init","kthreadd","(sd-pam)"]:
                    alerts.append({
                        "type":     "ORPHAN_NO_EXE",
                        "pid":      pid,
                        "cmd":      cmdline[:200],
                        "severity": "MEDIUM",
                        "mitre":    "T1055 - Process Injection",
                        "detail":   f"Orphan process with no exe path: {name}"
                    })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return alerts

# ── Baseline Builder / Deviation Checker ────────────────────────────

BASELINE_FILE = "/analyzer/baseline.json"

def build_baseline():
    baseline = {}
    for proc in psutil.process_iter(['name','ppid']):
        try:
            pname = psutil.Process(proc.info['ppid']).name()
            key   = f"{pname}->{proc.info['name']}"
            baseline[key] = baseline.get(key, 0) + 1
        except Exception:
            pass
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    log.info(f"Baseline built: {len(baseline)} process relationships recorded")
    return baseline

def load_baseline():
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def check_baseline_deviation(baseline):
    """Alert on process relationships never seen in baseline"""
    alerts = []
    if not baseline:
        return alerts
    for proc in psutil.process_iter(['name','ppid','pid','cmdline']):
        try:
            pname = psutil.Process(proc.info['ppid']).name()
            key   = f"{pname}->{proc.info['name']}"
            if key not in baseline:
                # Only flag if parent is a known service
                if pname in SUSPICIOUS_PAIRS:
                    alerts.append({
                        "type":     "BASELINE_DEVIATION",
                        "pid":      proc.info['pid'],
                        "cmd":      " ".join(proc.info['cmdline'] or [])[:200],
                        "severity": "HIGH",
                        "mitre":    "T1059 - Command and Scripting Interpreter",
                        "detail":   f"New relationship never seen in baseline: {key}"
                    })
        except Exception:
            pass
    return alerts

# ── Alert Output ─────────────────────────────────────────────────────

def emit(alert):
    """
    Structured log line — Wazuh localfile ingestion picks this up.
    Format matches your existing Falco→Wazuh decoder pattern.
    """
    line = json.dumps({
        "source":   "fileless-analyzer",
        "severity": alert['severity'],
        "type":     alert['type'],
        "pid":      alert['pid'],
        "mitre":    alert['mitre'],
        "detail":   alert['detail'],
        "cmd":      alert['cmd'],
    })

    if alert['severity'] == "CRITICAL":
        log.critical(line)
    elif alert['severity'] == "HIGH":
        log.warning(line)
    else:
        log.info(line)

    # Feed into syslog → Wazuh agent reads this too
    subprocess.run(["logger", "-p", "security.crit", f"fileless-analyzer: {line}"],
                   capture_output=True)

def _cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline") as f:
            return f.read().replace("\x00", " ").strip()[:200]
    except Exception:
        return ""

# ── Main ─────────────────────────────────────────────────────────────

def main():
    log.info("FilelessShield Analyzer v2 — starting")

    baseline = load_baseline()
    if not baseline:
        log.info("No baseline found — building from current clean state")
        baseline = build_baseline()

   # seen = set()   # deduplicate across scans
    scan = 0

    while True:
        scan += 1
        log.info(f"--- Scan #{scan} ---")

        alerts = []
        alerts += scan_proc_memory()
        alerts += scan_process_tree()
        alerts += check_baseline_deviation(baseline)

        new = 0
        for a in alerts:
            emit(a)
            new += 1
            #key = f"{a['pid']}-{a['type']}"
            #if key not in seen:
            #    seen.add(key)
            #    emit(a)
            #    new += 1

        log.info(f"Scan #{scan} done — {new} new alerts")

        # Refresh baseline every 24 hours
        if scan % 1440 == 0:
            log.info("Refreshing baseline")
            baseline = build_baseline()

        time.sleep(60)

if __name__ == "__main__":
    main()
