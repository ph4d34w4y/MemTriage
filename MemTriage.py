#!/usr/bin/env python3
"""
MemTriage.py - Memory forensics triage wrapper around Volatility 3.

Runs the key Volatility 3 plugins for detecting in-memory code injection,
correlates findings per process, scores each process for suspiciousness,
and produces a clean prioritised report.

Plugins used:
  windows.pslist     - linked process list
  windows.psscan     - pool scan to identify processes absent from pslist
  windows.malfind    - RWX/PE regions with no backing file on disk
  windows.ldrmodules - modules missing from one or more PEB linked lists
  windows.cmdline    - command lines (catches powershell -enc, etc.)
  windows.netscan    - network object artifacts per process
  windows.dlllist    - loaded DLLs (spots unusual load paths)

Usage:
  python MemTriage.py memory.dmp
  python MemTriage.py memory.dmp --report out.txt --json findings.json
  python MemTriage.py memory.dmp --vol /opt/volatility3/vol.py
  python MemTriage.py memory.dmp --redact-cmdline --report out.txt
  python MemTriage.py --demo          (synthetic data, no dump needed)

Requires: Volatility 3  (https://github.com/volatilityfoundation/volatility3)
          pip install volatility3   OR   clone + python vol.py
"""

import argparse
import json
import ntpath
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Suspicious indicator patterns applied to command lines, DLL paths, etc.
# ---------------------------------------------------------------------------

CMD_INDICATORS = [
    (re.compile(r"(?<!\S)[-/](?:enc|encodedcommand)(?=\s|:|$)", re.I), "HIGH", "PowerShell encoded command", "powershell"),
    (re.compile(r"(?<!\S)[-/](?:nop|noprofile)(?=\s|$)", re.I), "MEDIUM", "PowerShell NoProfile option", "powershell"),
    (re.compile(r"\b(?:IEX|Invoke-Expression)\b", re.I), "HIGH", "PowerShell expression execution", "powershell"),
    (re.compile(r"\b(?:DownloadString|DownloadFile)\b", re.I), "HIGH", "PowerShell download method", "powershell"),
    (re.compile(r"\bFromBase64String\b", re.I), "HIGH", "PowerShell Base64 decoding", "powershell"),
    (re.compile(r"(?<!\S)[-/](?:ExecutionPolicy|Exec)\s+Bypass\b", re.I), "MEDIUM", "PowerShell execution policy bypass", "powershell"),
    (re.compile(r"\bmshta(?:\.exe)?\b", re.I), "MEDIUM", "mshta invocation", None),
    (re.compile(r"\bregsvr32(?:\.exe)?\b.*\bscrobj\b", re.I), "HIGH", "regsvr32 scriptlet pattern", None),
    (re.compile(r"\brundll32(?:\.exe)?\b", re.I), "LOW", "rundll32 invocation", None),
    (re.compile(r"\bcertutil(?:\.exe)?\b.*(?<!\S)-urlcache\b", re.I), "HIGH", "certutil URL cache use", None),
    (re.compile(r"\bbitsadmin(?:\.exe)?\b", re.I), "MEDIUM", "bitsadmin invocation", None),
    (re.compile(r"\bschtasks(?:\.exe)?\b.*(?<!\S)/create\b", re.I), "MEDIUM", "Scheduled task creation", None),
    (re.compile(r"\bCurrentVersion\\Run\b", re.I), "HIGH", "Run key reference", None),
    (re.compile(r"\bvssadmin(?:\.exe)?\b.*\bdelete\b", re.I), "HIGH", "Shadow copy deletion command", None),
    (re.compile(r"\b(?:wscript|cscript)(?:\.exe)?\b", re.I), "LOW", "Windows Script Host invocation", None),
    (re.compile(r"\bnet(?:\.exe)?\s+user\b.*/add\b", re.I), "HIGH", "User account creation command", None),
    (re.compile(r"\b(?:mimikatz|sekurlsa)\b", re.I), "HIGH", "Credential tool reference", None),
]

# Processes whose connection artifacts warrant closer review
SENSITIVE_PROCS = {
    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "services.exe", "winlogon.exe", "dwm.exe",
}

# Common Windows DLL paths; location alone does not establish trust
LEGIT_DLL_DIRS = [
    r"c:\windows\system32", r"c:\windows\syswow64",
    r"c:\windows\winsxs",   r"c:\program files",
]

# Processes commonly faked by malware (process name spoofing)
COMMON_SPOOFED = {
    "svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe",
    "winlogon.exe", "services.exe", "spoolsv.exe",
}

# Expected parents for system processes
EXPECTED_PARENTS = {
    "smss.exe":     {"system"},
    "csrss.exe":    {"smss.exe"},
    "wininit.exe":  {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe":    {"wininit.exe"},
    "svchost.exe":  {"services.exe"},
    "taskhost.exe": {"services.exe"},
    "spoolsv.exe":  {"services.exe"},
    "explorer.exe": {"userinit.exe"},
}

SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

REQUIRED_COLUMNS = {
    "windows.pslist": {"PID", "PPID", "ImageFileName", "CreateTime", "ExitTime"},
    "windows.psscan": {"PID", "PPID", "ImageFileName", "CreateTime", "ExitTime"},
    "windows.cmdline": {"PID", "Args"},
    "windows.malfind": {"PID", "Process", "Start VPN", "End VPN", "Protection"},
    "windows.ldrmodules": {"Pid", "Base", "InLoad", "InInit", "InMem", "MappedPath"},
    "windows.netscan": {"PID", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State"},
    "windows.dlllist": {"PID", "Path"},
}


# ---------------------------------------------------------------------------
# Volatility 3 runner
# ---------------------------------------------------------------------------

def run_plugin(vol_bin, dump, plugin, extra_args=None):
    """
    Run a Volatility 3 plugin and return parsed rows as list-of-dicts.
    Request Volatility's structured JSON renderer.
    """
    launcher = [sys.executable, vol_bin] if Path(vol_bin).suffix.lower() == ".py" else [vol_bin]
    cmd = launcher + ["-q", "-r", "json", "-f", dump, plugin]
    if extra_args:
        cmd += extra_args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return [], result.stderr.strip() or f"{plugin} exited {result.returncode}"
        rows = json.loads(result.stdout)
        if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
            return [], f"{plugin} returned an unexpected JSON structure"
        for index, row in enumerate(rows):
            missing = REQUIRED_COLUMNS.get(plugin, set()) - row.keys()
            if missing:
                return [], f"{plugin} row {index} missing columns: {', '.join(sorted(missing))}"
        return rows, None
    except FileNotFoundError:
        return [], f"Volatility binary not found: {vol_bin}"
    except subprocess.TimeoutExpired:
        return [], f"Plugin {plugin} timed out after 300s"
    except (ValueError, OSError) as e:
        return [], str(e)


def safe_int(val, default=0):
    try:
        return int(str(val).replace(",", "").strip(), 0)
    except (ValueError, TypeError):
        return default


def row_pid(row):
    return safe_int(row.get("PID", row.get("Pid", row.get("pid", 0))))


def readable(value):
    return "" if value is None or value in ("N/A", "-", "") else str(value)


def plausible_established_connection(conn, process):
    """A live-looking remote TCP row, with no contradictory process timeline."""
    if str(conn["state"]).upper() != "ESTABLISHED":
        return False
    remote = conn["foreign"].rsplit(":", 1)
    if len(remote) != 2 or remote[0] in {"0.0.0.0", "::", "*", "?", ""} or remote[1] in {"0", "?", ""}:
        return False
    try:
        created = datetime.fromisoformat(conn.get("created", "").replace("Z", "+00:00"))
        started = datetime.fromisoformat(process.create_time.replace("Z", "+00:00"))
        if created < started:
            return False
        if process.exit_time:
            exited = datetime.fromisoformat(process.exit_time.replace("Z", "+00:00"))
            if created > exited:
                return False
    except (TypeError, ValueError, AttributeError):
        pass  # Missing dates do not prove the row invalid.
    return True


def writable_dll_path(path):
    normalized = ntpath.normpath(path.replace("/", "\\")).lower()
    components = normalized.split("\\")
    return (any(part in {"appdata", "temp", "tmp", "downloads"} for part in components)
            or "programdata" in components
            or ("users" in components and "public" in components))


# ---------------------------------------------------------------------------
# Per-process data collector
# ---------------------------------------------------------------------------

class ProcessRecord:
    def __init__(self, pid, name, ppid=0, parent_name=""):
        self.pid = pid
        self.name = name
        self.ppid = ppid
        self.parent_name = parent_name
        self.cmdline = ""
        self.malfind_hits = []       # each: {address, size, protection, has_pe, notes}
        self.hidden_modules = []     # each: {base, path, missing_from}
        self.network = []            # each: {proto, local, foreign, state}
        self.dll_paths = []
        self.indicators = []         # each: {severity, desc}
        self.score = 0
        self.scan_only = False
        self.offset = ""
        self.create_time = ""
        self.exit_time = ""
        self.sources = {}
        self.exe_path_candidate = ""
        self.exe_path_row = None

    def add_indicator(self, severity, desc, plugin=None, row=None, rule=None):
        key = (severity, desc)
        if key not in {(i["severity"], i["desc"]) for i in self.indicators}:
            self.indicators.append({"severity": severity, "desc": desc,
                                    "evidence": {"plugin": plugin, "row": row, "rule": rule}})
            self.score += {"HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}[severity]

    def max_severity(self):
        if not self.indicators:
            return "CLEAN"
        return min((i["severity"] for i in self.indicators),
                   key=lambda s: SEVERITY_RANK[s])


def collect(vol_bin, dump):
    """Run plugins and return process records, errors, and plugin coverage."""
    procs = {}
    errors = []
    coverage = {}

    def fetch(plugin):
        rows, err = run_plugin(vol_bin, dump, plugin)
        coverage[plugin] = {"status": "error" if err else "ok", "rows": len(rows),
                            "error": err}
        if err:
            errors.append((plugin, err))
        return rows, err

    def _ensure(pid, name="<unknown>", ppid=0, parent=""):
        if pid not in procs:
            procs[pid] = ProcessRecord(pid, name, ppid, parent)
        return procs[pid]

    # --- pslist ----------------------------------------------------------
    rows, err = fetch("windows.pslist")
    if err:
        return procs, errors, coverage
    pid_to_name = {}
    for index, r in enumerate(rows):
        pid  = safe_int(r.get("PID", r.get("pid", 0)))
        ppid = safe_int(r.get("PPID", r.get("ppid", 0)))
        name = r.get("ImageFileName", r.get("name", "<?>")).strip()
        if pid:
            pid_to_name[pid] = name
            pr = _ensure(pid, name, ppid)
            pr.offset = readable(r.get("Offset(P)", r.get("Offset(V)", r.get("Offset", ""))))
            pr.create_time = readable(r.get("CreateTime"))
            pr.exit_time = readable(r.get("ExitTime"))
            pr.sources["windows.pslist"] = index

    # Back-fill parent names now that pid_to_name is complete
    for pr in procs.values():
        if pr.ppid in pid_to_name:
            pr.parent_name = pid_to_name[pr.ppid]

    # A pool scan can find candidates that are absent from the linked list.
    rows, err = fetch("windows.psscan")
    if not err:
        for index, r in enumerate(rows):
            pid = row_pid(r)
            if not pid:
                continue
            offset = readable(r.get("Offset(P)", r.get("Offset(V)", r.get("Offset", ""))))
            created = readable(r.get("CreateTime"))
            active = procs.get(pid)
            if active and ((active.offset and offset and active.offset == offset)
                           or (active.create_time and created and active.create_time == created)):
                active.sources["windows.psscan"] = index
            elif not active or (offset or created):
                # Keep a reused PID separate from the linked process record.
                key = (pid, offset, created)
                pr = ProcessRecord(pid, r.get("ImageFileName", "<?>"), safe_int(r.get("PPID", 0)))
                procs[key] = pr
                pr.scan_only = True
                pr.offset, pr.create_time = offset, created
                pr.exit_time = readable(r.get("ExitTime"))
                pr.sources["windows.psscan"] = index
                pr.parent_name = pid_to_name.get(pr.ppid, "")
            else:
                # Identity absent from output: a PID alone cannot prove a second process.
                active.sources["windows.psscan"] = index

    ambiguous_pids = {pr.pid for pr in procs.values() if pr.scan_only and pr.pid in pid_to_name}

    def unambiguous(pid, plugin):
        if pid in ambiguous_pids:
            coverage[plugin]["status"] = "partial"
            coverage[plugin]["skipped_ambiguous_pid_rows"] = (
                coverage[plugin].get("skipped_ambiguous_pid_rows", 0) + 1)
            return False
        return True

    # --- cmdline ---------------------------------------------------------
    rows, err = fetch("windows.cmdline")
    for index, r in enumerate(rows):
        pid  = safe_int(r.get("PID", r.get("pid", 0)))
        args = r.get("Args", r.get("cmdline", "")).strip()
        if pid and unambiguous(pid, "windows.cmdline"):
            pr = _ensure(pid, pid_to_name.get(pid, "<?>"))
            pr.cmdline = args
            pr.sources["windows.cmdline"] = index

    # --- malfind ---------------------------------------------------------
    rows, err = fetch("windows.malfind")
    for index, r in enumerate(rows):
        pid  = safe_int(r.get("PID", r.get("pid", 0)))
        proc = r.get("Process", r.get("process", pid_to_name.get(pid, "<?>")))
        prot = str(r.get("Protection", r.get("protection", "")))
        addr = str(r.get("Start VPN", r.get("start", r.get("address", "?"))))
        end  = str(r.get("End VPN", r.get("end", "")))
        note = str(r.get("Notes", r.get("notes", "")))
        # Detect PE header in the hexdump column if present
        hexdump = str(r.get("Hexdump", r.get("hexdump", "")))
        has_pe = "4d 5a" in hexdump.lower() or "MZ" in note
        # Compute region size
        try:
            sz = safe_int(end, 0) - safe_int(addr, 0)
        except Exception:
            sz = 0
        if not pid or not unambiguous(pid, "windows.malfind"):
            continue
        pr = _ensure(pid, proc)
        pr.malfind_hits.append({
            "address": addr, "size": sz, "protection": prot,
            "has_pe": has_pe, "notes": note, "source_row": index,
        })

    # --- ldrmodules ------------------------------------------------------
    rows, err = fetch("windows.ldrmodules")
    for index, r in enumerate(rows):
        pid     = safe_int(r.get("Pid", r.get("pid", 0)))
        in_load = str(r.get("InLoad", "")).lower()
        in_init = str(r.get("InInit", "")).lower()
        in_mem  = str(r.get("InMem",  "")).lower()
        path    = r.get("MappedPath", r.get("mapped_path", r.get("path", ""))).strip()
        base    = r.get("Base", r.get("base", "?"))
        missing = []
        if in_load == "false":
            missing.append("LoadOrder list")
        if in_init == "false":
            missing.append("InitOrder list")
        if in_mem  == "false":
            missing.append("MemOrder list")
        if pid and missing and path and unambiguous(pid, "windows.ldrmodules"):
            pr = _ensure(pid, pid_to_name.get(pid, "<?>"))
            pr.hidden_modules.append({"base": base, "path": path,
                                      "missing_from": missing, "source_row": index})

    # --- netscan ---------------------------------------------------------
    rows, err = fetch("windows.netscan")
    for index, r in enumerate(rows):
        pid     = row_pid(r)
        proto   = r.get("Proto", r.get("proto", ""))
        local   = f"{r.get('LocalAddr','?')}:{r.get('LocalPort','?')}"
        foreign = f"{r.get('ForeignAddr','?')}:{r.get('ForeignPort','?')}"
        state   = r.get("State", r.get("state", ""))
        if pid and unambiguous(pid, "windows.netscan"):
            pr = _ensure(pid, pid_to_name.get(pid, "<?>"))
            pr.network.append({"proto": proto, "local": local,
                               "foreign": foreign, "state": state,
                               "created": readable(r.get("Created")), "source_row": index})

    # --- dlllist ---------------------------------------------------------
    rows, err = fetch("windows.dlllist")
    for index, r in enumerate(rows):
        pid  = safe_int(r.get("PID", r.get("pid", 0)))
        path = r.get("Path", r.get("path", r.get("Dll", ""))).strip()
        if pid and path and unambiguous(pid, "windows.dlllist"):
            pr = _ensure(pid, pid_to_name.get(pid, "<?>"))
            pr.dll_paths.append(path)
            pr.sources.setdefault("windows.dlllist", {})[path] = index
            # Loader list metadata is a candidate, not a verified kernel image path.
            module_name = str(r.get("Name", ""))
            if (not pr.exe_path_candidate and module_name.lower() == pr.name.lower()
                    and ntpath.basename(path.replace("/", "\\")).lower() == pr.name.lower()
                    and path.lower().endswith(".exe")):
                pr.exe_path_candidate = path
                pr.exe_path_row = index

    for plugin, result in coverage.items():
        if result["status"] == "partial":
            errors.append((plugin, f"Skipped {result['skipped_ambiguous_pid_rows']} row(s) whose PID belongs to multiple process identities"))
    return procs, errors, coverage


# ---------------------------------------------------------------------------
# Heuristic scoring engine
# ---------------------------------------------------------------------------

def score_all(procs):
    """Apply all heuristics to every process and populate their indicators."""

    for pr in procs.values():
        name_lower = pr.name.lower()

        if pr.scan_only:
            pr.add_indicator("INFO" if pr.exit_time else "MEDIUM",
                "Exited process found only by pool scan" if pr.exit_time else
                "Process found only by pool scan; verify object and timeline",
                "windows.psscan", pr.sources.get("windows.psscan"), "scan_only")

        # 1. Malfind hits
        for hit in pr.malfind_hits:
            prot = hit["protection"].upper()
            if hit["has_pe"]:
                pr.add_indicator("HIGH",
                    f"MZ/PE-like header in candidate memory region @ {hit['address']} ({prot})",
                    "windows.malfind", hit.get("source_row"), "malfind_header")
            elif "EXECUTE" in prot or "PAGE_EXEC" in prot or "X" in prot:
                pr.add_indicator("HIGH",
                    f"Executable memory candidate @ {hit['address']} (prot={prot}); inspect VAD and bytes",
                    "windows.malfind", hit.get("source_row"), "malfind_executable")
            else:
                pr.add_indicator("MEDIUM",
                    f"Suspicious private memory @ {hit['address']} ({prot})",
                    "windows.malfind", hit.get("source_row"), "malfind_other")

        # 2. Hidden modules
        for mod in pr.hidden_modules:
            pr.add_indicator("HIGH",
                f"Module missing from PEB list(s): {mod['path']} @ {mod['base']} "
                f"(missing from {', '.join(mod['missing_from'])})",
                "windows.ldrmodules", mod.get("source_row"), "peb_list_missing")

        # 4. Command line indicators
        if pr.cmdline:
            ps_context = name_lower in {"powershell.exe", "pwsh.exe"} or bool(
                re.search(r"\b(?:powershell|pwsh)(?:\.exe)?\b", pr.cmdline, re.I))
            for regex, sev, desc, context in CMD_INDICATORS:
                if (context != "powershell" or ps_context) and regex.search(pr.cmdline):
                    pr.add_indicator(sev, desc, "windows.cmdline",
                                     pr.sources.get("windows.cmdline"), "cmd_pattern")

        # 5. Parent process anomalies
        expected = EXPECTED_PARENTS.get(name_lower)
        if expected and pr.parent_name and pr.parent_name.lower() not in expected:
            pr.add_indicator("HIGH",
                f"Unexpected parent: {pr.name} should come from "
                f"{expected} but parent is {pr.parent_name!r} "
                f"(PPID {pr.ppid}) — process spoofing?",
                "windows.pslist", pr.sources.get("windows.pslist"), "parent_anomaly")

        # 6. Multiple instances of single-instance system processes
        # (resolved at report time)

        # 7. DLL loaded from suspicious path
        for dll in pr.dll_paths:
            dll_lower = dll.lower()
            in_legit = any(dll_lower == d or dll_lower.startswith(d + '\\') for d in LEGIT_DLL_DIRS)
            if not in_legit and dll_lower.endswith(".dll"):
                # Temp/user writable paths are suspicious
                if writable_dll_path(dll):
                    pr.add_indicator("HIGH",
                        f"DLL loaded from user-writable path: {dll}",
                        "windows.dlllist", pr.sources.get("windows.dlllist", {}).get(dll), "writable_dll")
                elif dll_lower not in [r"", "?"]:
                    pr.add_indicator("LOW",
                        f"DLL outside standard system dirs: {dll}",
                        "windows.dlllist", pr.sources.get("windows.dlllist", {}).get(dll), "dll_path")

        if pr.exe_path_candidate and writable_dll_path(pr.exe_path_candidate):
            pr.add_indicator("HIGH", f"Executable path candidate in user-writable location: {pr.exe_path_candidate}",
                             "windows.dlllist", pr.exe_path_row, "executable_path")

        established = [c for c in pr.network if plausible_established_connection(c, pr)]
        if established and (name_lower in SENSITIVE_PROCS or name_lower in
                            {"notepad.exe", "calc.exe", "wordpad.exe", "mspaint.exe"}):
            corroborated = any(i["severity"] in {"HIGH", "MEDIUM"} for i in pr.indicators)
            pr.add_indicator("HIGH" if corroborated else "MEDIUM",
                f"{pr.name} has established remote connection artifact: {established[0]['foreign']}; verify timing and endpoint",
                "windows.netscan", established[0].get("source_row"), "unexpected_network")

    # Multi-instance check (done here so we have the full proc list)
    single_instance = {
        "lsass.exe", "wininit.exe", "services.exe",
    }
    name_counts = defaultdict(list)
    for pr in procs.values():
        if not pr.scan_only and not pr.exit_time:
            name_counts[pr.name.lower()].append(pr.pid)
    for name, pids in name_counts.items():
        if name in single_instance and len(pids) > 1:
            for pid in pids:
                procs[pid].add_indicator("HIGH",
                    f"Multiple instances of {name} (PIDs {pids}) — "
                    "verify image paths and creation times",
                    "windows.pslist", procs[pid].sources.get("windows.pslist"), "instance_count")

    # Repeated evidence from one rule has diminishing value; independent
    # sources still increase the investigation priority.
    weights = {"HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    for pr in procs.values():
        by_rule = defaultdict(list)
        for ind in pr.indicators:
            evidence = ind.get("evidence") or {}
            by_rule[evidence.get("rule") or ind["desc"]].append(weights[ind["severity"]])
        pr.score = sum(sum(sorted(values, reverse=True)[:2]) for values in by_rule.values())


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def human_size(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


def build_report(procs, errors, dump_path, coverage=None, redact_cmdline=False):
    L = []
    w = L.append

    suspicious = [pr for pr in procs.values() if pr.indicators]
    clean      = [pr for pr in procs.values() if not pr.indicators]
    suspicious.sort(key=lambda p: (-p.score, p.name))

    sev_counts = defaultdict(int)
    for pr in suspicious:
        sev_counts[pr.max_severity()] += 1

    w("=" * 72)
    w("  MEMORY FORENSICS TRIAGE REPORT")
    w(f"  Dump file   : {dump_path}")
    w(f"  Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"  Processes   : {len(procs)} total  |  {len(suspicious)} flagged  |  {len(clean)} with no indicators")
    w(f"  Findings    : " + "   ".join(
        f"{s}: {sev_counts.get(s,0)}" for s in ["HIGH","MEDIUM","LOW"]))
    if errors:
        w(f"  INCOMPLETE ANALYSIS: {len(errors)} plugin error(s)")
        for plugin, msg in errors:
            w(f"    {plugin}: {msg}")
    if coverage:
        w("  Plugin coverage:")
        for plugin, result in coverage.items():
            w(f"    {plugin}: {result['status']} ({result['rows']} rows)")
    w("=" * 72)

    if not suspicious:
        w("")
        w("  No indicators detected in the available plugin results.")
        w("")
        return "\n".join(L)

    # Priority queue: highest score first
    w("")
    w("  INVESTIGATE FIRST (ranked by suspicion score):")
    w("")
    for pr in suspicious[:8]:
        bar = "█" * min(pr.score // 5, 20)
        w(f"    PID {pr.pid:<6}  {pr.name:<22}  score={pr.score:<4}  "
          f"[{pr.max_severity()}]  {bar}")
    w("")

    # Detailed per-process breakdown
    for n, pr in enumerate(suspicious, 1):
        w("-" * 72)
        w(f"  PROCESS #{n}  [{pr.max_severity()}]  score={pr.score}")
        w(f"  Name     : {pr.name}  (PID {pr.pid})")
        if pr.offset or pr.create_time or pr.exit_time:
            w(f"  Identity : offset={pr.offset or '?'}  created={pr.create_time or '?'}  exited={pr.exit_time or 'no/unknown'}")
        if pr.exe_path_candidate:
            w(f"  Loader path candidate: {pr.exe_path_candidate} (dlllist row {pr.exe_path_row})")
        w(f"  Parent   : {pr.parent_name or '<unknown>'}  (PPID {pr.ppid})")
        if pr.cmdline:
            if redact_cmdline:
                w("  CmdLine  : [REDACTED]")
            else:
                w(f"  CmdLine  : {pr.cmdline[:120]}"
                  + ("..." if len(pr.cmdline) > 120 else ""))

        # Indicators sorted by severity
        if pr.indicators:
            w("")
            w("  INDICATORS:")
            for ind in sorted(pr.indicators, key=lambda i: SEVERITY_RANK[i["severity"]]):
                ev = ind.get("evidence") or {}
                source = f" [{ev['plugin']} row {ev['row']}]" if ev.get("plugin") and ev.get("row") is not None else ""
                w(f"    [{ind['severity']:<6}] {ind['desc']}{source}")

        # Malfind detail
        if pr.malfind_hits:
            w("")
            w(f"  INJECTED / SUSPICIOUS MEMORY REGIONS ({len(pr.malfind_hits)}):")
            for hit in pr.malfind_hits:
                sz = human_size(hit["size"]) if hit["size"] > 0 else "?"
                pe_flag = "  ← MZ/PE HEADER PRESENT" if hit["has_pe"] else ""
                w(f"    {hit['address']}  size={sz}  prot={hit['protection']}{pe_flag}")
                if hit["notes"]:
                    w(f"      notes: {hit['notes']}")

        # Hidden modules
        if pr.hidden_modules:
            w("")
            w(f"  HIDDEN MODULES (not in PEB linked lists) ({len(pr.hidden_modules)}):")
            for mod in pr.hidden_modules:
                w(f"    {mod['base']}  {mod['path']}")
                w(f"      missing from: {', '.join(mod['missing_from'])}")

        # Network
        if pr.network:
            w("")
            w(f"  NETWORK CONNECTIONS ({len(pr.network)}):")
            for c in pr.network[:10]:
                w(f"    {c['proto']:<6} {c['local']:<25} -> {c['foreign']:<25} {c['state']}")
            if len(pr.network) > 10:
                w(f"    ... and {len(pr.network)-10} more")

        # Suspicious DLLs
        sus_dlls = [d for d in pr.dll_paths if writable_dll_path(d)]
        if sus_dlls:
            w("")
            w(f"  DLLS FROM SUSPICIOUS PATHS ({len(sus_dlls)}):")
            for d in sus_dlls[:5]:
                w(f"    {d}")

        w("")

    # Plugin errors
    if errors:
        w("-" * 72)
        w("  PLUGIN ERRORS")
        w("-" * 72)
        for plugin, msg in errors:
            w(f"  {plugin}: {msg}")
        w("")

    # Next steps
    w("=" * 72)
    w("  RECOMMENDED NEXT STEPS")
    w("=" * 72)
    top = suspicious[0] if suspicious else None
    if top:
        w(f"  1. Inspect PID {top.pid} ({top.name}) and validate the findings above.")
        w( "  2. If malfind identified a region, use its --dump option with --pid")
        w( "     and hash the extracted bytes locally before external lookup.")
        w( "  3. Correlate with your pcap capture:")
        w( "       Cross-reference PIDs' network connections against your")
        w( "       NetFlow / pcap analysis to link host activity to wire data.")
        w( "  4. Run targeted YARA rules against candidate memory regions.")
    w("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Demo mode - synthetic data so you can see the report without a real dump
# ---------------------------------------------------------------------------

def demo_procs():
    """Return a realistic set of ProcessRecords with planted findings."""
    procs = {}

    def add(pid, name, ppid, parent_name):
        procs[pid] = ProcessRecord(pid, name, ppid, parent_name)
        return procs[pid]

    # Normal processes
    add(4,    "System",       0,    "")
    add(320,  "smss.exe",     4,    "System")
    add(460,  "csrss.exe",    320,  "smss.exe")
    add(512,  "wininit.exe",  320,  "smss.exe")
    add(552,  "winlogon.exe", 320,  "smss.exe")
    add(608,  "services.exe", 512,  "wininit.exe")
    add(636,  "lsass.exe",    512,  "wininit.exe")
    add(980,  "explorer.exe", 1,    "userinit.exe")
    add(1234, "chrome.exe",   980,  "explorer.exe")
    add(1800, "notepad.exe",  980,  "explorer.exe")

    # ---- FINDING 1: process-hollowed svchost ----
    # svchost spawned by explorer (wrong parent - should be services.exe)
    hollow = add(2112, "svchost.exe", 980, "explorer.exe")
    hollow.cmdline = "svchost.exe"
    hollow.malfind_hits.append({
        "address": "0xb80000", "size": 77824,
        "protection": "PAGE_EXECUTE_READWRITE",
        "has_pe": True,
        "notes": "MZ header, no VAD backing file",
    })
    hollow.network.append({"proto": "TCPv4",
        "local": "10.0.0.15:49312",
        "foreign": "185.220.101.44:443", "state": "ESTABLISHED"})

    # ---- FINDING 2: PowerShell with encoded command + reflective region ----
    ps = add(3344, "powershell.exe", 2112, "svchost.exe")
    ps.cmdline = (
        "powershell.exe -NoP -NonI -W Hidden -Exec Bypass "
        "-Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQ"
    )
    ps.malfind_hits.append({
        "address": "0x1f4a0000", "size": 131072,
        "protection": "PAGE_EXECUTE_READ",
        "has_pe": False,
        "notes": "Private committed, not backed by file",
    })
    ps.network.append({"proto": "TCPv4",
        "local": "10.0.0.15:50001",
        "foreign": "203.0.113.9:80", "state": "ESTABLISHED"})

    # ---- FINDING 3: DLL loaded from TEMP (DLL side-load / hijack) ----
    word = add(4456, "WINWORD.EXE", 980, "explorer.exe")
    word.cmdline = r'WINWORD.EXE "C:\Users\victim\Desktop\invoice.doc"'
    word.dll_paths = [
        r"C:\Windows\system32\ntdll.dll",
        r"C:\Windows\system32\kernel32.dll",
        r"C:\Users\victim\AppData\Local\Temp\version.dll",   # suspicious
        r"C:\Users\victim\AppData\Roaming\update\mso.dll",   # suspicious
    ]
    word.malfind_hits.append({
        "address": "0x2b000000", "size": 40960,
        "protection": "PAGE_EXECUTE_READWRITE",
        "has_pe": True,
        "notes": "MZ header, mapped from C:\\Users\\victim\\AppData\\Local\\Temp\\version.dll",
    })

    # ---- FINDING 4: Hidden module in notepad (classic shellcode injection) ----
    np = procs[1800]
    np.hidden_modules.append({
        "base": "0x77800000",
        "path": r"C:\Windows\Temp\inject.dll",
        "missing_from": ["LoadOrder list", "InitOrder list"],
    })
    np.network.append({"proto": "TCPv4",
        "local": "10.0.0.15:51234",
        "foreign": "192.0.2.99:4444", "state": "ESTABLISHED"})

    # ---- FINDING 5: Suspicious second lsass (masquerader) ----
    fake_lsass = add(5500, "lsass.exe", 980, "explorer.exe")
    fake_lsass.cmdline = r"C:\Users\Public\lsass.exe"
    fake_lsass.dll_paths = [r"C:\Users\Public\msvcrt.dll"]
    fake_lsass.network.append({"proto": "TCPv4",
        "local": "10.0.0.15:52000",
        "foreign": "10.0.5.99:6666", "state": "ESTABLISHED"})

    return procs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Memory forensics triage: find in-memory injection using Volatility 3.")
    ap.add_argument("dump", nargs="?", help="memory dump file (.raw/.dmp/.vmem/etc.)")
    ap.add_argument("--vol", default="vol",
                    help="path to Volatility 3 binary (default: 'vol' on PATH)")
    ap.add_argument("--report", help="write text report to this file")
    ap.add_argument("--json",   dest="json_out", help="write findings as JSON")
    ap.add_argument("--redact-cmdline", action="store_true",
                    help="replace command-line values in printed, text, and JSON reports")
    ap.add_argument("--demo",   action="store_true",
                    help="run with synthetic data (no dump needed, shows report format)")
    args = ap.parse_args()

    if args.demo:
        print("\n[DEMO MODE — synthetic data, no real dump required]\n")
        procs = demo_procs()
        errors = []
        coverage = {}
        dump_path = "<demo>"
    else:
        if not args.dump:
            ap.error("provide a dump file, or use --demo to see the report format")
        if not Path(args.dump).is_file():
            sys.exit(f"File not found: {args.dump}")
        dump_path = args.dump
        print(f"[*] Running Volatility 3 plugins against {dump_path} ...")
        print("[*] This may take several minutes on a large dump.\n")
        procs, errors, coverage = collect(args.vol, dump_path)
        if not procs:
            print("[!] No process data returned. Errors:")
            for p, e in errors:
                print(f"    {p}: {e}")
            print("\nCheck that:")
            print("  - Volatility 3 is installed and on PATH (or use --vol /path/to/vol.py)")
            print("  - Your dump file is a supported format")
            print("  - Symbol packs are downloaded (~/.cache/volatility3/)")
            sys.exit(1)

    print(f"[*] Scoring {len(procs)} processes ...")
    score_all(procs)

    report = build_report(procs, errors, dump_path, coverage, args.redact_cmdline)
    print(report)

    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        print(f"[*] Report written to {args.report}")

    if args.json_out:
        out = []
        for pr in sorted(procs.values(), key=lambda p: -p.score):
            if not pr.indicators:
                continue
            out.append({
                "pid": pr.pid, "name": pr.name,
                "ppid": pr.ppid, "parent": pr.parent_name,
                "offset": pr.offset, "create_time": pr.create_time,
                "exit_time": pr.exit_time,
                "executable_path_candidate": pr.exe_path_candidate,
                "cmdline": "[REDACTED]" if args.redact_cmdline and pr.cmdline else pr.cmdline,
                "score": pr.score,
                "max_severity": pr.max_severity(),
                "indicators": pr.indicators,
                "malfind_hits": pr.malfind_hits,
                "hidden_modules": pr.hidden_modules,
                "network": pr.network,
                "scan_only": pr.scan_only,
            })
        Path(args.json_out).write_text(json.dumps({"dump": dump_path,
            "plugin_errors": [{"plugin": p, "error": e} for p, e in errors],
            "incomplete": bool(errors), "plugin_coverage": coverage,
            "cmdline_redacted": args.redact_cmdline,
            "findings": out}, indent=2), encoding="utf-8")
        print(f"[*] JSON written to {args.json_out}")


if __name__ == "__main__":
    main()
