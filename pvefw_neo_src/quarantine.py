"""
Quarantine layer: isolate individual source rules whose compiled output
is rejected by nftables or ovs-ofctl. Purely in-memory state during one
apply cycle. Persistent effects are:

  - the offending rule's `.fw` line gets a leading `|` (PVE disable marker)
  - `/var/log/pve-firewall.log` gets a `[pvefw-neo] QUARANTINE ...` entry

Next apply just sees an enable=0 rule and skips it naturally; no sidecar
state file. User's path to recovery is: see the unchecked checkbox →
read Log tab → fix the rule → re-check → apply tries again.
"""

import copy
import os
import re
import subprocess
import sys
import time

from . import ir


FW_LOG_PATH = "/var/log/pve-firewall.log"
_seq_counter = 10_000  # simple process-global monotonic; not persistent


# ═══════════════════════════════════════
# source_id <-> (vmid, line_num) helpers
# ═══════════════════════════════════════

_SRC_ID_RE = re.compile(r"vm(\d+)-line(\d+)")


def parse_source_id(source_id):
    """`vm100-line5` → (100, 5) or None if malformed."""
    if not source_id:
        return None
    m = _SRC_ID_RE.fullmatch(source_id)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


# ═══════════════════════════════════════
# Error parsers — nft & ovs-ofctl stderr → source_id
# ═══════════════════════════════════════

def parse_nft_error(stderr):
    """Find the offending rule's source_id in nft's stderr.

    nft prints the offending rule text in the error block; every managed
    rule carries a `comment "vm<N>-line<N>"` suffix, so a simple substring
    search is sufficient.

    Returns source_id (str) or None if not recoverable.
    """
    if not stderr:
        return None
    m = _SRC_ID_RE.search(stderr)
    if m:
        return m.group(0)
    return None


def parse_ovs_error(stderr, flows_text, cookie_map):
    """Find the offending flow's source_id from ovs-ofctl stderr.

    ovs-ofctl's failure report looks like:
        ovs-ofctl: /path/to/ovs-<br>.flows:<N>: <reason>
    preceded by optional `ofp_match|INFO` noise carrying ISO timestamps
    like `2026-04-18T15:11:31Z` — those colons+digits would trip up a
    naive `:(\\d+):` scan. We key off the literal `ovs-ofctl:` prefix
    (and the `.flows:` suffix on the file path) to pick the real line.

    Fallbacks if line resolution fails: scan stderr for any cookie hex
    literal, then for a bare source_id token.

    Returns source_id (str) or None.
    """
    if not stderr:
        return None

    # ── strategy 1: ovs-ofctl error prefix → flows_text line → cookie ──
    for raw in stderr.splitlines():
        line = raw.strip()
        if not line.startswith("ovs-ofctl:"):
            continue
        # Prefer `.flows:<N>:` since our flows files always end in .flows,
        # but accept a bare `<path>:<N>:` shape too.
        m = (re.search(r"\.flows:(\d+):", line)
             or re.match(r"ovs-ofctl:\s+\S+:(\d+):", line))
        if not m or not flows_text:
            continue
        line_num = int(m.group(1))
        ft_lines = flows_text.split("\n")
        if 0 < line_num <= len(ft_lines):
            bad_line = ft_lines[line_num - 1]
            cm = re.search(r"cookie=0x([0-9a-fA-F]+)", bad_line)
            if cm:
                cookie_int = int(cm.group(1), 16)
                src = cookie_map.get(cookie_int)
                if src:
                    return src

    # ── strategy 2: cookie= appears directly in stderr ──
    for cm in re.finditer(r"cookie=0x([0-9a-fA-F]+)", stderr):
        cookie_int = int(cm.group(1), 16)
        src = cookie_map.get(cookie_int)
        if src:
            return src

    # ── strategy 3: plain source_id token ──
    m = _SRC_ID_RE.search(stderr)
    if m:
        return m.group(0)

    return None


# ═══════════════════════════════════════
# IR filtering
# ═══════════════════════════════════════

def filter_ruleset(rs, quarantined):
    """Return a shallow-copied ir.Ruleset with rules whose source_id is in
    quarantined removed. NetDev objects are copied; rule lists are rebuilt.

    Sets and NetDev properties (isolated/disabled) are preserved as-is —
    quarantine applies to rules only, not to the framework. A quarantined
    sugar rule (e.g. @neo:isolated that somehow failed) would still mark
    NetDev.isolated; that's accepted for now since @neo:isolated doesn't
    produce IR rules so it can't be the cause of a backend rejection.
    """
    if not quarantined:
        return rs
    new_rs = ir.Ruleset(netdevs={}, sets=dict(rs.sets))
    for devname, nd in rs.netdevs.items():
        new_nd = copy.copy(nd)
        new_nd.rules = [r for r in nd.rules
                        if r.source_id not in quarantined]
        new_rs.netdevs[devname] = new_nd
    return new_rs


# ═══════════════════════════════════════
# .fw write-back (prepend `|` to the offending line)
# ═══════════════════════════════════════

def writeback_fw_disable(vmid, line_num):
    """Flip enable=1 → enable=0 on a specific .fw rule by prepending `|`.

    Best-effort digest CAS: re-read the file immediately before write and
    abort if it changed since first read (user or another process edited).
    In that case the next apply cycle will retry.

    Returns (ok, reason). reason is a short tag: "ok", "already-disabled",
    "no-file", "line-oob", "raced".
    """
    path = f"/etc/pve/firewall/{vmid}.fw"
    try:
        with open(path) as f:
            content = f.read()
    except FileNotFoundError:
        return False, "no-file"

    lines = content.split("\n")
    # line_num is 1-based (from parser.py:line_num counter).
    idx = line_num - 1
    if idx < 0 or idx >= len(lines):
        return False, "line-oob"

    target = lines[idx]
    if target.lstrip().startswith("|"):
        return True, "already-disabled"

    # Preserve leading whitespace: `|` goes at the first non-space char.
    stripped = target.lstrip()
    leading = target[:len(target) - len(stripped)]
    lines[idx] = leading + "|" + stripped
    new_content = "\n".join(lines)

    # CAS re-read
    try:
        with open(path) as f:
            recheck = f.read()
    except FileNotFoundError:
        return False, "no-file"
    if recheck != content:
        return False, "raced"

    try:
        with open(path, "w") as f:
            f.write(new_content)
    except OSError as e:
        return False, f"write-error:{e}"
    return True, "ok"


# ═══════════════════════════════════════
# Firewall log append
# ═══════════════════════════════════════

def _next_seq():
    global _seq_counter
    _seq_counter += 1
    return _seq_counter


def _pve_timestamp():
    """Emit timestamp in PVE's firewall log format: 17/Apr/2026:14:23:45 +0800."""
    return time.strftime("%d/%b/%Y:%H:%M:%S %z")


def _rule_pos_from_line(vmid, line_num):
    """Map a .fw absolute line number to its rule position in [RULES].

    PVE WebUI and its API both identify rules by a 0-based index within
    the [RULES] section (PVE API2::Firewall::Rules::get_rule: `pos`).
    Users see this number in the WebUI, so our log message should use the
    same "#<pos>" convention rather than a file line.

    All rule lines count, including disabled (leading `|`) ones — that
    mirrors how PVE indexes them.

    Returns int (pos) or None if the file or line isn't readable.
    """
    path = f"/etc/pve/firewall/{vmid}.fw"
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None
    pos = 0
    in_rules = False
    for i, raw in enumerate(lines, 1):
        if i == line_num:
            return pos if in_rules else None
        stripped = raw.strip()
        if stripped.startswith("["):
            in_rules = stripped.lower().startswith("[rules]")
            continue
        if not in_rules:
            continue
        if not stripped or stripped.startswith("#"):
            continue
        pos += 1
    return None


def _condense_reason(reason):
    """Squeeze multi-line nft/ovs stderr into one short line for the log.

    Priority order for picking the "real" error line:
      1. An `ovs-ofctl:` prefixed line (the tool's own error report).
      2. An `Error:`-containing line (nft convention).
      3. First non-empty, non-decorative line, skipping OVS INFO noise
         (`ofp_match|INFO|...` normalization notes that can precede the
         actual error).

    Caret/pointer-only lines (`^^^^`) are always skipped. Caps at 300 chars.
    """
    if not reason:
        return "(no detail)"
    lines = [ln.strip() for ln in reason.splitlines()]
    # Drop decorative / empty / INFO-log lines for fallback scanning.
    def _useful(ln):
        if not ln or set(ln) <= {"^", " "}:
            return False
        if "|INFO|" in ln or "|WARN|" in ln:
            return False
        return True

    # Strategy 1: ovs-ofctl-prefixed line.
    for ln in lines:
        if ln.startswith("ovs-ofctl:"):
            return _cap(ln)
    # Strategy 2: any line mentioning "Error:" (nft-style).
    for ln in lines:
        if _useful(ln) and "Error:" in ln:
            return _cap(ln)
    # Strategy 3: first useful line.
    for ln in lines:
        if _useful(ln):
            return _cap(ln)
    return "(no detail)"


def _cap(line, limit=300):
    return line if len(line) <= limit else line[:limit - 3] + "..."


def log_quarantine(vmid, source_id, reason):
    """Append one entry to /var/log/pve-firewall.log. Best-effort — never
    raises: firewall logging is operator UX, not correctness.

    Format must start with `<vmid> ` so VM → Firewall → Log filters pick
    it up (PVE API2/Firewall/VM.pm:229: `$line =~ m/^$vmid /`).

    words[3] + words[4] must be parseable by str2time for since/until
    filtering to work (Helpers.pm:91) — we emit the standard PVE format.

    Message body uses `#<pos>` so the user sees the same rule number the
    WebUI shows. Falls back to line number if pos can't be resolved.
    """
    seq = _next_seq()
    ts = _pve_timestamp()
    parsed = parse_source_id(source_id)
    if parsed:
        _, line_num = parsed
        pos = _rule_pos_from_line(vmid, line_num)
        ident = f"#{pos}" if pos is not None else f"at line {line_num}"
    else:
        ident = source_id or "(unknown)"
    reason_line = _condense_reason(reason)
    line = (f"{vmid} {seq} - {ts} [pvefw-neo] invalid rule {ident} "
            f"disabled, reason: {reason_line}\n")
    try:
        # O_APPEND + open-per-write avoids fighting logrotate.
        with open(FW_LOG_PATH, "a") as f:
            f.write(line)
    except OSError as e:
        print(f"pvefw-neo: failed to append firewall log: {e}",
              file=sys.stderr)


# ═══════════════════════════════════════
# Backend adapters (thin wrappers so the retry loop is backend-agnostic)
# ═══════════════════════════════════════

def _try_apply_nft(nft_text, ruleset_path):
    """Try `nft -f <path>` atomically. Returns (ok, stderr)."""
    os.makedirs(os.path.dirname(ruleset_path), exist_ok=True)
    with open(ruleset_path, "w") as f:
        f.write(nft_text)
    ret = subprocess.run(
        ["nft", "-f", ruleset_path],
        capture_output=True, text=True,
    )
    return ret.returncode == 0, ret.stderr


# ═══════════════════════════════════════
# The retry loop
# ═══════════════════════════════════════

def apply_with_quarantine(
    ir_rs,
    nft_renderer,     # callable(ir_rs) → (nft_text, isolated_devs)
    ruleset_path,     # where to write nft text
    ovs_bridges,      # iterable of (bridge_name, devnames)
    isolation_hook,   # callable(isolated_devs) — applies bridge isolation
    pre_nft_hook=None,  # callable() for cleanup (orphaned tables), optional
):
    """Atomic apply with progressive quarantine of bad rules.

    Algorithm:
      1. Filter IR excluding already-quarantined source_ids.
      2. Render + try nft. If it rejects, parse stderr → add bad id to
         quarantine → go to 1.
      3. For each OVS bridge: render + try apply. On reject, parse stderr
         (with cookie_map) → add bad id → go to 1.
      4. On full success, for each quarantined id: write `.fw` enable=0 +
         firewall-log entry.

    Natural termination: each iteration either succeeds or removes one
    source rule. Bounded by total number of source rules in the IR.

    Returns (ok, quarantined_reasons) where quarantined_reasons is a
    dict {source_id: error_text}. If ok is False, the error was
    unrecoverable (parser returned None or repeat-offender) and the
    caller should surface it without touching `.fw`.
    """
    quarantined = {}   # source_id → error text (for logging at the end)

    while True:
        filtered = filter_ruleset(ir_rs, set(quarantined))

        # ── nft pass ──
        nft_text, isolated_devs = nft_renderer(filtered)
        if pre_nft_hook:
            pre_nft_hook()
        ok, err = _try_apply_nft(nft_text, ruleset_path)
        if not ok:
            bad = parse_nft_error(err)
            if bad is None:
                print(f"nft apply failed, cannot identify rule:\n{err}",
                      file=sys.stderr)
                return False, quarantined
            if bad in quarantined:
                print(f"nft still reports {bad} after quarantine:\n{err}",
                      file=sys.stderr)
                return False, quarantined
            quarantined[bad] = err
            continue

        # ── OVS pass: try each bridge ──
        from . import ovsgen
        ovs_retry = False
        for br_name, devs in ovs_bridges:
            ok, err, flows_text, cookie_map = ovsgen.apply(
                filtered, br_name, devs,
            )
            if ok:
                continue
            bad = parse_ovs_error(err, flows_text, cookie_map)
            if bad is None:
                print(f"ovs-ofctl failed on {br_name}, cannot identify flow:\n{err}",
                      file=sys.stderr)
                return False, quarantined
            if bad in quarantined:
                print(f"ovs-ofctl still reports {bad} after quarantine:\n{err}",
                      file=sys.stderr)
                return False, quarantined
            quarantined[bad] = err
            ovs_retry = True
            break  # restart whole loop (re-render nft + retry OVS)

        if ovs_retry:
            continue

        # ── isolation (runs on final successful state) ──
        if isolation_hook:
            isolation_hook(isolated_devs)

        return True, quarantined


# ═══════════════════════════════════════
# Post-apply fallout: write back .fw + log
# ═══════════════════════════════════════

def materialize_quarantine(quarantined_reasons):
    """For each quarantined source_id, flip its .fw line to enable=0 and
    append a firewall-log entry.

    Best-effort: logs a note to stderr on per-rule failure but keeps going.
    Called only after apply_with_quarantine returned (True, ...).
    """
    for src_id, err in quarantined_reasons.items():
        parsed = parse_source_id(src_id)
        if not parsed:
            print(f"pvefw-neo: quarantined id {src_id!r} is malformed, "
                  f"skipping writeback", file=sys.stderr)
            continue
        vmid, line_num = parsed
        ok, reason = writeback_fw_disable(vmid, line_num)
        if not ok and reason != "already-disabled":
            print(f"pvefw-neo: writeback failed for {src_id}: {reason}",
                  file=sys.stderr)
        # Log either way — user still needs to see what broke.
        log_quarantine(vmid, src_id, err)
