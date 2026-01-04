#!/usr/bin/env python3
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
BASELINE_PATH = BASE_DIR / "baseline" / "baseline_state.json"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


def run_cmd(cmd, timeout=10):
    """Run a command safely and return stdout (string)."""
    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout
        )
        return out.strip()
    except Exception:
        return ""


def read_file(path, max_bytes=200_000):
    """Read a file safely (avoid huge files)."""
    try:
        p = Path(path)
        if not p.exists():
            return ""
        data = p.read_text(errors="ignore")
        return data[:max_bytes]
    except Exception:
        return ""


def list_files_recursive(path, max_files=5000):
    """List files under a directory (bounded)."""
    results = []
    try:
        p = Path(path)
        if not p.exists():
            return results
        for i, f in enumerate(p.rglob("*")):
            if i >= max_files:
                break
            if f.is_file():
                results.append(str(f))
    except Exception:
        pass
    return sorted(results)


def collect_users():
    passwd = read_file("/etc/passwd")
    users = []
    uid0_users = []
    for line in passwd.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        name = parts[0]
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        users.append({"user": name, "uid": uid})
        if uid == 0:
            uid0_users.append(name)
    return {"users": users, "uid0_users": sorted(uid0_users)}


def collect_sudoers():
    sudoers_main = read_file("/etc/sudoers")
    sudoers_d_files = list_files_recursive("/etc/sudoers.d", max_files=500)
    sudoers_d_contents = {}
    for f in sudoers_d_files:
        sudoers_d_contents[f] = read_file(f, max_bytes=50_000)

    return {
        "sudoers_main_present": bool(sudoers_main),
        "sudoers_d_files": sudoers_d_files,
        "sudoers_d_preview": {k: v[:300] for k, v in sudoers_d_contents.items()}
    }


def collect_cron():
    cron = {
        "etc_crontab": read_file("/etc/crontab"),
        "cron_dirs": {
            "/etc/cron.d": list_files_recursive("/etc/cron.d", max_files=500),
            "/etc/cron.daily": list_files_recursive("/etc/cron.daily", max_files=500),
            "/etc/cron.hourly": list_files_recursive("/etc/cron.hourly", max_files=500),
            "/etc/cron.weekly": list_files_recursive("/etc/cron.weekly", max_files=500),
            "/etc/cron.monthly": list_files_recursive("/etc/cron.monthly", max_files=500),
        },
        # user crontab (root + current user)
        "root_crontab": run_cmd(["bash", "-lc", "sudo crontab -l 2>/dev/null"], timeout=5),
        "user_crontab": run_cmd(["bash", "-lc", "crontab -l 2>/dev/null"], timeout=5),
    }
    return cron


def collect_systemd():
    # List enabled services (persistence often hides here)
    enabled = run_cmd(
        ["bash", "-lc", "systemctl list-unit-files --type=service --state=enabled --no-pager"],
        timeout=10
    )
    # Unit files on disk (some attackers drop files here)
    system_dirs = {
        "/etc/systemd/system": list_files_recursive("/etc/systemd/system", max_files=2000),
        "/lib/systemd/system": list_files_recursive("/lib/systemd/system", max_files=4000),
    }
    return {"enabled_services": enabled, "system_dirs": system_dirs}


def collect_ssh_keys():
    # Authorized keys for common users (you can expand later)
    paths = [
        "/root/.ssh/authorized_keys",
        str(Path.home() / ".ssh/authorized_keys"),
    ]
    keys = {p: read_file(p, max_bytes=50_000) for p in paths}
    return {"authorized_keys": keys}


def collect_suid_limited():
    # Safer + faster than scanning entire /
    suid_files = []
    suid_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
    try:
        for d in suid_dirs:
            out = run_cmd(["find", d, "-perm", "-4000", "-type", "f"], timeout=15)
            if out:
                suid_files.extend(out.splitlines())
    except Exception:
        pass
    return {"suid_files": sorted(set(suid_files))}


def collect_current_state():
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        **collect_users(),
        **collect_sudoers(),
        **collect_cron(),
        **collect_systemd(),
        **collect_ssh_keys(),
        **collect_suid_limited(),
    }


def diff_lists(old_list, new_list):
    old_set = set(old_list or [])
    new_set = set(new_list or [])
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    return added, removed


def load_baseline():
    if not BASELINE_PATH.exists():
        print(f"[ERROR] Baseline not found: {BASELINE_PATH}")
        print("Run: sudo python3 analyzer/baseline_collector.py first")
        raise SystemExit(1)

    with open(BASELINE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    baseline = load_baseline()
    current = collect_current_state()

    alerts = []

    # 1) UID 0 users (very high-signal)
    baseline_uid0 = baseline.get("uid0_users", [])
    current_uid0 = current.get("uid0_users", [])
    added_uid0, _ = diff_lists(baseline_uid0, current_uid0)
    if added_uid0:
        alerts.append(f"[ALERT] New UID=0 user(s) detected: {added_uid0}")

    # 2) SUID files changed
    added_suid, removed_suid = diff_lists(baseline.get("suid_files", []), current.get("suid_files", []))
    if added_suid:
        alerts.append(f"[ALERT] New SUID binaries found: {added_suid[:10]}{' ...' if len(added_suid) > 10 else ''}")
    if removed_suid:
        alerts.append(f"[INFO] SUID binaries removed: {removed_suid[:10]}{' ...' if len(removed_suid) > 10 else ''}")

    # 3) New sudoers.d files
    added_sudoers_d, removed_sudoers_d = diff_lists(
        baseline.get("sudoers_d_files", []),
        current.get("sudoers_d_files", [])
    )
    if added_sudoers_d:
        alerts.append(f"[ALERT] New /etc/sudoers.d file(s): {added_sudoers_d}")
    if removed_sudoers_d:
        alerts.append(f"[INFO] Removed /etc/sudoers.d file(s): {removed_sudoers_d}")

    # 4) Enabled services changed (persistence)
    # We'll compare raw text lines for simplicity
    base_enabled = set((baseline.get("enabled_services", "")).splitlines())
    curr_enabled = set((current.get("enabled_services", "")).splitlines())
    added_services = sorted(curr_enabled - base_enabled)
    removed_services = sorted(base_enabled - curr_enabled)
    if added_services:
        alerts.append(f"[ALERT] New enabled service entries detected (possible persistence): {added_services[:10]}{' ...' if len(added_services) > 10 else ''}")
    if removed_services:
        alerts.append(f"[INFO] Enabled service entries removed: {removed_services[:10]}{' ...' if len(removed_services) > 10 else ''}")

    # 5) Cron directory changes (common persistence)
    for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]:
        base = baseline.get("cron_dirs", {}).get(cron_dir, [])
        curr = current.get("cron_dirs", {}).get(cron_dir, [])
        added, removed = diff_lists(base, curr)
        if added:
            alerts.append(f"[ALERT] New cron file(s) in {cron_dir}: {added}")
        if removed:
            alerts.append(f"[INFO] Removed cron file(s) in {cron_dir}: {removed}")

    # Report paths
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    txt_report = REPORTS_DIR / f"detection_report_{ts}.txt"
    json_report = REPORTS_DIR / f"detection_report_{ts}.json"

    # Write JSON report
    report_obj = {
        "generated_at": current["generated_at"],
        "alerts": alerts,
        "diff": {
            "uid0_added": added_uid0,
            "suid_added": added_suid,
            "suid_removed": removed_suid,
            "sudoers_d_added": added_sudoers_d,
            "sudoers_d_removed": removed_sudoers_d,
            "enabled_services_added": added_services,
            "enabled_services_removed": removed_services,
        }
    }
    with open(json_report, "w", encoding="utf-8") as f:
        json.dump(report_obj, f, indent=2)

    # Write text report
    lines = []
    lines.append("Linux Persistence & Privilege Escalation Detection Report")
    lines.append("=" * 58)
    lines.append(f"Generated: {current['generated_at']}")
    lines.append("")
    if alerts:
        lines.append("Alerts:")
        for a in alerts:
            lines.append(a)
    else:
        lines.append("Alerts:")
        lines.append("[OK] No suspicious changes detected compared to baseline.")
    lines.append("")
    lines.append("Report files:")
    lines.append(f"- {txt_report}")
    lines.append(f"- {json_report}")

    txt_report.write_text("\n".join(lines), encoding="utf-8")

    print("\n".join(lines))


if __name__ == "__main__":
    main()
