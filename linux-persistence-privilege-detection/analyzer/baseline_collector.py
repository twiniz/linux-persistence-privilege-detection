import json
import subprocess
from datetime import datetime

baseline = {
    "generated_at": datetime.now().isoformat(),
    "users": [],
    "uid_0_accounts": [],
    "sudoers": [],
    "cron_jobs": [],
    "suid_files": []
}

# Collect users
with open("/etc/passwd", "r") as f:
    for line in f:
        parts = line.strip().split(":")
        user = {
            "username": parts[0],
            "uid": int(parts[2]),
            "shell": parts[-1]
        }
        baseline["users"].append(user)
        if user["uid"] == 0:
            baseline["uid_0_accounts"].append(user["username"])

# Collect sudoers
try:
    sudoers = subprocess.check_output(
        ["bash", "-c", "grep -v '^#' /etc/sudoers 2>/dev/null"],
        text=True
    )
    baseline["sudoers"] = sudoers.splitlines()
except Exception:
    baseline["sudoers"] = []

# Collect cron jobs
cron_paths = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]

for path in cron_paths:
    try:
        files = subprocess.check_output(["ls", path], text=True)
        for f in files.splitlines():
            baseline["cron_jobs"].append(f"{path}/{f}")
    except Exception:
        continue

# Safer SUID scan (limited paths)
suid_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
suid_files = []

for d in suid_dirs:
    try:
        output = subprocess.check_output(
            ["find", d, "-perm", "-4000", "-type", "f"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15
        )
        suid_files.extend(output.splitlines())
    except subprocess.TimeoutExpired:
        continue

baseline["suid_files"] = sorted(suid_files)

# Save baseline
with open("baseline/baseline_state.json", "w") as f:
    json.dump(baseline, f, indent=4)

print("[+] Baseline collected and saved to baseline/baseline_state.json")
