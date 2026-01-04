# 🔐 Linux Persistence & Privilege Escalation Detection

A defensive cybersecurity project that detects **persistence mechanisms** and **privilege escalation indicators** on Linux systems by comparing the current system state against a trusted baseline.

This project simulates how **SOC analysts** and **blue team engineers** identify stealthy attacker footholds after initial compromise.

---

## 🎯 What This Project Detects

- 👤 **Privilege Escalation**
  - New UID 0 (root-level) users
  - Unauthorized sudoers configuration changes

- 🔁 **Persistence Mechanisms**
  - New or modified cron jobs
  - Newly enabled systemd services
  - SUID binary changes
  - SSH authorized key modifications

---

## 🧠 How It Works

1. **Baseline Collection**
   - Collects a clean snapshot of:
     - Users & UID 0 accounts
     - SUID binaries
     - sudoers & sudoers.d
     - Cron jobs
     - Enabled systemd services
     - SSH authorized keys
   - Saved as `baseline/baseline_state.json`

2. **Detection Phase**
   - Re-collects the same system artifacts
   - Compares them against the baseline
   - Flags deviations as **alerts** or **informational changes**

3. **Reporting**
   - Generates:
     - Human-readable SOC report (`.txt`)
     - Structured JSON report (`.json`)

---

## 📂 Project Structure

linux-persistence-privilege-detection/
├── analyzer/
│   ├── baseline_collector.py
│   └── detector.py
├── baseline/
│   └── baseline_state.json
├── reports/
│   ├── detection_report_YYYYMMDD_HHMMSS.txt
│   └── detection_report_YYYYMMDD_HHMMSS.json
├── logs/
├── screenshots/
└── README.md

---

## ▶️ Usage

### 1️⃣ Collect Baseline (Run Once on Clean System)
```bash
sudo python3 analyzer/baseline_collector.py

