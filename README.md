# Linux Persistence & Privilege Escalation Detection

A defensive Linux security tool that detects persistence mechanisms and privilege escalation indicators by comparing the current system state against a trusted baseline.

This project simulates how SOC and Blue Team analysts identify post-compromise activity that survives reboots and privilege boundaries.

---

## 🔍 What This Project Detects

- Persistence via **cron jobs** (daily, hourly, weekly, monthly)
- Suspicious or newly enabled **systemd services**
- Changes to **sudoers configuration**
- New or modified **SUID binaries**
- Privilege escalation indicators
- New UID 0 (root-equivalent) users

---

## 🧠 How It Works

1. **Baseline Collection**
   - Captures a trusted snapshot of the system state
   - Stores baseline data in JSON format

2. **Detection Phase**
   - Compares current system state against the baseline
   - Flags new, modified, or suspicious entries

3. **Reporting**
   - Generates both **human-readable (.txt)** and **machine-readable (.json)** reports
   - Designed to support incident response workflows

---

## 🛠️ Tools & Techniques Used

- Python (subprocess, os, json)
- Linux internals (cron, systemd, sudoers, SUID)
- Privilege escalation detection concepts
- Baseline vs drift analysis
- Defensive security mindset

---

## 🚀 How a SOC Analyst Would Use This

1. Capture a baseline on a clean system  
2. Schedule periodic detection scans  
3. Investigate alerts for persistence or privilege escalation  
4. Use reports during incident response or forensic analysis  
