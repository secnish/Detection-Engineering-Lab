# Cybersecurity Research & Detection Lab
### 👨‍💻 Developed by Manish

> **The Philosophy:** Moving beyond the "Search Bar" mindset. This repository documents my transition from finding "flags" in CTFs to engineering production-grade detection logic for enterprise environments.

---

## 🛡️ Project Overview
This repository serves as a tactical library for SIEM queries (Splunk/Wazuh) and investigation notes. Most of these logs are derived from **HackTheBox** defensive modules and my personal **Wazuh Home Lab** environments.

### 🎯 My Core Focus:
* **Behavioral Modeling:** Detecting TTPs (Tactics, Techniques, and Procedures) rather than static, easily-changed Indicators of Compromise (IOCs).
* **Data Normalization:** Using `spath`, `mvcount`, `eval`, and `rex` to transform messy, unstructured telemetry into actionable data.
* **Noise Reduction:** Implementing statistical thresholds and time-binning to separate attacker activity from daily system baselines.

---

## 📚 Investigation Series: "The SOC Analyst’s Ledger"
I document the analytical "story" and the research behind these queries on my Medium blog.

| Part | Investigation Topic | Core Logic Used | Status |
| :--- | :--- | :--- | :--- |
| **01** | [AD Enumeration (LDAP)](./01-AD-Enumeration) | `spath`, `stats dc(User)`, `samAccountType` | ✅ Completed |
| **02** | [Password Spraying](./02-Password-Spraying) | `bin span=15m`, `dc(user) > 5` | ✅ Completed |
| **03** | [MITM / Responder Poisoning](./03-MITM-Poisoning) | `split()`, `mvcount()`, Sysmon EID 22 | ✅ Completed |
| **04** | Detecting Kerberoasting/AS-REProasting | *Coming Soon* | ⏳ In Progress |

---

## 🛠️ Lab Environment & Tools
* **SIEM:** Splunk Enterprise / Wazuh (FIM & SIEM)
* **Endpoints:** Windows Server 2022 (Domain Controller), Simulated Corporate Hosts (Target), Industry Grade Attacker Machines (Attacker)
* **Telemetry:** Sysmon (Modular), Windows Event Logs (Security/System), SilkService (LDAP Logging)
* **Frameworks:** MITRE ATT&CK Mapping

---

## 🚀 Featured Detection: Automated LDAP Recon - Example
In a production environment, simply searching for a string isn't enough. This query identifies automated enumeration by tracking the frequency of LDAP User-Object queries.

```splunk
index=main source="WinEventLog:SilkService-Log"
| spath input=Message 
| rename XmlEventData.* as * | search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as StartTime, max(_time) as EndTime, count by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(StartTime), ctime(EndTime)
```

---

## 🤝 Connect with the Researcher
If you are interested in detection engineering, SIEM optimization, or SOC operations, let’s connect!

* 📝 **Medium:** [Read my Investigations](secnish.medium.com)
* 💼 **LinkedIn:** [Connect on LinkedIn](https://www.linkedin.com/in/secnish/)
* 📧 **Email:** [My Professional Email](mailto:secops.manish@gmail.com)

**Current Goal:** I am actively preparing for **SOC Analyst** and **Detection Engineering** placements, focusing on high-fidelity alerting and incident response.

---

<p align="center">
  © 2026 Manish | 🛡️ Research-Oriented Cybersecurity Portfolio <br>
  <i>"Turning raw logs into actionable intelligence."</i>
</p>
