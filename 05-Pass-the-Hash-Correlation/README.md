# Module 05: Detecting Pass-the-Hash (PtH) via Correlation

## 📌 Investigation Overview
Pass-the-Hash (T1550.002) is a lateral movement technique where an attacker steals an NTLM hash from a system's memory and uses it to authenticate as that user elsewhere, bypassing the need for a plaintext password.

In this module, we move beyond simple event hunting. We are engineering a **Correlation Search** that links a "Process Access" event with a "Suspicious Logon" event to identify the exact moment a hash is leveraged.

---

## 🔍 The Logic Bridge
A successful Pass-the-Hash attack typically leaves two distinct fingerprints in a very short time window:

1. **The Reach (Sysmon Event 10):** An unauthorized process (like Mimikatz or a malicious script) accesses the memory space of `lsass.exe`.
2. **The Logon (Windows Event 4624):** A specific logon type—**Type 9 (NewCredentials)**—is triggered. This is the tell-tale sign of tools like `sekurlsa::pth` in Mimikatz or Impacket's `psexec`.

---

## 🛠️ The Correlation Query (Transaction Method)
This query builds a "Transaction" that groups these two events by host, provided they occur within 60 seconds of each other.

```splunk
index=main 
    (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe") 
    OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m startswith=(EventCode=10) endswith=(EventCode=4624)
| stats count by _time, Computer, SourceImage, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

## 💎 Why This Logic is Elite

To catch a sophisticated attacker, your query must be both **fast** and **precise**. Here is why this specific correlation works:

* **`maxspan=1m`**: Attackers move at the speed of scripts. By limiting the transaction window to 60 seconds, we eliminate the "noise" of normal system behavior and focus only on rapid, sequential events.
* **`Logon_Type=9`**: This is the **NewCredentials** type. It is a massive red flag in a SOC environment because it is the default behavior for tools that "pass" hashes over the network (like `runas /netonly`).

---

## 🔬 The Researcher’s Insight: Filtering the Noise

As I built this detection, I realized that **Windows Defender (`MsMpEng.exe`)** touches `lsass.exe` constantly during routine scans. If you don't filter that out, your SIEM will scream at you 24/7 with false positives.

> **The Secret:** High-fidelity detection isn’t just about knowing what is **bad**; it’s about knowing what is **normal** and excluding it. 

By adding `SourceImage!="*MsMpEng.exe"` to our query, we transform a noisy, useless alert into a precise, high-severity investigation. It really is that easy when you understand the baseline.



---

## 🎯 Final Verdict: Behavior > Tools

Pass-the-Hash is a technique that has existed for decades, yet it still catches organizations off guard. Why? **Because most defenders are looking for "tools."**

As we’ve seen in this series, the specific tool (whether it’s Mimikatz, Impacket, or a custom script) doesn’t matter. The **behavior** remains identical:
1. An unauthorized process accesses sensitive memory (`lsass.exe`).
2. A suspicious network logon follows immediately.

When you stop hunting for filenames and start thinking in **Transactions**, the attacker has nowhere left to hide.

