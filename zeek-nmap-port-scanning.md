# Detecting NMAP port scanning with Zeek

## 📌 Investigation Overview
Moving away from host-based logs, we are now utilizing **Zeek (formerly Bro)** connection logs to identify automated network scanning and brute-force patterns. While host logs can be cleared, the network "wire" doesn't lie.

In this module, we move beyond simple searching and into **Statistical Summarization**. We use time-binning and distinct counting to identify malicious velocity in network traffic.

---

## 🔍 The Logic: Binning and Distinct Counts
To catch an attacker, we need to organize data by **Time** and **Behavior**.

### The "Golden Combo":
1. **`bin _time` (The Organizer):** We group logs into 5-minute "buckets." This allows us to see the *velocity* of an attack rather than just individual, disconnected events.
2. **`stats dc()` (The Accountant):** We use **Distinct Count** to see how many *different* ports an attacker is hitting.

---

## 🛠️ The Discovery Query
This query is designed to find horizontal port scanning and heavy connection attempts.

```splunk
index="main" sourcetype="bro:conn:json"
| bin _time span=5m
| stats dc(id.resp_p) as unique_ports_count, 
        count as total_connections 
        by _time, id.orig_h, id.resp_h
| where unique_ports_count > 10 OR total_connections > 50
| rename id.orig_h AS src_ip, id.resp_h AS dest_ip
```
