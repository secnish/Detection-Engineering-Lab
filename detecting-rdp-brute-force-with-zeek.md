Detecting RDP Brute Force with Zeek Logs

## 📌 Investigation Overview
https://chatgpt.com/backend-api/estuary/content?id=file_00000000358071fa883028b9af377e10&ts=491581&p=fs&cid=1&sig=5f4231e3ce00a9ee909103ab5bb5d75bfa8a37840676fbad828e0b270be9df93&v=0
After diving deep into the complexities of Windows Event Logs, we are shifting our perspective to the network layer. While host logs tell us what a machine *claims* happened, network logs (**Zeek/Bro**) show us what *actually* crossed the wire.

In this module, we identify **RDP Brute Force attacks**. RDP (Remote Desktop Protocol) is a high-value target for attackers looking for initial access. Because brute-forcing creates a high volume of network "noise," Zeek is the perfect tool to capture this behavior in real-time.

---

## 🔍 The Logic: Volume and Velocity
Legitimate RDP connections typically involve a single successful handshake. An attack, however, is characterized by a high frequency of connection attempts from a single source to a single destination within a short timeframe.

### Key Zeek Fields:
* `id.orig_h`: The source (attacker) IP address.
* `id.resp_h`: The destination (target) IP address.
* `cookie`: A field in the RDP handshake that often reveals the username being targeted.

---

## 🛠️ The Zeek RDP Hunt Query
This query uses time-binning to identify IP pairs that exceed a threshold of 30 connection attempts within a 5-minute window.

```splunk
index="main" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) as targeted_usernames by _time, id.orig_h, id.resp_h
| where count > 30
```
