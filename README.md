# Minescan IP Blocker

A Python script that automatically fetches known Minecraft scanner IPs and blocks them from connecting to your server port.

## Quick Start

Run the script with **Administrator** or **root** privileges:

* **Linux / macOS:**
```bash
wget -O mc-firewall.py https://raw.githubusercontent.com/aleksireede/mc-firewall/refs/heads/main/main.py
chmod +x mc-firewall.py
sudo python3 main.py

```

* **Windows (Administrator PowerShell):**
```powershell
python main.py

```

By default, it downloads the Minescan blocklist and blocks inbound connections on port **25565**.

---

## Minescan API

The Minescan API endpoint is rate-limited to **5 requests per minute** and **60 requests per hour**. If you're using a custom script or frequently refreshing the blocklist, make sure your requests stay within these limits.

For updates, support, and discussion, join the **Minescan Discord server:**
https://discord.gg/AYbDNEWgHE

---

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `--port <number>` | Change the TCP port to block.| `25565`<br> |
| `--url <url>` | Use a different IP blocklist feed.| Minescan export feed|
| `--dry-run` | Test fetching IPs without changing firewall settings.| *Off* |


**Examples:**
```bash
# Block port 25566 instead
sudo python3 main.py --port 25566
# Test the script without applying firewall rules
python3 main.py --dry-run
```

---

## Requirements & Compatibility

**Python:** 3.7+ (no external `pip` packages needed).


**Supported OS:**
* **Linux:** Automatically uses `nftables`, `ipset` + `iptables`, `firewalld`, or `ufw`.
* **macOS:** Uses `pf` (Packet Filter).
* **Windows:** Uses Windows Defender Firewall.
