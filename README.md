# Minescan IP Blocker

A Python script that fetches known Minecraft scanner IPs and blocks all inbound traffic from them, on every port and protocol. It can also merge in extra blocklists of your own.

## Quick Start

Run the script with **Administrator** or **root** privileges:

* **Linux / macOS:**
```bash
wget -O mc-firewall.py https://raw.githubusercontent.com/aleksireede/mc-firewall/refs/heads/main/main.py
chmod +x mc-firewall.py
sudo python3 mc-firewall.py

sudo sed -i 's/\r$//' /opt/mc-firewall.py # fix line endings
```

### Example crontab entry /etc/crontab
```bash
@reboot root /usr/bin/python3 /opt/mc-firewall.py
```

* **Windows (Administrator PowerShell):**
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/aleksireede/mc-firewall/refs/heads/main/main.py -OutFile mc-firewall.py
python mc-firewall.py
```

By default, it downloads the Minescan blocklist and blocks all inbound traffic from listed addresses, regardless of port or protocol.

The script is safe to re-run: each run replaces the existing block list instead of adding duplicate rules, so you can schedule it to keep the list fresh (see [Keeping it up to date](#keeping-it-up-to-date)).

---

## Minescan API

The Minescan API endpoint is rate-limited to **5 requests per minute** and **60 requests per hour**. If you're using a custom script or frequently refreshing the blocklist, make sure your requests stay within these limits.

For updates, support, and discussion, join the **Minescan Discord server:**
https://discord.gg/AYbDNEWgHE

---

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `--port <number>` | Legacy option used only with `--remove` to remove older Linux rules that blocked a single port. It does not limit new rules. | `25565` |
| `--url <url>` | Use a different primary blocklist feed. | Minescan export feed |
| `--secondary <url or file>` | Add an extra blocklist (URL or local file, one IP or CIDR per line). Merged with the primary list. Can be repeated. If it can't be loaded, it is skipped with a warning. | None |
| `--allow <cidr>` | Never block entries that overlap this IP or range, e.g. your own network. Can be repeated. | None |
| `--dry-run` | Download and parse the lists without changing firewall settings (no root needed). | *Off* |
| `--remove` | Remove the rules and block list installed by this script. | *Off* |

**Examples:**
```bash
# Blocklist rules always apply to every inbound port and protocol
sudo python3 mc-firewall.py

# Add a second blocklist (URL) and a local file of your own
sudo python3 mc-firewall.py --secondary https://example.com/list.txt --secondary my-ips.txt

# Different primary list
sudo python3 mc-firewall.py --url https://gitlab.com/-/snippets/6073805/raw/main/snippetfile1.txt

# Make sure your home network is never blocked
sudo python3 mc-firewall.py --allow 203.0.113.0/24

# Test the script without applying firewall rules
python3 mc-firewall.py --dry-run

# Remove everything the script installed
sudo python3 mc-firewall.py --remove
```

Blocklist files can contain single IPs or CIDR ranges (IPv4 and IPv6). Lines starting with `#` are treated as comments.

For older Linux installations that used a custom `--port`, run `--remove --port <old port>` to remove the previous port-specific rule.

---

## Safety Filters

All lists, primary and secondary, go through the same checks before anything is applied:

* Invalid lines are ignored.
* Private, loopback and other non-public addresses are skipped.
* Overly broad ranges (wider than /16 for IPv4 or /32 for IPv6) are skipped, so a broken feed can't block a large part of the internet.
* Entries overlapping an `--allow` range are skipped.
* Duplicate and overlapping entries are merged.

The primary list is required: if it can't be downloaded, the script stops and changes nothing.

---

## Keeping it up to date

On **Linux**, the rules do not survive a reboot. On **macOS** and **Windows**, the rules persist. To keep the blocklist current (and restored after reboots on Linux), run the script on a schedule, for example from root's crontab:

```cron
@reboot /usr/bin/python3 /opt/mc-firewall.py
0 4 * * * /usr/bin/python3 /opt/mc-firewall.py
```

A daily run stays well within the Minescan rate limits.

---

## Making your own list

Download the minescan list, add it to your list and sort(removes duplicated)

**Example includes my gitlab snippet list**
* **Linux/Macos**
```bash
wget -qO- 'https://data.minescan.xyz/scanners/export?format=ip&includeMinescan=true&limit=5000' > ips.txt
wget -qO- 'https://gitlab.com/-/snippets/6073805/raw/main/snippetfile1.txt' >> ips.txt

sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n ips.txt > ips_sorted.txt
```

* **Windows powershell**
```powershell
$a = (Invoke-WebRequest 'https://data.minescan.xyz/scanners/export?format=ip&includeMinescan=true&limit=5000').Content -split "`r?`n"
$b = (Invoke-WebRequest 'https://gitlab.com/-/snippets/6073805/raw/main/snippetfile1.txt').Content -split "`r?`n"
($a + $b) | ForEach-Object { $_.Trim() } |
  Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } |
  Sort-Object -Unique { [version]$_ } | Set-Content ips_all.txt

Get-Content ips_all.txt | Where-Object { $_.Trim() } | Sort-Object -Unique { [version]$_.Trim() } | Set-Content ips_sorted.txt
```

## Requirements & Compatibility

**Python:** 3.7+ (no external `pip` packages needed).

**Supported OS:**
* **Linux:** Uses `nftables`, or `ipset` + `iptables` if `nft` isn't installed. These work alongside `ufw` and `firewalld`.
* **macOS:** Uses `pf` (Packet Filter). `/etc/pf.conf` is backed up to `/etc/pf.conf.bak` before the first change.
* **Windows:** Uses Windows Defender Firewall.

**Docker:** On Linux the rules are applied before Docker's port forwarding, so containers with published ports are protected too.
