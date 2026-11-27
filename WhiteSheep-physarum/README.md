# BlackSheep-physarum

A small CLI for auditing **your own** networks: find live hosts, then let nmap look at each one and flag open ports that are commonly insecure.

Single file, Python 3.9+, no pip packages needed.

## Requirements
- Python 3.9 or newer
- [nmap](https://nmap.org/download.html) for the `analyse` and `scan` commands (on Windows the installer's default path is found automatically)

## Commands

### 1. `sweep` — find live hosts (Angry IP Scanner style)
Pings every address and also tries a few common TCP ports, so hosts that block ping are still found. Shows hostname, ping time and which probe ports answered.

```
python physarum.py sweep 192.168.1.0/24
python physarum.py sweep 192.168.1.1-254 -o hosts.json
python physarum.py sweep 10.0.0.5,10.0.0.20-40 --no-ping -t 0.5
```

Range formats: CIDR (`192.168.1.0/24`), short range (`192.168.1.10-50`), full range (`192.168.1.10-192.168.1.50`), a single IP, or a comma separated mix.

### 2. `analyse` — soft nmap analysis of each host
Runs nmap on each host and rates every open port as HIGH / MEDIUM / LOW / INFO (Telnet, FTP, SMB, RDP, VNC, exposed databases, Redis, Docker API and so on).

```
python physarum.py analyse -i hosts.json -r report.json
python physarum.py analyse 192.168.1.1 192.168.1.20
python physarum.py analyse 192.168.1.1 --profile deep
```

Profiles:
| profile | what nmap does |
|---|---|
| `soft` (default) | top 1000 TCP ports, light service/version detection, polite timing |
| `quick` | top 100 TCP ports, no version detection |
| `deep` | all 65535 TCP ports, version detection and default safe scripts (slow) |

Extra nmap flags: `--nmap-args="-Pn"` (use the `=` form).

### 3. `scan` — both in one go
```
python physarum.py scan 192.168.1.0/24 -o hosts.json -r report.json
```

## Output
Everything prints as a table; `-o` / `-r` also save JSON you can keep or diff between runs.

## Notes
- Only scan networks you own or have permission to test.
- Some nmap features (OS detection, SYN scan) need an Administrator/root terminal. The default profiles work without it.
