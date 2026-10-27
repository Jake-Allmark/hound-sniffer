# 🐕 Hound Sniffer

Terminal-based SOC threat intelligence platform.

## Features
- IP and domain investigations
- URL and file-hash investigations
- VirusTotal, AbuseIPDB, ProxyCheck
- URLhaus, ThreatFox and MalwareBazaar
- Local AI with Ollama
- Bulk investigations and JSON export

## Usage
```bash
hound sniff 8.8.8.8
hound sniff google.com --ai
hound batch targets.txt
```

## Status
Alpha — tested on Ubuntu Linux.
Windows and macOS support is planned.
Threat scores are experimental.
