# EternalBlue Exploitation Lab (MS17-010)

A controlled lab environment demonstrating Windows 7 exploitation via EternalBlue vulnerability.

## Lab Overview
- **Attacker**: Kali Linux
- **Target**: Windows 7 SP1 x64 (unpatched)
- **Vulnerability**: MS17-010 (CVE-2017-0143)

## Methodology
1. Host Discovery: `nmap -sn 192.168.20.0/24`
2. Service Enumeration: `nmap -sV 192.168.20.130`
3. Vulnerability Scanning: `nmap --script vuln 192.168.20.130`
4. Exploitation: Metasploit Framework
5. Post-Exploitation: Meterpreter

## Documentation
- Full report: [docs/Report.md](docs/Report.md)
- Lab setup: [configs/lab_setup.md](configs/lab_setup.md)

## Disclaimer
⚠️ For educational purposes only. Use only in authorized environments.