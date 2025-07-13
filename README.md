# EternalBlue Exploitation Lab (MS17-010)

![Security Lab](docs/images/lab_diagram.png) *(Optional diagram if you have one)*

A controlled lab environment demonstrating the exploitation of Windows 7 via the EternalBlue vulnerability (MS17-010).

## Lab Overview

- **Objective**: Demonstrate how unpatched Windows systems can be compromised via SMBv1 vulnerabilities
- **Attacker**: Kali Linux 2025.2
- **Target**: Windows 7 Professional SP1 x64 (unpatched)
- **Vulnerability**: MS17-010 (CVE-2017-0143)

## Methodology

1. Host Discovery (`nmap -sn`)
2. Service Enumeration (`nmap -sV`)
3. Vulnerability Scanning (`nmap --script vuln`)
4. Exploitation (Metasploit Framework)
5. Post-Exploitation (Meterpreter)

## Getting Started

### Prerequisites
- VMware/VirtualBox
- Kali Linux VM
- Windows 7 SP1 VM (unpatched)

### Lab Setup
See [configs/lab_setup.md](configs/lab_setup.md)

### Running the Lab
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Run discovery
./scripts/discovery.sh 192.168.20.0/24

# Run exploitation (via Metasploit)
msfconsole -r scripts/exploit.rc
