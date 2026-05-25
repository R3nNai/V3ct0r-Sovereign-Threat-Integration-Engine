**PSA** THIS TOOL WAS CREATED FOR EDUCATIONAL PURPOSES ONLY! I AM NOT RESPONSIBLE FOR HOW THIS TOOL IS USED OR CHANGED IN ANY WAY. 
With that said please enjoy and be safe out there. 


# Sovereign Threat Integration Engine (SOAR Pipeline)

An autonomous, lightweight Security Orchestration, Automation, and Response (SOAR) pipeline built in Python. This tool bridges the gap between passive vulnerability scanning and active infrastructure defense.

## How It Works
1. **Asset Discovery:** Probes the host package manager (`dpkg`) to dynamically identify active software versions and map them to standard CPE strings.
2. **Threat Intelligence:** Queries the live production NIST National Vulnerability Database (NVD) API v2 to identify real-time vulnerabilities.
3. **Triage & Response:** Filters for High/Critical vectors ($\ge 7.0$ CVSS) and automatically routes the threat to targeted mitigation playbooks based on root-cause analysis.

## Technical Stack
- **OS Platform:** Parrot Security OS (Haven't gotten around to trying this on any other OS) 
- **Language:** Python 3
- **Libraries:** HTTPX (Asynchronous network requests), Pydantic (Data validation orchestration)
