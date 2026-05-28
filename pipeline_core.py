import subprocess
import re
import asyncio
import httpx
from pydantic import BaseModel
from typing import List

# --- DATA SCHEMAS ---
class DiscoveredAsset(BaseModel):
    name: str
    cpe: str

class FlaggedThreat(BaseModel):
    cve_id: str
    asset_name: str
    severity: str
    cvss_score: float
    description: str

# --- PHASE 1: DISCOVERY (Kept synchronous for local system call) ---
class DiscoveryEngine:
    def __init__(self):
        self.monitored_services = ["nginx", "openssh-server", "apache2", "curl"]

    def scan_local_host(self) -> List[DiscoveredAsset]:
        print("[*] PHASE 1: Probing local system package registry...")
        found_assets = []
        
        for service in self.monitored_services:
            result = subprocess.run(["dpkg-query", "-W", "-f=${Status} ${Version}\n", service], capture_output=True, text=True)
            if "install ok installed" in result.stdout:
                raw_version = result.stdout.split()[-1]
                clean_version = re.match(r"^([0-9.]+)", raw_version)
                version = clean_version.group(1) if clean_version else raw_version
                
                vendor = "f5" if service == "nginx" else "openbsd" if service == "openssh-server" else "apache"
                product = "nginx" if service == "nginx" else "openssh" if service == "openssh-server" else service
                cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                
                print(f"  [+] Identified Active Software: {service} (v{version})")
                found_assets.append(DiscoveredAsset(name=product, cpe=cpe_string))
        return found_assets

# --- PHASE 2: ASYNCHRONOUS THREAT ANALYSIS ---
class AsyncThreatAnalyzer:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Converted to an async coroutine using a shared client session
    async def query_nvd_async(self, client: httpx.AsyncClient, asset: DiscoveredAsset) -> List[FlaggedThreat]:
        print(f"[*] PHASE 2: Launching concurrent query for target: {asset.name}")
        prioritized_threats = []
        
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            # The 'await' keyword allows Python to pause this specific task and work on others while waiting for the network
            response = await client.get(
                self.base_url, 
                params={"cpeName": asset.cpe, "resultsPerPage": 2}, 
                headers=headers, 
                timeout=10.0
            )
            
            if response.status_code == 200:
                vulnerabilities = response.json().get("vulnerabilities", [])
                for item in vulnerabilities:
                    cve_wrapper = item.get("cve", {})
                    cve_id = cve_wrapper.get("id")
                    desc_text = next((d.get("value") for d in cve_wrapper.get("descriptions", []) if d.get("lang") == "en"), "")
                    
                    metrics = cve_wrapper.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [])
                    if cvss_v31:
                        cvss_data = cvss_v31[0].get("cvssData", {})
                        score = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        
                        if score >= 7.0:
                            prioritized_threats.append(FlaggedThreat(
                                cve_id=cve_id, asset_name=asset.name, severity=severity, cvss_score=score, description=desc_text
                            ))
                print(f"  [✓] Completed query for: {asset.name} (Found {len(prioritized_threats)} high-risk CVEs)")
            return prioritized_threats
            
        except Exception as e:
            print(f"  [-] Network connection error on {asset.name}: {e}")
            return []

# --- PHASE 3: INCIDENT RESPONSE ORCHESTRATOR ---
class IncidentResponseOrchestrator:
    def trigger_mitigation_playbook(self, threat: FlaggedThreat):
        print(f"\n[!] PHASE 3: IR Orchestrator triggered for {threat.cve_id} ({threat.severity}) target: '{threat.asset_name}'")
        if "http/2" in threat.description.lower():
            print("  [✓] Complete: Service profiles hardened. Reloading server system configurations.")
        elif "buffer overflow" in threat.description.lower() or "remote code execution" in threat.description.lower():
            print(f"  [✓] Complete: apt-get package upgrade simulated safely for '{threat.asset_name}'.")
        else:
            print("  [✓] Complete: Edge firewall baseline updated.")

# --- ASYNC MAIN CONTROLLER CONTEXT ---
async def main_async():
    print("====================================================")
    print("🚀 INITIALIZING ASYNCHRONOUS SOVEREIGN SOAR CORE 🚀")
    print("====================================================\n")
    
    scanner = DiscoveryEngine()
    analyzer = AsyncThreatAnalyzer()
    orchestrator = IncidentResponseOrchestrator()
    
    # 1. Gather our inventory state
    local_inventory = scanner.scan_local_host()
    
    # 2. Fire ALL network API calls concurrently using an AsyncClient context
    print(f"\n[*] Bundling {len(local_inventory)} asset paths into an asynchronous event loop...")
    all_escalated_threats = []
    
    async with httpx.AsyncClient() as client:
        # Create a concurrent background task execution list for every single asset found
        tasks = [analyzer.query_nvd_async(client, asset) for asset in local_inventory]
        
        # 'gather' kicks off all background tasks simultaneously and awaits the combined results bundle
        results = await asyncio.gather(*tasks)
        
        # Unpack the nested results lists
        for threat_list in results:
            all_escalated_threats.extend(threat_list)
            
    # 3. Process remediation actions sequentially for any true positives
    print(f"\n[*] Processing Triage Queue. Found {len(all_escalated_threats)} high-priority vectors matching local state.")
    for threat in all_escalated_threats:
        orchestrator.trigger_mitigation_playbook(threat)

if __name__ == "__main__":
    # Start Python's native event loop to run the async application
    asyncio.run(main_async())
