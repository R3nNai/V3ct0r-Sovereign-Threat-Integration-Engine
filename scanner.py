import subprocess
import re

class LocalAssetScanner:
    def __init__(self):
        # The target services we want our pipeline to automatically police
        self.monitored_services = ["nginx", "openssh-server", "apache2", "curl"]

    def discover_local_assets(self) -> list:
        print("[*] Accessing local system package registry...")
        discovered_cpes = []

        for service in self.monitored_services:
            try:
                # Query dpkg for the specific installed package status and version
                result = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Status} ${Version}\n", service],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                output = result.stdout.strip()
                
                # Check if the package is fully installed on the host
                if "install ok installed" in output:
                    # Extract just the raw version string (e.g., "1.22.1-1~deb12u1")
                    raw_version = output.split()[-1]
                    
                    # Clean up Linux distribution suffixes for NVD syntax mapping
                    # (e.g., turning "1.22.1-1~deb12u1" cleanly into "1.22.1")
                    clean_version = re.match(r"^([0-9.]+)", raw_version)
                    if clean_version:
                        version = clean_version.group(1)
                    else:
                        version = raw_version

                    # Determine the correct NVD vendor partition mapping
                    vendor = "f5" if service == "nginx" else "openbsd" if service == "openssh-server" else "apache"
                    product = "nginx" if service == "nginx" else "openssh" if service == "openssh-server" else service

                    # Build the official CPE 2.3 formatted string dynamically
                    cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                    print(f" [+] Discovered Alive Asset: {service} (v{version}) -> Generated CPE Target.")
                    
                    discovered_cpes.append({
                        "asset": product,
                        "cpe": cpe_string
                    })
                    
            except Exception as e:
                print(f"[-] Error scanning registry for {service}: {e}")
                
        return discovered_cpes

if __name__ == "__main__":
    scanner = LocalAssetScanner()
    assets = scanner.discover_local_assets()
    print(f"\n[✓] Asset discovery phase complete. Found {len(assets)} targets for pipeline injection.")
