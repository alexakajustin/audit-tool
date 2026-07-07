# NetAudit

NetAudit is an advanced network discovery and cybersecurity auditing application designed to identify assets and evaluate local network security posture using legal, passive monitoring and targeted active scanning. The tool runs as a lightweight local web service with a clean, single-page application interface.

## Core Capabilities

### Passive Network Discovery
NetAudit continuously monitors local network traffic on the active interface using Scapy. It intercepts broadcast, multicast, and ARP protocols to map active hosts without injecting traffic into the network. This includes:
* Automated MAC-to-Vendor resolution.
* Passive host activity mapping based on protocol interactions (ARP, DHCP, mDNS, LLMNR, SSDP, DNS).
* Live packet counters and traffic distribution charts.

### Active Security Scanners
The application includes a plugin-based architecture for active security checks:
* **ARP Cache Reader**: Checks the local system ARP cache for quick peer discovery.
* **ARP Sweep**: Broadcasts ARP requests to map the subnet (requires administrative permissions).
* **DHCP Sniffer**: Audits the local subnet for DHCP configurations and rogue DHCP servers.
* **Nmap Scanner**: Wrapper around local Nmap installations to perform detailed port and service discovery.
* **Wi-Fi AP Scanner**: Queries surrounding Wi-Fi Access Points to map neighboring wireless environments.

### Security Telemetry & Metrics Reporting
A background session-based telemetry gathering engine aggregates network statistics, packet counts, active hosts, and security threats over a user-defined window.
* **Master Service Control**: Clicking "Start Gathering Metrics" auto-detects the best network interface and starts both passive discovery and the packet sniffer if they are inactive.
* **Telemetry PDF Report**: Once stopped, NetAudit generates a structured PDF containing a network summary, raw telemetry values, and extensive health metrics:
  * **Traffic Rate & Statistics**: Total packets captured, duration, active interface IP, and Average Traffic Rate in Packets per Second (PPS).
  * **Protocol Distribution**: Table detailing packet counts and traffic share percentage for active network protocols (TCP, UDP, ARP, DNS, etc.).
  * **Top Bandwidth Consumers**: Detailed breakdown of hosts transferring the most data during the session (formatted in B, KB, MB, GB).
  * **Top DNS Queries**: Summary of target domains queried on the network by count.
  * **Most Visited Websites**: Table mapping HTTP hostnames/websites requested.
  * **Detected Network Services**: List of active network assets and the broadcast services or protocols they run.
  * **Security Findings & Mitigation Recommendations**: Clean table of detected anomalies (like ARP spoofing or rogue DHCP offers) with actionable, industry-standard mitigation advice.

## Project Structure

* `/api` - Flask Blueprint definitions handling endpoints for scanners, passive discovery, and metrics control.
* `/core` - Core business logic including the scanner registry, network inventory managers, and the metrics telemetry engine.
* `/network` - Low-level network interface detection utilities.
* `/scanners` - Plugin scanner implementations loaded dynamically at runtime.
* `/sniffers` - Background passive sniffer workers utilizing raw sockets.
* `/static` - Frontend assets (CSS styles, JavaScript components, API helpers).
* `/templates` - Single HTML index serving as the GUI entry point.
* `app.py` - Flask web server initialization and application bootstrap.
* `build.py` - PyInstaller compiler script to bundle the app into a single executable.

## Installation and Prerequisites

NetAudit requires Python 3.10+ and a packet capture library.

### Windows Prerequisites
* **Npcap**: NetAudit uses raw sockets for passive sniffing and active sweeping. Npcap must be installed on Windows. Ensure "Install Npcap in WinPcap API-compatible Mode" is checked during installation.
* Administrator privileges are required to bind to network interfaces.

### Linux/macOS Prerequisites
* **libpcap**: Ensure your system has libpcap installed.
* NetAudit must be run with `sudo` or appropriate capabilities (`CAP_NET_RAW` and `CAP_NET_ADMIN`) to sniff packets.

### Python Dependencies
Install required packages via pip:
```bash
pip install -r requirements.txt
```

## Running the Application

### From Source
Run the server using the provided helper scripts or execute python directly. Ensure you run this from an elevated/administrator command line.

**Windows (Administrator Command Prompt):**
```cmd
python app.py
```
Or execute:
```cmd
run_admin.bat
```

Access the UI in your web browser at `http://127.0.0.1:5000`.

### Compiling to a Stand-alone Folder
You can bundle Python, all code dependencies, dynamic scanners, and frontend assets into a stand-alone folder using the custom build script:
```bash
python build.py
```
This produces the folder `dist/NetAudit/` containing the executable `NetAudit.exe` alongside its linked library dependencies (which bypasses Windows Smart App Control blocking). The build script is configured to preserve other files in the `dist` folder, meaning you can store Npcap or Nmap installer prerequisites alongside the compiled directory for easy distribution.
