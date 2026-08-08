# 🍯 Automated Threat Intelligence & Zero-Trust SIEM Pipeline (Cowrie Honeypot)

## 📄 Overview
This project transforms a repurposed Android device into a live edge sensor using Termux and the Cowrie honeypot to capture real-world internet threats. Utilizing a decoupled architecture, it exposes the sensor via standard port forwarding, while a centralized Kali Linux broker automatically extracts, enriches, and forwards the threat data to a Splunk SIEM for real-time geographic visualization. To guarantee absolute security during log extraction, we implemented **Tailscale** to create an invisible, out-of-band management network which creates a tunnel between the Broker(our Kali Machine) and the sensor(the phone/honeypot) so that the broker can extract the data from the Honeypot from any network anywhere in the world.

## 🏗️ Architecture & Network Flow

1. **The Edge Sensor (Redmi Note 7 Pro):** Runs Cowrie inside an isolated Termux Linux environment.
2. **Public Exposure (Port Forwarding):** The honeypot's port 2222 is exposed directly to the public internet via the home router, serving as the trap for attacker,automated scanners and the botnets.
3. **Out-of-Band Management (Tailscale):** A Zero-Trust mesh VPN connects the Kali broker directly to the honeypot using a private `100.x.x.x` virtual subnet. This bypasses local network restrictions and ensures management traffic is invisible to the public internet.
4. **The Automation Broker (Kali Linux):** A custom Python script (`broker.py`) connects to the honeypot via Tailscale SSH, extracts `cowrie.json` logs, and queries the **AbuseIPDB API** to append threat scores and geolocation.
5. **The SIEM (Splunk Enterprise):** Receives the enriched JSON payload via the HTTP Event Collector (HEC) and translates it into actionable threat dashboards.

![Description of image](.\Diagrams\Arch Diagram.png)
![Description of image](.\NotebookLMMindMap.png)

---

## 🛠️ Tools, Technologies, & Libraries Used

### **Hardware & OS**
* **Sensor Node:** Old Android Phone (Redmi Note 7 Pro) running **Termux** (Android 10)
* **Central Broker & SIEM:** Spare Laptop running **Kali Purple Linux** (Debian-based)

### **Software & Platforms**
* **Cowrie:** Medium-interaction SSH/Telnet honeypot.
* **Splunk Enterprise (Free):** Data ingestion, SPL queries, and visualization.
* **AbuseIPDB:** Threat intelligence API for checking IP reputation and reporting malicious actors (Also collecting the live Geolocation of the IP from here).
* **Tailscale:** Zero-trust encrypted mesh VPN (WireGuard-based) for secure out-of-band management.
* **OpenSSH:** `sshd` daemon on Termux (Port 8022) and SSH client on Kali.

### **Python Libraries**
* `requests`: For making HTTP calls to the AbuseIPDB API and Splunk HEC.
* `paramiko`: For automated, programmatic SSH log extraction from Kali to the phone.
* `cryptography`, `twisted`, `cffi`, `setuptools`: Core dependencies for the Cowrie framework.


---

## 🚀 Step-by-Step Implementation Guide

### Phase 1: Deploying the Edge Sensor (Android/Termux)
1. **Install Termux** via F-Droid (Because the Play Store version is depricated as the Phone has 2021 security and OS version).
2. **Update repositories and install system packages: (in a Termux session)**
   ```bash
   pkg update && pkg upgrade -y
   pkg install python git clang rust pkg-config openssl python-cryptography openssh
   ```
   * Here **clang, rust pkg-config, openssl** are hour complier toolchain. Because Cowrie depends on the python libraries like **Twisted, cffi and Cryptography** and they can not be downloaded as pre compiled libraries on an Android devices (or any ARM based devices), so they must be built from source during the installation. And to do that we need Clang (C/C++ Compiler), Rust compiler and the openssl.
3. **Clone Cowrie and create the isolated environment:**
   ```bash
   git clone https://github.com/cowrie/cowrie.git
   ```
   * Pull the entire Cowrie source code from the Github repo and copy it to the device.
   ```bash 
   cd cowrie
   ```
   * Change the directory to the cowrie folder.
   ```bash
   python -m venv cowrie-env
   ```
   * This tells python to create a Virtual Environment and we name it "cowrie-env".
   * This is very very crucial as it keeps the core Cowrie python dependencies seperate from our device Android device's python packages. 
   
   ```bash
   source cowrie-env/bin/activate
   ```
   * Activate the Virtual Environment. 

4. **Fixing ARM Architecture Compilation Errors:**
   Because pip struggles to build the massive `cryptography` library from raw C/Rust source code on mobile processors, we used Termux's pre-compiled binary (`python-cryptography`).
   * We edited `requirements.txt` (`nano requirements.txt`) to remove `cryptography`.
   * We modified `cowrie-env/pyvenv.cfg` to set `include-system-site-packages = true`, forcing the virtual environment to utilize the system-installed package.
5. **Install Python dependencies and initialize:**
   ```bash
   pip install -r requirements.txt   
   #Installs the remaining required Python libraries into the virtual environment.
   
   pip install --no-deps -e .
   #Installs the Cowrie package locally.

   bin/cowrie init   
   #Initializes the honeypot configuration files.
   
   cowrie start
   #Starts the honeypot daemon.
   cowrie status
   # We can check the status of the Virtual environment using the command `cowrie status` and it will show us the status with the process id "Cowrie is running (PID: XXXXX)". 
   ```

6. **Start the SSH Daemon for Remote Management:**
   ```bash
   sshd  # Runs on port 8022 by default
   passwd # Set password for Kali broker
   ```
7. **Swipe the notification bar and select "Aquire Wake Lock" on the Termux notification:**
   * It prevents the honeypot and SSH daemon from being killed by background battery optimization.

### Phase 2: Zero-Trust Networking & Public Exposure (Tailscale & ISP)
Instead of relying on third-party cloud tunnels like Pinggy, we separated the network planes for maximum security:

1. **The Management Plane (Tailscale):**
   * Installed Tailscale on both the Android phone and the Kali laptop.
   * Both devices were added to the same Tailnet, granting them private `100.x.x.x` IP addresses. This established an encrypted, out-of-band tunnel for the Python script to extract logs without traversing the public internet.
2. **The Attacker Plane (Port Forwarding):**
   * Logged into the home ISP Gateway (Bell router).
   * Created a TCP port forwarding rule to map public external traffic on Port 2222 directly to the Android phone's local IP address on Port 2222.
   * The honeypot was successfully exposed.

* We can test the connection to the Honeypot by using a seperate device on a seperate network. All we need to do is in the other device's terminal try to ssh to the home IPAddress.
``` bash
    ssh root@IPAddressOftheNetwork
    # This is not the tailscale IP, it is the IP on which our device/sensor sits on.
    # Once we hit enter it will ask us to enter a password and when we enter a random password it should let us in to the Honeypot. 
    # It will accept the random passowords 99% of the times to lure the attackers. 
```
   ![Description of image]()

### Phase 3: The SIEM Pipeline (Kali Linux)
1. **Install Splunk:**
   ```bash
   wget -O splunk.deb 'https://download.splunk.com/...'
   sudo dpkg -i splunk.deb
   sudo /opt/splunk/bin/splunk start --accept-license
   ```
2. **Configure Splunk:**
   * Access the web UI at `http://localhost:8000`.
   * Create an index named `honeypot`.
   * Enable the **HTTP Event Collector (HEC)** globally on port 8088.
   * Generate an HEC token for the automation script.

### Phase 4: The Automation Broker (`broker.py`)
1. On Kali, install requirements:
   ```bash
   pip install requests paramiko
   ```
2. **Create the Script:** The `broker.py` script:
   * Uses `paramiko` to SSH into the phone securely over the Tailscale interface (`100.x.x.x:8022`).
   * Reads `var/log/cowrie/cowrie.json`.
   * State Management: Checks a local text file (broker_state.txt) that tracks the index/line number of the last pulled log. It only reads and extracts new data generated after that index to ensure no duplicate logs are sent to the SIEM.
   * Identifies attacker IPs and queries the **AbuseIPDB API**.
   * Pushes the enriched threat intelligence payload via HTTP POST to `127.0.0.1:8088` (Splunk HEC).
   * Updates broker_state.txt with the new final index position for the next run.
3. **Automating with Cron (The 5-Minute Pull)**
   * To ensure near real-time ingestion into our SIEM without manual intervention, we scheduled the Python script to run automatically every 5 minutes. 
   * Open the crontab editor on the Kali machine:
`crontab -e`
   * Add the following rule to execute the pull script every 5 minutes.

      `*/5 * * * * /usr/bin/python3 /path/to/your/broker.py >> /var/log/honeypot_pull.log 2>&1`

   * This ensures a continuous flow of enriched threat data into Splunk, ready for dashboard visualization and SPL querying.

![Description of image]()
### Phase 5: Splunk Visualization & SPL Queries
Once data was flowing, different visual panels were built using custom SPL:

1. **Global Threat Origin Map (Choropleth Map):**
   *Resolved an offline MaxMind Geolocation database discrepancy by explicitly relying on live AbuseIPDB data and Splunk's lookup feature.*
   ```sql
   index="honeypot" eventid="cowrie.session.connect"
   | dedup _raw
   | lookup geo_attr_countries iso2 AS threat_intel.country_code OUTPUT country
   | stats count by country
   | geom geo_countries featureIdField="country"
   ```
   ![Description of image]()
2. **Top Attackers Overview (Stats Table):**
   ```sql
   index="honeypot" eventid="cowrie.session.connect"
   | dedup _raw
   | stats count by src_ip, threat_intel.country_code, threat_intel.abuse_score
   | rename src_ip as "Attacker IP", threat_intel.country_code as "Country", threat_intel.abuse_score as "AbuseIPDB Score", count as "Total Connections"
   | sort - "Total Connections"
   ```
   ![Description of image]()

3. **High-Fidelity Alerts (Score > 50):**
   ```sql
   index="honeypot" threat_intel.abuse_score > 50
   | dedup _raw
   | table _time, src_ip, threat_intel.country_code, threat_intel.abuse_score
   | rename src_ip as "Malicious IP", threat_intel.country_code as "Origin", threat_intel.abuse_score as "Threat Score"
   | sort - _time
   ```
   ![Description of image]()
4. **Attack Volumn by Country:**
   ```sql
   index="honeypot" eventid="cowrie.session.connect"
   | dedup _raw
   | timechart span=1h count by threat_intel.country_code
   ```
   ![Description of image]()
5. **Data Received time log:**
   * To Check if we are receiving the data from the honeypot every 5 mins.
   ```sql
   index="honeypot"
   | dedup _raw
   | timechart span=5m count
   ```
   ![Description of image]()

---

## 🚧 Challenges & Troubleshooting Log
* **ISP Firewall Blocking (Bell Advanced Security):** Discovered that the ISP's built-in McAfee AI shield silently dropped incoming SSH connections to Port 2222, overriding standard port forwarding rules. Solved by bypassing the advanced shield settings in the Bell Wi-Fi app.
* **Bypassing Mobile ARM Architecture Limitations:** `pip` failed to compile cryptography libraries from raw C/Rust. Solved by installing pre-compiled binaries via the Termux `pkg` manager and creating a `PYTHONPATH` bridge for the virtual environment.
* **Android Battery Optimization (TimeoutErrors):** Aggressive background app management killed the `sshd` daemon. Solved by forcefully acquiring an Android Wakelock.
* **SIEM Geo-Discrepancies:** Discovered that Splunk's offline `iplocation` database was mis-mapping IP locations compared to the live API data. Refactored SPL queries to map coordinates using `geo_attr_countries` for 100% accuracy.
* **Broker Desynchronization:** During cold reboots, the script hung waiting for `cowrie.json` to reach a previous byte offset. Reset the state tracker by clearing the broker's bookmark file, wiping the honeypot log, and generating a clean Splunk index.

---

## 🔮 Pontential Future improvements
If I were to work on it furthur and improve the current project, here are some recommendations:
1. **Automated Threat Response (SOAR):** Integrate a SOAR (Security Orchestration, Automation, and Response) capability into the broker.py script. If an attacker's IP returns an AbuseIPDB score of 100, the script could automatically trigger an API call to a perimeter firewall (or cloud WAF) to permanently block that IP across the entire network.

2. **MITRE ATT&CK Mapping:** Enhance the Splunk dashboards to automatically map the commands executed inside the honeypot (e.g., wget, chmod 777) to specific MITRE ATT&CK techniques (like T1105: Ingress Tool Transfer), providing a more structured threat intelligence report.

3. **Automated YARA Rule Generation:** Configure the pipeline to automatically hash any files or malware payloads dropped into the honeypot, run them against VirusTotal, and auto-generate YARA rules for local endpoint detection.

4. **Containerization of the Middleware:** Package the Kali Linux broker.py script and its dependencies into a lightweight Docker container. This would make the log-forwarding architecture entirely OS-agnostic and easy to deploy on any server instantly.
