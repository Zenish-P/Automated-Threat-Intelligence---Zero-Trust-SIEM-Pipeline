import json
import paramiko
import requests
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
PHONE_IP = "100.XX.XX.XX" # this will be the Honeypot's Tailscale IP
PHONE_PORT = 8022
PHONE_USER = "u0_aXXX" 
PHONE_PASS = "XXXXX" #This is the password we set for the Node

SPLUNK_URL = 'https://127.0.0.1:8088/services/collector/event'
SPLUNK_TOKEN = 'XXXXXXXXXXXXXXXXXXXXXXXXX' # From the Splunk platform
ABUSEIPDB_KEY = 'XXXXXXXXXXXXXXXXXXXXXXXXXx' # Unique API key from the AbuseIPDB account 

# The file where the script remembers its place
STATE_FILE = "/home/user/Desktop/broker_state.txt"
# Ensure this matches the correct path you found earlier (e.g., "cowrie/var/log/cowrie/cowrie.json")
LOG_PATH = "cowrie/var/log/cowrie/cowrie.json" 
# ---------------------

def query_abuseipdb(ip):
    if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
        ip = "8.8.8.8" # Checks for any local IPand see if any attacker spoofed a local address, if soo it changes it to Google's DNS to avoid error from API
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_KEY}
    querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "abuse_score": data["data"]["abuseConfidenceScore"],
                "country_code": data["data"]["countryCode"]
            }
    except Exception as e:
        print(f"[!] AbuseIPDB lookup failed: {e}")
    return None

def send_to_splunk(payload):
    headers = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}
    splunk_packet = {"sourcetype": "cowrie", "event": payload} #JSON wrapper for splunk
    try:
        res = requests.post(SPLUNK_URL, headers=headers, json=splunk_packet, verify=False, timeout=5)
        return res.status_code == 200
    except Exception:
        return False

def main():
    # 1. Read the bookmark(broker_state.txt) to see where we left off
    last_pos = 0
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            last_pos = int(f.read().strip())

    print(f"[*] Establishing secure connection to sensor at {PHONE_IP}:{PHONE_PORT}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(PHONE_IP, port=PHONE_PORT, username=PHONE_USER, password=PHONE_PASS, timeout=10)
        sftp = ssh.open_sftp()
        
        # 2. Check file size. If the log file was rotated/deleted by your janitor script, reset to 0
        try:
            file_stat = sftp.stat(LOG_PATH)
            if file_stat.st_size < last_pos:
                print("[*] Log rotation detected. Resetting bookmark to 0.")
                last_pos = 0
        except IOError:
            print("[!] Could not find the log file. Check your LOG_PATH variable.")
            return

        remote_file = sftp.open(LOG_PATH, "r")
        
        # 3. Fast-forward to the exact byte we stopped at last time
        remote_file.seek(last_pos)
        print(f"[*] Resuming log extraction from byte {last_pos}...")
        
        new_events_count = 0
        
        # We use readline() instead of a for-loop to ensure byte tracking is perfectly accurate
        while True:
            line = remote_file.readline()
            if not line:
                break
                
            line = line.strip()
            if not line:
                continue
                
            try:
                event = json.loads(line)
                event_id = event.get("eventid", "")
                
                if event_id == "cowrie.session.connect":
                    src_ip = event.get("src_ip", "")
                    intel = query_abuseipdb(src_ip)
                    if intel:
                        event["threat_intel"] = intel
                
                if send_to_splunk(event):
                    new_events_count += 1
                    
            except json.JSONDecodeError:
                continue
                
        # 4. Save the new bookmark position for next time
        new_pos = remote_file.tell()
        with open(STATE_FILE, "w") as f:
            f.write(str(new_pos))
            
        print(f"[*] Success: Forwarded {new_events_count} new events to Splunk. Bookmark saved at byte {new_pos}.")
        
        remote_file.close()
        sftp.close()
        
    except Exception as e:
        print(f"[!] Pipeline Execution Error: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
