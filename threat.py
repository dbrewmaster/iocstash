import requests
import time
import csv

filename = "iocs_combined.csv"

# Sources
sources = {
    "URLHaus_CSV": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "Feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "MalwareBazaar": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "OpenPhish": "https://openphish.com/feed.txt",
    "ThreatFox_API": "https://threatfox-api.abuse.ch/api/v1/",
    "GreyNoise": "https://api.greynoise.io/v3/community/",
    "URLScan": "https://urlscan.io/api/v1/search/?q=domain:example.com",
    "Shodan": "https://api.shodan.io/dns/resolve?hostnames=example.com"
}

ioc_data = []

# GreyNoise Community API
def fetch_greynoise():
    print("[*] Fetching from GreyNoise Community API...")
    test_ip = "8.8.8.8"  # Example IP
    try:
        response = requests.get(sources["GreyNoise"] + test_ip)
        response.raise_for_status()
        data = response.json()
        ioc_data.append({
            "Type": "IP",
            "Value": test_ip,
            "Source": "GreyNoise",
            "Threat_Category": data.get("classification", "Unknown"),
            "Date": data.get("last_seen", "N/A")
        })
        print("  [+] Loaded IP from GreyNoise")
    except Exception as e:
        print("Error fetching from GreyNoise:", e)

# URLScan public domain search
def fetch_urlscan():
    print("[*] Fetching from URLScan.io...")
    try:
        response = requests.get(sources["URLScan"])
        response.raise_for_status()
        results = response.json().get("results", [])
        count = 0
        for result in results[:10]:
            ioc_data.append({
                "Type": "URL",
                "Value": result.get("task", {}).get("url"),
                "Source": "URLScan.io",
                "Threat_Category": "Scan Result",
                "Date": result.get("task", {}).get("time", "N/A")
            })
            count += 1
        print(f"  [+] Loaded {count} IOCs from URLScan.io")
    except Exception as e:
        print("Error fetching from URLScan.io:", e)

# Shodan basic DNS resolve (public usage)
def fetch_shodan_info():
    print("[*] Fetching from Shodan Public API...")
    try:
        api_key = "dzOB1jDn1DeLf5YOSCddCrBmNC5YjKM8"
        # Example query: search for malware-related results (change query as needed)
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            "key": api_key,
            "query": "malware"
        }
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        count = 0
        for match in data.get("matches", []):
            ioc_data.append({
                "Type": "IP",
                "Value": match.get("ip_str", "N/A"),
                "Source": "Shodan",
                "Threat_Category": match.get("tags", ["N/A"])[0] if match.get("tags") else "N/A",
                "Date": match.get("timestamp", "N/A")
            })
            count += 1

        print(f"  [+] Loaded {count} IOCs from Shodan (search)")
    except Exception as e:
        print("Error fetching from Shodan:", e)

# Already existing fetchers...
def fetch_threatfox_api():
    print("[*] Fetching from ThreatFox API...")
    try:
        payload = {"query": "get_iocs", "limit": 100}
        response = requests.post(sources["ThreatFox_API"], json=payload)
        response.raise_for_status()
        data = response.json()
        count = 0
        for ioc in data.get("data", []):
            ioc_data.append({
                "Type": ioc.get("ioc_type"),
                "Value": ioc.get("ioc"),
                "Source": "ThreatFox API",
                "Threat_Category": ioc.get("threat_type"),
                "Date": ioc.get("first_seen", "N/A")
            })
            count += 1
        print(f"  [+] Loaded {count} IOCs from ThreatFox API")
    except Exception as e:
        print("Error fetching from ThreatFox API:", e)

def fetch_urlhaus_csv():
    print("[*] Fetching from URLHaus (CSV)...")
    try:
        response = requests.get(sources["URLHaus_CSV"])
        response.raise_for_status()
        lines = response.text.splitlines()
        reader = csv.reader(lines)
        count = 0
        for i, row in enumerate(reader):
            if i < 9 or len(row) < 7:
                continue
            ioc_data.append({
                "Type": "URL",
                "Value": row[2],
                "Source": "URLHaus",
                "Threat_Category": row[6],
                "Date": row[1]
            })
            count += 1
        print(f"  [+] Loaded {count} IOCs from URLHaus")
    except Exception as e:
        print("Error fetching from URLHaus:", e)

def fetch_feodo():
    print("[*] Fetching from Feodo Tracker...")
    try:
        response = requests.get(sources["Feodo"])
        response.raise_for_status()
        count = 0
        for line in response.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            ioc_data.append({
                "Type": "IP",
                "Value": line.strip(),
                "Source": "Feodo Tracker",
                "Threat_Category": "Botnet C2",
                "Date": "N/A"
            })
            count += 1
        print(f"  [+] Loaded {count} IOCs from Feodo Tracker")
    except Exception as e:
        print("Error fetching from Feodo Tracker:", e)

def fetch_malwarebazaar():
    print("[*] Fetching from MalwareBazaar...")
    try:
        response = requests.get(sources["MalwareBazaar"])
        response.raise_for_status()
        count = 0
        for line in response.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            ioc_data.append({
                "Type": "Hash",
                "Value": line.strip(),
                "Source": "MalwareBazaar",
                "Threat_Category": "Malware",
                "Date": "N/A"
            })
            count += 1
        print(f"  [+] Loaded {count} IOCs from MalwareBazaar")
    except Exception as e:
        print("Error fetching from MalwareBazaar:", e)

def fetch_openphish():
    print("[*] Fetching from OpenPhish...")
    try:
        response = requests.get(sources["OpenPhish"])
        response.raise_for_status()
        count = 0
        for line in response.text.splitlines():
            url = line.strip()
            if url:
                ioc_data.append({
                    "Type": "URL",
                    "Value": url,
                    "Source": "OpenPhish",
                    "Threat_Category": "Phishing",
                    "Date": "N/A"
                })
                count += 1
        print(f"  [+] Loaded {count} IOCs from OpenPhish")
    except Exception as e:
        print("Error fetching from OpenPhish:", e)

# Run all fetchers
fetch_threatfox_api()
fetch_urlhaus_csv()
fetch_feodo()
fetch_malwarebazaar()
fetch_openphish()
fetch_greynoise()
time.sleep(5)
fetch_urlscan()
time.sleep(5)
# fetch_shodan_info()

# Save to CSV
print(f"[+] Saving {len(ioc_data)} total IOCs to {filename}")
with open(filename, "w", newline="", encoding="utf-8") as csvfile:
    fieldnames = ["Type", "Value", "Source", "Threat_Category", "Date"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in ioc_data:
        writer.writerow(row)

print("[✔] Done.")
