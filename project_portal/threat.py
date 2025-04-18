import requests
import csv

filename = "iocs_combined.csv"

# Sources
sources = {
    "URLHaus_CSV": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "Feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "MalwareBazaar": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "OpenPhish": "https://openphish.com/feed.txt",
    "ThreatFox_API": "https://threatfox-api.abuse.ch/api/v1/"
}

ioc_data = []

# 1. ThreatFox API (POST request)
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

# 2. URLHaus (CSV)
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

# 3. Feodo Tracker (IP list)
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

# 4. MalwareBazaar (SHA256 list)
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

# 5. OpenPhish (URLs)
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

# Running all fetchers
fetch_threatfox_api()
fetch_urlhaus_csv()
fetch_feodo()
fetch_malwarebazaar()
fetch_openphish()

# Saving to CSV
print(f"[+] Saving {len(ioc_data)} total IOCs to {filename}")
with open(filename, "w", newline="", encoding="utf-8") as csvfile:
    fieldnames = ["Type", "Value", "Source", "Threat_Category", "Date"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in ioc_data:
        writer.writerow(row)

print("[✔] Done.")
