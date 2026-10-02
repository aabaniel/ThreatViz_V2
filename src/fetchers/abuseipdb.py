
#===============================================================#

# API implementation: AbuseIPDB

#===============================================================#
def fetch_abuseipdb(ip: str, headers: dict, timeout: int = 20):
    print("[*] Fetching AbuseIPDB...")
    abuse_score = 0
    abuse_total_reports = 0
    abuse_country = "Unknown"
    abuse_data = {}
    
    try:
        check_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=365&verbose"
        r_check = requests.get(check_url, headers=headers, timeout=timeout)
        if r_check.status_code == 200:
            abuse_json = r_check.json().get("data", {}) or {}
            abuse_score = abuse_json.get("abuseConfidenceScore", 0) or 0
            abuse_total_reports = abuse_json.get("totalReports", 0) or 0
            abuse_country = abuse_json.get("countryCode") or abuse_json.get("country", "Unknown")
            abuse_data["check"] = abuse_json
        else:
            print(f"AbuseIPDB check request status: {r_check.status_code}")
    except Exception as e:
        print("AbuseIPDB check lookup failed:", e)
    
    try:
        reports_url = f"https://api.abuseipdb.com/api/v2/reports?ipAddress={ip}&maxAgeInDays=365"
        r_reports = requests.get(reports_url, headers=headers, timeout=timeout)
        if r_reports.status_code == 200:
            reports_json = r_reports.json().get("data", {}) or {}
            abuse_data["reports"] = reports_json
            print(f"[+] Retrieved {len(reports_json.get('results', []))} detailed reports")
        else:
            print(f"AbuseIPDB reports request status: {r_reports.status_code}")
    except Exception as e:
        print("AbuseIPDB reports lookup failed:", e)
    
    try:
        blacklist_url = f"https://api.abuseipdb.com/api/v2/blacklist?ipAddress={ip}"
        r_blacklist = requests.get(blacklist_url, headers=headers, timeout=timeout)
        if r_blacklist.status_code == 200:
            blacklist_json = r_blacklist.json().get("data", {}) or {}
            abuse_data["blacklist"] = blacklist_json
            if blacklist_json:
                print(f"[!] IP found in AbuseIPDB blacklist")
        else:
            print(f"AbuseIPDB blacklist request status: {r_blacklist.status_code}")
    except Exception as e:
        print("AbuseIPDB blacklist lookup failed:", e)
    
    try:
        outdir = globals().get("tmpdir", None)
        if outdir and abuse_data:
            for endpoint_name, endpoint_data in abuse_data.items():
                with open(os.path.join(outdir, f"abuseipdb_{endpoint_name}.json"), "w", encoding="utf-8") as f:
                    json.dump(endpoint_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Failed saving AbuseIPDB JSON files: {e}")
    
    return abuse_score, abuse_total_reports, abuse_country
