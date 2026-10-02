
#===============================================================#

# AbuseIPDB reports by category graph

#===============================================================#
def create_abuseipdb_category_graph(ip: str, headers: dict):
    """
    Fetch AbuseIPDB reports and create a bar graph showing
    the quantity of reports by category for the given IP address.
    """
    print("[*] Fetching AbuseIPDB category reports...")
    
    CATEGORY_MAP = {
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted"
    }
    
    try:
        abuse_url = f"https://api.abuseipdb.com/api/v2/reports?ipAddress={ip}&maxAgeInDays=365"
        r = requests.get(abuse_url, headers=headers, timeout=20)
        
        if r.status_code != 200:
            print(f"AbuseIPDB reports request failed: {r.status_code}")
            return None
        
        data = r.json().get("data", {}) or {}
        reports = data.get("results", []) or []
        
        category_counts = {cat_name: 0 for cat_name in CATEGORY_MAP.values()}
        
        if reports:
            for report in reports:
                categories = report.get("categories", []) or []
                for cat_id in categories:
                    cat_name = CATEGORY_MAP.get(cat_id, f"Category {cat_id}")
                    category_counts[cat_name] += 1
        
        sorted_cats = sorted(category_counts.items(), key=lambda x: x[0])
        categories = [c[0] for c in sorted_cats]
        counts = [c[1] for c in sorted_cats]
        
        fig = plt.figure(figsize=(10, 6))
        bars = plt.barh(categories, counts, color='#fd8d3c', alpha=0.8)
        plt.xlabel("Number of Reports")
        plt.title(f"AbuseIPDB Report Categories for {ip}")
        plt.grid(axis="x", linestyle="--", alpha=0.35)
        
        for bar, count in zip(bars, counts):
            plt.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                     str(count), va='center', fontsize=9)
        
        plt.tight_layout()
        path = save_fig(fig, "abuseipdb_categories.png")
        print(f"[+] AbuseIPDB category graph saved to: {path}")
        return path
        
    except Exception as e:
        print(f"Failed to fetch AbuseIPDB category reports: {e}")
        return None
