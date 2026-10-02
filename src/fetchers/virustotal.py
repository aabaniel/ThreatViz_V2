
#===============================================================#

# API implementation: Virustotal

#===============================================================#

def fetch_virustotal(ip: str, headers: dict):
    print("[*] Fetching VirusTotal...")
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r_vt = requests.get(vt_url, headers=headers, timeout=20)
        if r_vt.status_code != 200:
            print(f"VirusTotal request failed: {r_vt.status_code} - {r_vt.text[:300]}")
            vt_data = {}
        else:
            vt_data = r_vt.json().get("data", {}).get("attributes", {}) or {}
    except Exception as e:
        print(f"VirusTotal lookup failed: {e}")
        vt_data = {}

    vt_stats = vt_data.get("last_analysis_stats", {}) or {}
    vt_stat_order = ["harmless", "undetected", "suspicious", "malicious", "timeout"]
    vt_keys = [k for k in vt_stat_order if k in vt_stats]
    vt_vals = [vt_stats.get(k, 0) for k in vt_keys]
    vt_asn = vt_data.get("as_owner") or "Unknown ASN"
    vt_country = vt_data.get("country") or "Unknown"
    vt_rep = vt_data.get("reputation") or 0
    vt_malicious = vt_stats.get("malicious", 0)

    res = vt_data.get("resolutions") or []
    related_domains = []
    for r in res:
        if isinstance(r, dict):
            d = r.get("host_name") or r.get("hostname") or r.get("host")
            if d:
                related_domains.append(d)
    related_domains = related_domains[:8]

    return (
        vt_data,
        vt_stats,
        vt_stat_order,
        vt_keys,
        vt_vals,
        vt_asn,
        vt_country,
        vt_rep,
        vt_malicious,
        related_domains,
    )
