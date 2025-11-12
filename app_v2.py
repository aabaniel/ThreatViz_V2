#===============================================================#

# NSCOM03 Network Simulation Study Project
# Threat Intelligence through APIs Visualization 

# Group 2 Members:
# Aaron Abaniel
# Luis Biacora
# Isha Zulueta

#===============================================================#

# Libraries

#===============================================================#
import requests
import matplotlib.pyplot as plt
import networkx as nx
import folium
import os
import time
from matplotlib.patches import Patch
import csv
import json

#===============================================================#

# To install dependencies:

# pip install requests matplotlib networkx folium os time

#===============================================================#

# API Configuration - Current keys are from Aaron Abaniel

#===============================================================#

VT_API_KEY = "I AINT GIVING YOU MINE"
ABUSE_API_KEY = "I AINT GIVING YOU MINE"
OTX_API_KEY = "I AINT GIVING YOU MINE"  

# initialize keys into variables

HEADERS_VT = {"x-apikey": VT_API_KEY}
HEADERS_ABUSE = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
HEADERS_OTX = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}

#===============================================================#

# Save figures as files

#===============================================================#

def save_fig(fig, name, dpi=150):
    path = os.path.join(tmpdir, name)
    fig.savefig(path, bbox_inches="tight", dpi=dpi)
    plt.close(fig)
    return path

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

#===============================================================#

# API implementation: AlienVault OTX

#===============================================================#
def fetch_otx(ip: str, headers: dict, timeout: int = 20):
    print("[*] Fetching AlienVault OTX...")

    base = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
    endpoints = {
        "general": f"{base}/general",
        "reputation": f"{base}/reputation",
        "geo": f"{base}/geo",
        "malware": f"{base}/malware?limit=50&page=1",
        "url_list": f"{base}/url_list?limit=50&page=1",
        "passive_dns": f"{base}/passive_dns?limit=50&page=1",
        "http_scans": f"{base}/http_scans?limit=50&page=1",
    }

    data = {}
    pulse_count = 0
    otx_tags = []
    otx_malware_families = []
    otx_geo = "Unknown"

    def _get(url: str):
        try:
            r = requests.get(url, headers=headers or {}, timeout=timeout)
            if r.status_code == 200:
                return r.json() or {}
            print(f"OTX request status: {r.status_code} for {url}")
        except Exception as e:
            print(f"OTX lookup failed for {url}: {e}")
        return {}

    for name, url in endpoints.items():
        j = _get(url)
        data[name] = j
        try:
            outdir = globals().get("tmpdir", None)
            if outdir:
                with open(os.path.join(outdir, f"otx_{name}.json"), "w", encoding="utf-8") as f:
                    json.dump(j, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Failed saving OTX {name} JSON: {e}")

    general = data.get("general", {}) or {}
    pulse_info = general.get("pulse_info", {}) or {}
    pulses = pulse_info.get("pulses", []) or []
    pulse_count = len(pulses)
    otx_tags = pulse_info.get("tags", []) or []
    otx_malware_families = list({
        mf for p in pulses for mf in (p.get("malware_families") or [])
    })

    otx_geo = (
        (general.get("geo") or {}).get("country_code")
        or data.get("geo", {}).get("country_code")
        or otx_geo
    )

    return pulse_count, otx_tags, otx_malware_families, otx_geo

#===============================================================#

# Creation of Temporary Directory

#===============================================================#

def prepare_tmpdir(ip):
    global tmpdir
    try:
        base = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        base = os.getcwd()
    tmpdir = os.path.join(base, f"ip_report_{ip.replace('.', '_')}")
    os.makedirs(tmpdir, exist_ok=True)
    print(f"[+] Temporary working folder: {tmpdir}")
    return tmpdir

#===============================================================#

# Output of API data to CSV

#===============================================================#
def output_to_csv(ip, vt_data, vt_stats, vt_asn, vt_country, vt_rep, vt_malicious,
                  abuse_score, abuse_total_reports, abuse_country,
                  pulse_count, otx_tags, otx_malware_families, otx_geo,
                  related_domains):
    """Output comprehensive API data to a CSV file"""
    
    csv_path = os.path.join(tmpdir, f"{ip}_report.csv")
    
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            writer.writerow(['Metric', 'Value'])
            writer.writerow([])

            # IP Information
            writer.writerow(['=== IP Information ===', ''])
            writer.writerow(['IP Address', ip])
            writer.writerow(['ASN Owner', vt_asn])
            writer.writerow(['Country (VT)', vt_country])
            writer.writerow(['Country (Abuse)', abuse_country])
            writer.writerow(['Country (OTX)', otx_geo])
            writer.writerow([])

            # VirusTotal Data
            writer.writerow(['=== VirusTotal ===', ''])
            writer.writerow(['Reputation Score', vt_rep])
            writer.writerow(['Malicious Detections', vt_malicious])
            for key, val in (vt_stats or {}).items():
                writer.writerow([f'Detection - {key.capitalize()}', val])
            if vt_data:
                writer.writerow(['Network', vt_data.get('network', 'N/A')])
                writer.writerow(['AS Owner', vt_data.get('as_owner', 'N/A')])
                writer.writerow(['ASN', vt_data.get('asn', 'N/A')])
                writer.writerow(['Continent', vt_data.get('continent', 'N/A')])
                writer.writerow(['Regional Internet Registry', vt_data.get('regional_internet_registry', 'N/A')])
                writer.writerow(['JARM', vt_data.get('jarm', 'N/A')])
                total_votes = vt_data.get('total_votes', {}) or {}
                writer.writerow(['Total Votes - Harmless', total_votes.get('harmless', 0)])
                writer.writerow(['Total Votes - Malicious', total_votes.get('malicious', 0)])
                writer.writerow(['Last Analysis Date', vt_data.get('last_analysis_date', 'N/A')])
                writer.writerow(['Last Modification Date', vt_data.get('last_modification_date', 'N/A')])
            writer.writerow([])

            # AbuseIPDB Data
            writer.writerow(['=== AbuseIPDB ===', ''])
            writer.writerow(['Abuse Confidence Score', abuse_score])
            writer.writerow(['Total Reports', abuse_total_reports])
            writer.writerow([])

            # OTX Data
            writer.writerow(['=== AlienVault OTX ===', ''])
            writer.writerow(['Pulse Count', pulse_count])
            writer.writerow(['Tags', ', '.join(otx_tags) if otx_tags else 'None'])
            writer.writerow(['Malware Families', ', '.join(otx_malware_families) if otx_malware_families else 'None'])
            writer.writerow([])

            # Related Domains
            writer.writerow(['=== Related Domains ===', ''])
            if related_domains:
                for idx, domain in enumerate(related_domains, 1):
                    writer.writerow([f'Domain {idx}', domain])
            else:
                writer.writerow(['No related domains found', ''])

            # Parse to CSV
            json_files = ['abuseipdb_check.json', 'abuseipdb_reports.json', 'otx_general.json', 'otx_reputation.json']
            for json_file in json_files:
                json_path = os.path.join(tmpdir, json_file)
                if os.path.exists(json_path):
                    with open(json_path, 'r', encoding='utf-8') as f:
                        json_data = json.load(f)
                        writer.writerow([f'=== {json_file.replace(".json", "").capitalize()} ===', ''])
                        for key, value in json_data.items():
                            writer.writerow([key, value])
                        writer.writerow([])

        print(f"[+] CSV report saved to: {csv_path}")
        return csv_path
        
    except Exception as e:
        print(f"Failed to create CSV report: {e}")
        return None

#===============================================================#

# VirusTotal Bar Chart

#===============================================================#

def create_vt_detection_bar(ip, vt_keys, vt_vals):
    fig = plt.figure(figsize=(7, 4))
    if vt_vals and sum(vt_vals) > 0:
        bars = plt.bar(vt_keys, vt_vals, alpha=0.9)
        plt.title(f"VirusTotal Detection Counts for {ip}")
        plt.ylabel("Count")
        plt.grid(axis="y", linestyle="--", alpha=0.35)
        for rect, val in zip(bars, vt_vals):
            plt.text(rect.get_x() + rect.get_width()/2, rect.get_height()+0.3, str(val),
                     ha="center", va="bottom", fontsize=8)
    else:
        plt.text(0.5, 0.5, "No detection stats available", ha="center", va="center")
        plt.title(f"VirusTotal Detection Counts for {ip}")
        plt.xticks([]); plt.yticks([])
    return save_fig(fig, "vt_detection_counts.png")

#===============================================================#

# VirusTotal Piechart

#===============================================================#

def create_vt_pie(ip, vt_keys, vt_vals):
    if not (vt_vals and sum(vt_vals) > 0):
        return None

    fig, ax = plt.subplots(figsize=(6,6))

    color_map = {
        "harmless": "#2ca02c",  
        "malicious": "#d62728", 
        "undetected": "#9467bd", 
        "suspicious": "#ff7f0e", 
        "timeout": "#1f77b4", 
    }
    colors = [color_map.get(k, "#7f7f7f") for k in vt_keys] 

    def autopct_no_zeros(pct):
        return "" if pct <= 0.0 else f"{pct:1.1f}%"
    
    wedges, texts, autotexts = ax.pie(
        vt_vals,
        labels=None,
        colors=colors,
        autopct=autopct_no_zeros,
        startangle=140,
        pctdistance=0.8,
        labeldistance=1.15,
    )
    ax.legend(
        wedges,
        vt_keys,
        title="Categories",
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1)
    )

    ax.set_aspect('equal')
    plt.title(f"Detection Proportions for {ip}")
    plt.tight_layout()

    return save_fig(fig, "vt_detection_pie.png")

#===============================================================#

# Comparison Bar

#===============================================================#

def create_comparison_bar(vt_rep, abuse_score, pulse_count):
    fig = plt.figure(figsize=(6,4))
    sources = ["VT Reputation", "AbuseIPDB Score", "OTX Pulses"]
    vals = [float(vt_rep or 0), float(abuse_score or 0), float(pulse_count or 0)]
    bars = plt.bar(sources, vals, color=["#86A9FA", "#29742b", "#090E53"])
    plt.title("Threat Intelligence Comparison")
    plt.ylabel("Score / Count")
    top = max(vals) if any(vals) else 1.0
    for rect, val in zip(bars, vals):
        plt.text(rect.get_x() + rect.get_width()/2, val + max(0.5, 0.02*top),
                 str(val), ha="center", va="bottom")
    return save_fig(fig, "comparison_bar.png")

#===============================================================#

# Whois Lookup graph

#===============================================================#

def build_whois_graph(ip: str, headers: dict, max_owners: int = 20):

    print("[*] Building WHOIS ownership graph from VirusTotal...")
    
    def get_vt_whois(target: str, target_type: str = "ip"):
        """Fetch WHOIS data from VirusTotal API"""
        try:
            if target_type == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:  # domain
                url = f"https://www.virustotal.com/api/v3/domains/{target}"
            
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code != 200:
                return None
            
            data = r.json().get("data", {}).get("attributes", {})
            whois_data = data.get("whois")
            
            if whois_data:
                lines = whois_data.lower().split('\n')
                for line in lines:
                    if any(keyword in line for keyword in ['registrant org:', 'org-name:', 'organization:', 'registrant:', 'owner:']):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            return parts[1].strip()  
                            owner = parts[1].strip()
                            if owner and len(owner) > 2:
                                return owner[:60]  
            
            return data.get("as_owner") or data.get("network", {}).get("name")
            
        except Exception as e:
            print(f"VT WHOIS lookup failed for {target}: {e}")
            return None
    
    ownership = {}
    
    print(f"[*] Fetching WHOIS for IP: {ip}")
    ip_owner = get_vt_whois(ip, "ip")
    if ip_owner:
        ownership[ip] = ip_owner
    
    print("[*] Fetching related domains for WHOIS lookups...")
    domains = []
    try:
        res_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
        r = requests.get(res_url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json().get("data", []) or []
            for item in data[:max_owners]:
                if isinstance(item, dict):
                    attr = item.get("attributes", {}) or {}
                    d = attr.get("host_name") or attr.get("hostname")
                    if d:
                        domains.append(d)
    except Exception as e:
        print(f"Failed to fetch resolutions: {e}")
    
    for idx, domain in enumerate(domains[:max_owners]):
        if idx > 0 and idx % 4 == 0:
            time.sleep(1)
        print(f"[*] Fetching WHOIS for domain {idx+1}/{min(len(domains), max_owners)}: {domain}")
        owner = get_vt_whois(domain, "domain")
        if owner:
            ownership[domain] = owner
    
    if not ownership:
        print("[*] No WHOIS ownership data found from VirusTotal.")
        return None
    
    G = nx.Graph()
    G.add_node(ip, node_type="IP")
    
    owners = {}
    for target, owner in ownership.items():
        owners.setdefault(owner, []).append(target)
    
    for owner, targets in owners.items():
        owner_node = f"Owner: {owner}"
        G.add_node(owner_node, node_type="Owner")
        for target in targets:
            if target == ip:
                G.add_edge(owner_node, ip, weight=2.0)
            else:
                if not G.has_node(target):
                    G.add_node(target, node_type="Domain")
                G.add_edge(owner_node, target, weight=1.0)
    
    if len(G.nodes()) <= 1:
        print("[*] Insufficient WHOIS data for graph.")
        return None
    
    fig = plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, seed=42, k=0.6)

    color_map = {
        "IP": (1.0, 0.5, 0.2, 1.0),
        "Owner": (0.3, 0.7, 0.3, 1.0),
        "Domain": (0.55, 0.35, 0.75, 1.0),
    }
    default_color = (0.7, 0.7, 0.7, 1.0)

    node_colors = []
    node_sizes = []
    for n, attr in G.nodes(data=True):
        ntype = attr.get("node_type", "Other")
        node_colors.append(color_map.get(ntype, default_color))
        if ntype == "IP":
            node_sizes.append(1800)
        elif ntype == "Owner":
            node_sizes.append(1300)
        elif ntype == "Domain":
            node_sizes.append(900)
        else:
            node_sizes.append(600)

    edge_widths = [max(0.8, d.get("weight", 1.0) * 1.5) for (_, _, d) in G.edges(data=True)]
    nx.draw_networkx_edges(G, pos, width=edge_widths, edge_color="#888888", alpha=0.6)

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, edgecolors="k", linewidths=0.8)

    labels = {n: str(n) for n in G.nodes()}
    nx.draw_networkx_labels(
        G, pos, labels,
        font_size=10, 
        font_weight="bold",
        horizontalalignment="center",
        verticalalignment="center",
        bbox=dict(facecolor='white', edgecolor='none', alpha=0.7, pad=2)
    )

    plt.title(f"WHOIS Ownership Relationships for {ip} (VirusTotal)", fontsize=14, fontweight="bold", pad=20)
    plt.axis("off")

    legend_elements = [
        Patch(facecolor=(1.0, 0.5, 0.2, 1.0), edgecolor='k', label='IP Address'),
        Patch(facecolor=(0.3, 0.7, 0.3, 1.0), edgecolor='k', label='Owner'),
        Patch(facecolor=(0.55, 0.35, 0.75, 1.0), edgecolor='k', label='Domain')
    ]
    plt.legend(handles=legend_elements, loc='upper right', framealpha=0.9)

    plt.tight_layout()
    fig.subplots_adjust(left=0.02, right=0.98, top=0.92, bottom=0.02)

    path = save_fig(fig, "whois_ownership.png")
    print(f"[+] WHOIS ownership graph saved to: {path}")
    return path

#===============================================================#

# VirusTotal Relationships list creation

#===============================================================#

def build_vt_resolution_graph(ip: str, headers: dict, max_domains: int = 150):

    print("[*] Fetching VirusTotal resolutions and building graph...")
    domains = []
    domain_detections = {} 
    
    urls = [
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    ]
    j = None
    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=20)
            if not r.ok:
                continue
            j = r.json() or {}
            if url.endswith("/resolutions"):
                data = j.get("data", []) or []
                for item in data:
                    if isinstance(item, dict):
                        attr = item.get("attributes", {}) or {}
                        d = attr.get("host_name") or attr.get("hostname") or attr.get("domain")
                        if d:
                            domains.append(d)
            else:
                data = j.get("data", {}) or {}
                attrs = data.get("attributes", {}) or {}
                res = attrs.get("resolutions") or j.get("resolutions") or []
                if isinstance(res, list):
                    for ritem in res:
                        if isinstance(ritem, dict):
                            d = ritem.get("host_name") or ritem.get("hostname") or ritem.get("host") or ritem.get("domain")
                            if d:
                                domains.append(d)
            if domains:
                break
        except Exception as e:
            continue

    domains = [d.strip() for d in domains if isinstance(d, str) and d.strip()]
    domains = list(dict.fromkeys(domains)) 
    if not domains:
        print("[*] No resolved domains found for this IP in VirusTotal.")
        return None, []

    domains = domains[:max_domains]

    print(f"[*] Fetching detection stats for {len(domains)} domains...")
    for idx, domain in enumerate(domains):
        if idx > 0 and idx % 4 == 0:
            time.sleep(1) 
        try:
            domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            r = requests.get(domain_url, headers=headers, timeout=10)
            if r.status_code == 200:
                domain_data = r.json().get("data", {}).get("attributes", {}) or {}
                stats = domain_data.get("last_analysis_stats", {}) or {}
                malicious = stats.get("malicious", 0) or 0
                suspicious = stats.get("suspicious", 0) or 0
                domain_detections[domain] = malicious + suspicious
            else:
                domain_detections[domain] = 0
        except Exception:
            domain_detections[domain] = 0

    G = nx.Graph()
    G.add_node(ip, node_type="IP")
    G.add_node("VirusTotal", node_type="Source")
    G.add_edge("VirusTotal", ip, weight=1.0)

    for d in domains:
        G.add_node(d, node_type="Domain", detections=domain_detections.get(d, 0))
        G.add_edge(ip, d, weight=1.0)

    fig = plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, seed=42, k=0.6)

    color_map = {
        "IP": (1.0, 0.5, 0.2, 1.0),
        "Source": (0.3, 0.7, 0.95, 1.0),
    }
    default_color = (0.7, 0.7, 0.7, 1.0)

    node_colors = []
    node_sizes = []
    for n, attr in G.nodes(data=True):
        ntype = attr.get("node_type", "Other")
        if ntype == "Domain":
            detections = attr.get("detections", 0)
            if detections == 0:
                node_colors.append((0.2, 0.8, 0.2, 1.0))  
            else:
                intensity = min(detections / 10.0, 1.0)
                node_colors.append((1.0, 0.2 * (1 - intensity), 0.2 * (1 - intensity), 1.0))
            node_sizes.append(900)
        else:
            node_colors.append(color_map.get(ntype, default_color))
            if ntype == "IP":
                node_sizes.append(1800)
            elif ntype == "Source":
                node_sizes.append(1300)
            else:
                node_sizes.append(600)

    edge_widths = [max(0.8, d.get("weight", 1.0) * 1.2) for (_, _, d) in G.edges(data=True)]
    nx.draw_networkx_edges(G, pos, width=edge_widths, edge_color="#888888", alpha=0.6)

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, edgecolors="k", linewidths=0.8)

    labels = {n: str(n) for n in G.nodes()}
    nx.draw_networkx_labels(
        G, pos, labels,
        font_size=10,
        font_weight="bold",
        horizontalalignment="center",
        verticalalignment="center",
        bbox=dict(facecolor='white', edgecolor='none', alpha=0.75, pad=2)
    )

    plt.title(f"Domains that resolved to {ip} (VirusTotal)", 
                fontsize=14, fontweight="bold", pad=18)
    plt.axis("off")

    legend_elements = [
        Patch(facecolor=(1.0, 0.5, 0.2, 1.0), edgecolor='k', label='IP Address'),
        Patch(facecolor=(0.3, 0.7, 0.95, 1.0), edgecolor='k', label='VirusTotal Source'),
        Patch(facecolor=(0.2, 0.8, 0.2, 1.0), edgecolor='k', label='Domain (No Detections)'),
        Patch(facecolor=(1.0, 0.2, 0.2, 1.0), edgecolor='k', label='Domain (Has Detections)')
    ]
    plt.legend(handles=legend_elements, loc='upper right', framealpha=0.9)

    plt.tight_layout()
    fig.subplots_adjust(left=0.02, right=0.98, top=0.92, bottom=0.02)

    path = save_fig(fig, "vt_resolutions.png")
    print(f"[+] VT resolutions graph saved to: {path}")
    return path, domains

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

#===============================================================#

# Folium map creation

#===============================================================#

def build_folium_map(ip, vt_data, vt_asn, vt_country, vt_rep, vt_malicious,
                     abuse_score, abuse_total_reports, pulse_count):
    print("[*] Building interactive folium map (HTML)...")
    lat = vt_data.get("latitude") or None
    lon = vt_data.get("longitude") or None

    if lat is None or lon is None:
        lat = None; lon = None
        try:
            rgeo = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if rgeo.ok:
                jr = rgeo.json()
                lat = jr.get("lat"); lon = jr.get("lon")
        except Exception:
            pass

    try:
        lat = float(lat) if lat is not None else 0.0
        lon = float(lon) if lon is not None else 0.0
    except Exception:
        lat, lon = 0.0, 0.0

    m = folium.Map(location=[lat, lon], zoom_start=3 if (lat, lon) != (0.0, 0.0) else 2)
    popup_html = f"""
<b>IP:</b> {ip}<br>
<b>ASN:</b> {vt_asn}<br>
<b>Country (VT):</b> {vt_country}<br>
<b>Reputation:</b> {vt_rep}<br>
<b>VT malicious:</b> {vt_malicious}<br>
<b>Abuse Score:</b> {abuse_score} (reports {abuse_total_reports})<br>
<b>OTX pulses:</b> {pulse_count}
"""
    folium.Marker([lat, lon], popup=popup_html,
                  icon=folium.Icon(color="red" if (vt_malicious or 0) > 0 or (abuse_score or 0) > 50 else "green")
                  ).add_to(m)
    folium.CircleMarker([lat, lon], radius=8 + max(0, (vt_malicious or 0)*2), fill=True,
                        color="red" if (vt_malicious or 0) > 0 else "green", fill_opacity=0.6).add_to(m)

    map_path = os.path.join(tmpdir, f"{ip}_interactive_map.html")
    m.save(map_path)
    print(f"[+] Interactive map saved to: {map_path}")
    return map_path

#===============================================================#

# Splash screen

#===============================================================#

def splash_screen():
    print("    ███        ▄█    █▄       ▄████████    ▄████████    ▄████████     ███      ▄█    █▄   ▄█   ▄███████▄   ")
    print("▀█████████▄   ███    ███     ███    ███   ███    ███   ███    ███ ▀█████████▄ ███    ███ ███  ██▀     ▄██   ")
    print("   ▀███▀▀██   ███    ███     ███    ███   ███    █▀    ███    ███    ▀███▀▀██ ███    ███ ███▌       ▄███▀  ")
    print("    ███   ▀  ▄███▄▄▄▄███▄▄  ▄███▄▄▄▄██▀  ▄███▄▄▄       ███    ███     ███   ▀ ███    ███ ███▌  ▀█▀▄███▀▄▄    ")
    print("    ███     ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ▀███████████     ███     ███    ███ ███▌   ▄███▀   ▀    ")
    print("    ███       ███    ███   ▀███████████   ███    █▄    ███    ███     ███     ███    ███ ███  ▄███▀        ")
    print("    ███       ███    ███     ███    ███   ███    ███   ███    ███     ███     ███    ███ ███  ███▄     ▄█ ")
    print("   ▄████▀     ███    █▀      ███    ███   ██████████   ███    █▀     ▄████▀    ▀██████▀  █▀    ▀████████▀   ")
    print("        ThreatViz v1         ███    ███   by @aabaniel, @biacora, @Ishlalalay                  \n\n")

# "Font" used and origin:
# patorjk.com - Text to ASCII Art Generator - Delta Corps Priest 1

#===============================================================#

# Main Function

#===============================================================#

def main():
    while True:
        os.system('cls')
        splash_screen()
        try:
            ip = input("Enter an IPv4 address to analyze (or type 'exit' to quit): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if not ip:
            continue
        if ip.lower() == "exit":
            break

        # temp folder
        prepare_tmpdir(ip)

        # fetch data
        vt_tuple = fetch_virustotal(ip, HEADERS_VT)
        (
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
        ) = vt_tuple

        abuse_score, abuse_total_reports, abuse_country = fetch_abuseipdb(ip, HEADERS_ABUSE)
        pulse_count, otx_tags, otx_malware_families, otx_geo = fetch_otx(ip, HEADERS_OTX)


        # charts
        create_vt_detection_bar(ip, vt_keys, vt_vals)
        create_vt_pie(ip, vt_keys, vt_vals)
        create_comparison_bar(vt_rep, abuse_score, pulse_count)

        # WHOIS ownership graph
        whois_graph_path = build_whois_graph(ip, HEADERS_VT)
        if whois_graph_path:
            print(f"[+] WHOIS ownership graph saved to: {whois_graph_path}")
        else:
            print("[*] No WHOIS ownership graph generated.")

        # VT resolutions graph
        vt_res_path, vt_domains = build_vt_resolution_graph(ip, HEADERS_VT)
        if vt_res_path:
            print(f"[+] VT resolutions graph saved to: {vt_res_path}")
            print(f"[+] Found {len(vt_domains)} domains resolved to {ip}")
        else:
            print("[*] No VT resolutions graph generated.")

        # AbuseIPDB category graph
        abuse_cat_path = create_abuseipdb_category_graph(ip, HEADERS_ABUSE)
        if abuse_cat_path:
            print(f"[+] AbuseIPDB category graph saved to: {abuse_cat_path}")
        else:
            print("[*] No AbuseIPDB category graph generated.")

        # folium map
        build_folium_map(
            ip, vt_data, vt_asn, vt_country, vt_rep, vt_malicious,
            abuse_score, abuse_total_reports, pulse_count
        )

        output_to_csv(
            ip, vt_data, vt_stats, vt_asn, vt_country, vt_rep, vt_malicious,
            abuse_score, abuse_total_reports, abuse_country,
            pulse_count, otx_tags, otx_malware_families, otx_geo,
            related_domains
        )

        print("\n--- Done ---")
        print("Files saved in:", tmpdir)
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()