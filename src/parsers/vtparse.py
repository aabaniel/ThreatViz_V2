
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

