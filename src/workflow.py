#===============================================================#

# Save figures as files

#===============================================================#

def save_fig(fig, name, dpi=150):
    path = os.path.join(tmpdir, name)
    fig.savefig(path, bbox_inches="tight", dpi=dpi)
    plt.close(fig)
    return path


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
