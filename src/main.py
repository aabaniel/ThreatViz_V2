
#===============================================================#

# Personal Project: Threat Intelligence through APIs Visualization
# Aaron Abaniel || aabaniel

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