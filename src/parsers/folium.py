
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