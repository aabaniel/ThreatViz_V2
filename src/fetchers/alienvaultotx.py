
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
