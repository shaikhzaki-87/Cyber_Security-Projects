import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cve(product, version):
    if not product or not version:
        return []

    query = f"{product} {version}"
    params = {"keywordSearch": query, "resultsPerPage": 5}

    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] CVE lookup failed for {query}: {e}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]

        desc = ""
        for d in cve.get("descriptions", []):
            if d["lang"] == "en":
                desc = d["value"]
                break

        score = None
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            score = m["baseScore"]
            severity = m["baseSeverity"]
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]["cvssData"]
            score = m["baseScore"]
            severity = m["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]["cvssData"]
            score = m["baseScore"]
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

        results.append({
            "cve_id": cve_id,
            "score": score,
            "severity": severity,
            "summary": desc[:150]
        })

    return results


def enrich_scan_results(scan_data):
    for host, hostdata in scan_data.items():
        for port_entry in hostdata["ports"]:
            product = port_entry.get("product")
            version = port_entry.get("version")
            if product and version:
                print(f"[*] Looking up CVEs for {product} {version} ...")
                port_entry["cves"] = search_cve(product, version)
                time.sleep(2)
            else:
                port_entry["cves"] = []
    return scan_data
