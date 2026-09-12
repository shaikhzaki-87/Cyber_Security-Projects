












import nmap

def run_scan(target_ip, ports="1-1000"):
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {target_ip} on ports {ports} ...")
    scanner.scan(target_ip, ports, arguments="-sV -O")

    results = {}
    for host in scanner.all_hosts():
        results[host] = {
            "state": scanner[host].state(),
            "os": scanner[host].get("osmatch", []),
            "ports": []
        }
        for proto in scanner[host].all_protocols():
            ports_list = scanner[host][proto].keys()
            for port in sorted(ports_list):
                port_info = scanner[host][proto][port]
                results[host]["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": port_info.get("state"),
                    "service": port_info.get("name"),
                    "product": port_info.get("product"),
                    "version": port_info.get("version")
                })
    return results


if __name__ == "__main__":
    from cve_lookup import enrich_scan_results
    from report_generator import generate_report

    target = input("Enter target IP (Metasploitable2 VM): ").strip()
    data = run_scan(target)
    data = enrich_scan_results(data)
    generate_report(data)
    print("[+] Done! Open report.html in a browser.")
