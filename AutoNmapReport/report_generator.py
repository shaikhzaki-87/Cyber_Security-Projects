from jinja2 import Environment, FileSystemLoader
from datetime import datetime

def generate_report(scan_data, output_file="report.html"):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html")

    for target, hostdata in scan_data.items():
        os_name = hostdata["os"][0]["name"] if hostdata["os"] else "Unknown"

        html = template.render(
            target=target,
            os_name=os_name,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ports=hostdata["ports"]
        )

        with open(output_file, "w") as f:
            f.write(html)

        print(f"[+] Report saved: {output_file}")
