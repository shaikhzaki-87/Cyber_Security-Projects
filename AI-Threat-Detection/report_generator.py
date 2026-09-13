from jinja2 import Environment, FileSystemLoader

def generate_report(df, output_file="anomaly_report.html"):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("anomaly_report.html")

    rows = df.to_dict(orient="records")
    anomaly_count = (df["verdict"] == "ANOMALY").sum()

    html = template.render(rows=rows, total=len(df), anomaly_count=anomaly_count)

    with open(output_file, "w") as f:
        f.write(html)

    print(f"[+] Report saved: {output_file}")
