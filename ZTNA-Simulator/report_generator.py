from jinja2 import Environment, FileSystemLoader

def generate_report(results, output_file="ztna_report.html"):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("ztna_report.html")

    html = template.render(results=results, total=len(results))

    with open(output_file, "w") as f:
        f.write(html)

    print(f"[+] Report saved: {output_file}")
