import re
import pandas as pd
from datetime import datetime

LOG_PATH = "auth_export.log"

def parse_auth_log(path=LOG_PATH):
    pattern = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*sshd.*?'
        r'(?P<status>Failed|Accepted) password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    records = []
    current_year = datetime.now().year

    with open(path, 'r', errors='ignore') as f:
        for line in f:
            m = pattern.search(line)
            if m:
                d = m.groupdict()
                ts_str = f"{current_year} {d['month']} {d['day']} {d['time']}"
                try:
                    ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                except ValueError:
                    continue
                records.append({
                    "timestamp": ts,
                    "status": d["status"],
                    "user": d["user"],
                    "ip": d["ip"]
                })

    return pd.DataFrame(records)


if __name__ == "__main__":
    df = parse_auth_log()
    print(f"[+] Parsed {len(df)} login events")
    print(df.head(15))
