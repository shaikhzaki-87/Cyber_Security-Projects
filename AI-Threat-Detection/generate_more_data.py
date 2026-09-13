import subprocess
import time
import random

# Generate more normal successful logins at varied intervals
print("[*] Generating additional normal login traffic...")
for i in range(15):
    subprocess.run(
        ["sshpass", "-p", "kali", "ssh", "-o", "StrictHostKeyChecking=no", "kali@127.0.0.1", "exit"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(random.uniform(2, 5))

print("[+] Done generating normal traffic.")
