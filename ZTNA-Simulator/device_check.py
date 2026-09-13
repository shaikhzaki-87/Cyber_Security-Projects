import random

def check_device_posture(device_id):
    # Simulated checks (in a real ZTNA setup, an endpoint agent reports these)
    return {
        "os_patched": random.choice([True, True, True, False]),
        "antivirus_active": random.choice([True, True, True, False]),
        "disk_encrypted": random.choice([True, True, True, False]),
    }

def is_device_healthy(posture):
    return all(posture.values())
