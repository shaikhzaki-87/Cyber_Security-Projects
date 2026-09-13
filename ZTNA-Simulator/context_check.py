from datetime import datetime

BUSINESS_HOURS = range(8, 20)  # 8 AM - 8 PM
KNOWN_LOCATIONS = ["India", "Germany"]

def check_context(location):
    hour = datetime.now().hour
    is_business_hours = hour in BUSINESS_HOURS
    is_known_location = location in KNOWN_LOCATIONS
    return {
        "business_hours": is_business_hours,
        "known_location": is_known_location,
        "current_hour": hour
    }
