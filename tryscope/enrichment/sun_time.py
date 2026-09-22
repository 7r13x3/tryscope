"""
TryScope - Local time & sunrise/sunset computation
Uses only Python stdlib (no API needed).
"""
from datetime import datetime, timezone, timedelta


def compute_local_time(timezone_name: str, utc_offset: str = "") -> dict:
    """
    Compute the current local time from a timezone string.
    utc_offset format: "+01:00" or "-05:00" or "+0000"
    """
    result = {
        "local_time":   "",
        "utc_offset":   utc_offset or "",
        "is_evening":   False,
        "is_night":     False,
        "is_business":  False,
    }

    # try zoneinfo first (Python 3.9+)
    try:
        from zoneinfo import ZoneInfo
        if timezone_name:
            now = datetime.now(ZoneInfo(timezone_name))
            result["local_time"] = now.strftime("%Y-%m-%d %H:%M:%S")
            hour = now.hour
            result["is_evening"]  = 17 <= hour < 21
            result["is_night"]    = hour < 6 or hour >= 21
            result["is_business"] = 9 <= hour < 18 and now.weekday() < 5
            return result
    except Exception:
        pass

    # fallback: use UTC offset
    if utc_offset:
        try:
            sign = 1 if utc_offset[0] == "+" else -1
            parts = utc_offset.lstrip("+-").replace(":", "")
            hours = int(parts[:2])
            minutes = int(parts[2:4]) if len(parts) >= 4 else 0
            delta = timedelta(hours=hours, minutes=minutes) * sign
            now = datetime.now(timezone.utc) + delta
            result["local_time"] = now.strftime("%Y-%m-%d %H:%M:%S")
            hour = now.hour
            result["is_evening"]  = 17 <= hour < 21
            result["is_night"]    = hour < 6 or hour >= 21
            result["is_business"] = 9 <= hour < 18 and now.weekday() < 5
        except Exception:
            pass

    return result


def day_phase(is_night: bool, is_evening: bool, is_business: bool) -> str:
    """Return a human label for the current phase of the day."""
    if is_night:
        return "Night"
    if is_evening:
        return "Evening"
    if is_business:
        return "Business hours"
    return "Daytime"
