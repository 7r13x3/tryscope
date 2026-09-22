"""
TryScope - Map link generator
Produces URLs for Google Maps, OpenStreetMap, and static preview.
No API keys required.
"""


def google_maps_link(lat: float, lon: float) -> str:
    if not lat and not lon:
        return ""
    return f"https://www.google.com/maps?q={lat},{lon}"


def openstreetmap_link(lat: float, lon: float) -> str:
    if not lat and not lon:
        return ""
    return f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}"


def osm_static_url(lat: float, lon: float,
                   width: int = 600, height: int = 400) -> str:
    """Free static map (no key required)."""
    if not lat and not lon:
        return ""
    return (
        f"https://staticmap.openstreetmap.de/staticmap.php"
        f"?center={lat},{lon}&zoom=10&size={width}x{height}"
        f"&maptype=mapnik&markers={lat},{lon},red-pushpin"
    )


def all_links(lat: float, lon: float) -> dict:
    return {
        "google_maps":  google_maps_link(lat, lon),
        "osm":          openstreetmap_link(lat, lon),
        "osm_static":   osm_static_url(lat, lon),
    }
