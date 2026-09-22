"""
TryScope - Interactive map HTML snippet (Leaflet)
Generates a self-contained map to embed in the HTML report.
"""


def render(lat: float, lon: float, label: str,
           color: str = "#4cc9f0") -> str:
    if not lat and not lon:
        return ""

    return f"""
<div id="tryscope-map" style="height: 360px; border-radius: 8px;
     border: 1px solid #2a2f3f; margin-bottom: 20px;"></div>
<link rel="stylesheet"
      href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
  var map = L.map('tryscope-map').setView([{lat}, {lon}], 10);
  L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',
    {{ attribution: '&copy; OpenStreetMap' }}).addTo(map);
  L.marker([{lat}, {lon}])
    .addTo(map)
    .bindPopup('<b>{label}</b>').openPopup();
</script>
"""
