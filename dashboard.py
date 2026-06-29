import json
import os
import webbrowser
from collections import Counter
from flask import Flask, jsonify, render_template_string

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
EVE_LOG = os.path.join(LOG_DIR, "eve.json")

app = Flask(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Suricata IDS Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
      body { font-family: Arial, sans-serif; margin: 20px; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 24px; }
      .panel { padding: 18px; border: 1px solid #ccc; border-radius: 8px; background: #fff; }
      h1, h2 { margin-top: 0; }
      table { width: 100%; border-collapse: collapse; }
      th, td { text-align: left; padding: 8px; border-bottom: 1px solid #eee; }
      .small { font-size: 0.9rem; color: #555; }
    </style>
  </head>
  <body>
    <h1>Suricata IDS Dashboard</h1>
    <p class="small">Live alert summaries from <code>logs/eve.json</code>. Refresh the page to reload data.</p>
    <div class="grid">
      <div class="panel">
        <h2>Alert Signatures</h2>
        <canvas id="signatureChart"></canvas>
      </div>
      <div class="panel">
        <h2>Top Source IPs</h2>
        <canvas id="sourceChart"></canvas>
      </div>
    </div>
    <div class="panel" style="margin-top: 24px;">
      <h2>Recent Alerts</h2>
      <table>
        <thead><tr><th>Time</th><th>Signature</th><th>Source</th><th>Dest</th><th>Severity</th></tr></thead>
        <tbody id="recentAlerts"></tbody>
      </table>
    </div>
    <script>
      async function fetchData() {
        const summary = await fetch('/api/summary').then(r => r.json());
        const recent = await fetch('/api/recent').then(r => r.json());

        const signatureCtx = document.getElementById('signatureChart').getContext('2d');
        const sourceCtx = document.getElementById('sourceChart').getContext('2d');

        new Chart(signatureCtx, {
          type: 'bar',
          data: {
            labels: summary.signatureLabels,
            datasets: [{ label: 'Alerts', data: summary.signatureCounts, backgroundColor: 'rgba(220,53,69,0.7)' }]
          },
          options: { responsive: true, plugins: { legend: { display: false } } }
        });

        new Chart(sourceCtx, {
          type: 'bar',
          data: {
            labels: summary.sourceLabels,
            datasets: [{ label: 'Alerts', data: summary.sourceCounts, backgroundColor: 'rgba(54,162,235,0.7)' }]
          },
          options: { responsive: true, plugins: { legend: { display: false } } }
        });

        const recentBody = document.getElementById('recentAlerts');
        recentBody.innerHTML = '';
        for (const item of recent) {
          const row = document.createElement('tr');
          row.innerHTML = `
            <td>${item.timestamp || 'n/a'}</td>
            <td>${item.signature}</td>
            <td>${item.src_ip}</td>
            <td>${item.dest_ip}</td>
            <td>${item.severity}</td>
          `;
          recentBody.appendChild(row);
        }
      }
      fetchData();
    </script>
  </body>
</html>
"""


def load_alerts():
    alerts = []
    if not os.path.exists(EVE_LOG):
        return alerts
    with open(EVE_LOG, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


def summarize_alerts(alerts, top_n=10):
    signature_counts = Counter(event.get("alert", {}).get("signature", "unknown") for event in alerts)
    source_counts = Counter(event.get("src_ip", "unknown") for event in alerts)

    return {
        "signatureLabels": [label for label, _ in signature_counts.most_common(top_n)],
        "signatureCounts": [count for _, count in signature_counts.most_common(top_n)],
        "sourceLabels": [label for label, _ in source_counts.most_common(top_n)],
        "sourceCounts": [count for _, count in source_counts.most_common(top_n)],
    }


def recent_alerts(alerts, limit=20):
    recent = []
    for event in alerts[-limit:]:
        recent.append({
            "timestamp": event.get("timestamp", ""),
            "signature": event.get("alert", {}).get("signature", "unknown"),
            "src_ip": event.get("src_ip", "unknown"),
            "dest_ip": event.get("dest_ip", "unknown"),
            "severity": event.get("alert", {}).get("severity", 0),
        })
    return list(reversed(recent))


@app.route("/")
def dashboard():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/summary")
def api_summary():
    alerts = load_alerts()
    return jsonify(summarize_alerts(alerts))


@app.route("/api/recent")
def api_recent():
    alerts = load_alerts()
    return jsonify(recent_alerts(alerts))


if __name__ == "__main__":
    url = "http://127.0.0.1:5000"
    print(f"Opening dashboard at {url}")
    webbrowser.open(url)
    app.run(host="0.0.0.0", port=5000)
