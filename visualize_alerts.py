import json
import os
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
EVE_LOG = os.path.join(LOG_DIR, "eve.json")


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


def count_by_signature(alerts):
    return Counter(event.get("alert", {}).get("signature", "unknown") for event in alerts)


def count_by_src_ip(alerts):
    return Counter(event.get("src_ip", "unknown") for event in alerts)


def plot_top_counts(counts, title, filename):
    items = counts.most_common(10)
    if not items:
        print("No alerts found to plot.")
        return

    labels, values = zip(*items)
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(labels, values, color="tab:red")
    ax.set_title(title)
    ax.set_ylabel("Count")
    ax.set_xticklabels(labels, rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(LOG_DIR, filename))
    plt.close(fig)
    print(f"Saved visualization to {filename}")


def main():
    alerts = load_alerts()
    if not alerts:
        print("No alert data available in eve.json")
        return

    plot_top_counts(count_by_signature(alerts), "Top 10 Alert Signatures", "top_signatures.png")
    plot_top_counts(count_by_src_ip(alerts), "Top 10 Source IPs", "top_source_ips.png")


if __name__ == "__main__":
    main()
