import argparse
import json
import os
import subprocess
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
SURICATA_YAML = os.path.join(BASE_DIR, "config", "suricata.yaml")
EVE_LOG = os.path.join(LOG_DIR, "eve.json")
RESPONSE_FILE = os.path.join(LOG_DIR, "response.log")


def get_interface_argument():
    parser = argparse.ArgumentParser(description="Run Suricata and monitor eve.json for alerts")
    parser.add_argument(
        "-i", "--interface",
        default=os.environ.get("SURICATA_INTERFACE", "eth0"),
        help="Network interface name to monitor (or set SURICATA_INTERFACE)"
    )
    return parser.parse_args()


def block_ip_windows(src_ip):
    if not src_ip:
        return
    rule_name = f"Suricata Block {src_ip}"
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={src_ip}"
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"Firewall block rule created for {src_ip}")
    except subprocess.CalledProcessError as exc:
        print(f"Failed to block {src_ip}: {exc.stderr.strip()}")


def respond_to_alert(alert):
    src_ip = alert.get("src_ip")
    dest_ip = alert.get("dest_ip")
    proto = alert.get("proto")
    signature = alert.get("alert", {}).get("signature")
    severity = alert.get("alert", {}).get("severity", 0)

    if not src_ip:
        return

    if severity >= 3:
        action = f"BLOCK {src_ip}"
        block_ip_windows(src_ip)
    else:
        action = f"MONITOR {src_ip}"

    message = (
        f"[{datetime.now().isoformat()}] {action} - "
        f"src={src_ip} dst={dest_ip} proto={proto} rule={signature} severity={severity}\n"
    )
    with open(RESPONSE_FILE, "a", encoding="utf-8") as f:
        f.write(message)

    print(message.strip())


def tail_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def parse_eve_line(line):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def start_suricata(interface):
    os.makedirs(LOG_DIR, exist_ok=True)
    command = [
        "suricata",
        "-c",
        SURICATA_YAML,
        "-i",
        interface
    ]
    print(f"Starting Suricata on interface: {interface}")
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def monitor_alerts():
    if not os.path.exists(EVE_LOG):
        print(f"Waiting for eve.json to be created at {EVE_LOG}")
        while not os.path.exists(EVE_LOG):
            time.sleep(1)

    for line in tail_file(EVE_LOG):
        event = parse_eve_line(line)
        if not event:
            continue
        if event.get("event_type") != "alert":
            continue

        print(f"Detected alert: {event.get('alert', {}).get('signature')} from {event.get('src_ip')}")
        respond_to_alert(event)


def main():
    args = get_interface_argument()
    suricata_proc = start_suricata(args.interface)
    try:
        monitor_alerts()
    except KeyboardInterrupt:
        print("Stopping monitoring...")
    finally:
        suricata_proc.terminate()
        suricata_proc.wait()


if __name__ == "__main__":
    main()
