from pathlib import Path
import re
from OTXv2 import OTXv2
from collections import Counter
import os
import time
import ipaddress
import json
import requests
import csv

# ===== CONFIG =====
OTX_API_KEY = os.getenv("OTX_API_KEY")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

MIN_HITS_FOR_OTX = 5
TOP_N = 20
ALERT_LEVELS = ["HIGH", "CRITICAL"]

otx = OTXv2(OTX_API_KEY)
cache = {}

apache_logs_ubuntu = Path("/var/log/apache2/access.log")
apache_logs_centos = Path("/var/log/httpd/access_log")
nginx_logs = Path("/var/log/nginx/access.log")


# ===== CACHE =====
def load_cache():
    global cache
    if Path("cache.json").exists():
        cache = json.loads(Path("cache.json").read_text())
    else:
        cache = {}

def save_cache():
    Path("cache.json").write_text(json.dumps(cache))


# ===== TELEGRAM =====
def send_telegram(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message
        }, timeout=5)
    except Exception:
        pass


# ===== LOG =====
def get_log_files():
    files = [
        apache_logs_ubuntu,
        apache_logs_centos,
        nginx_logs,
        Path("/var/log/auth.log"),
    ]
    return [f for f in files if f.exists()]


def read_logs():
    for file in get_log_files():
        with file.open(errors="ignore") as f:
            for line in f:
                yield line


def extract_ip(line):
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
    if not match:
        return None

    ip = match.group(0)
    try:
        ipaddress.ip_address(ip)
        return ip
    except:
        return None


def is_suspicious(line):
    high_risk = ["sqlmap", "nmap"]
    auth = ["Failed password", "Invalid user"]
    server_error = ["500"]

    if any(p.lower() in line.lower() for p in high_risk):
        return True
    if any(p.lower() in line.lower() for p in auth):
        return True
    if any(p in line for p in server_error):
        return True

    return False


# ===== CTI =====
def check_ip_reputation(ip):
    for _ in range(3):
        try:
            result = otx.get_indicator_details_by_section("IPv4", ip, "general")
            return result.get("pulse_info", {}).get("count", 0)
        except Exception:
            time.sleep(1)
    return 0


def check_ip_cached(ip):
    if ip in cache:
        return cache[ip]

    score = check_ip_reputation(ip)
    cache[ip] = score
    return score


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False


# ===== PROCESS =====
def process_logs():
    ip_counter = Counter()
    samples = {}

    for line in read_logs():
        if not is_suspicious(line):
            continue

        ip = extract_ip(line)
        if ip and is_public_ip(ip):
            ip_counter[ip] += 1

            if ip not in samples:
                samples[ip] = line.strip()

    return ip_counter, samples


def classify(score, count):
    if score > 0 and count > 10:
        return "CRITICAL"
    elif score > 0:
        return "HIGH"
    elif count > 20:
        return "MEDIUM"
    else:
        return "LOW"


# ===== MAIN =====
def main():
    load_cache()

    ip_data, samples = process_logs()

    results = []

    for ip, count in ip_data.most_common(TOP_N):

        # skip kecil biar hemat API
        if count < MIN_HITS_FOR_OTX:
            score = 0
        else:
            score = check_ip_cached(ip)

        level = classify(score, count)

        print(f"[{level}] {ip} | hits={count} | intel={score}")
        print(f"  sample: {samples[ip]}")

        results.append([ip, count, score, level, samples[ip]])

        # ===== TELEGRAM ALERT =====
        if level in ALERT_LEVELS:
            send_telegram(
                f"[{level}] Suspicious IP Detected\n"
                f"IP: {ip}\n"
                f"Hits: {count}\n"
                f"Intel: {score}\n"
                f"Sample: {samples[ip]}"
            )

    # ===== SAVE CSV (optional) =====
    with open("report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Hits", "Intel", "Level", "Sample"])
        writer.writerows(results)

    save_cache()


if __name__ == "__main__":
    load_cache()
    while True:
        main()
        save_cache()
        time.sleep(300)  # 5 menit