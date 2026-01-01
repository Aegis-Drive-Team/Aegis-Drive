import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

API_KEY = os.getenv('ABUSEIPDB_API_KEY')

def api_query(input_ips, verbose=False):
    """
    Query AbuseIPDB API for one or multiple IP addresses.
    Returns a list of formatted records.
    """
    if isinstance(input_ips, str):
        input_ips = [input_ips]

    records = []
    for ip in input_ips:
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': verbose}
            headers = {'Accept': 'application/json', 'Key': API_KEY}

            response = requests.get(url, headers=headers, params=querystring)
            response.raise_for_status()

            decoded_response = response.json()
            print(f"[DEBUG] API raw response for {ip}:", decoded_response)  # <-- ADD THIS

            record = convert_data(decoded_response)
            records.append(record)
        except Exception as e:
            print(f"[ERROR] Failed to query {ip}: {e}")
            records.append({"ip": ip, "error": str(e)})

    return records

def api_query_search(input_ips, verbose=False, max_report_age=90, role="user"):
    """
    Query AbuseIPDB API for one or multiple IP addresses.
    Returns a list of formatted records.
    Non-admin users only see public reports.
    """
    if isinstance(input_ips, str):
        input_ips = [input_ips]

    records = []
    for ip in input_ips:
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {'ipAddress': ip, 'maxAgeInDays': str(max_report_age), 'verbose': verbose}
            headers = {'Accept': 'application/json', 'Key': API_KEY}

            response = requests.get(url, headers=headers, params=querystring)
            response.raise_for_status()

            decoded_response = response.json()
            print(f"[DEBUG] API raw response for {ip}:", decoded_response)

            record = convert_data_search(decoded_response)

            # Filter reports for non-admins
            if "reports" in record and role != "admin":
                record["reports"] = [
                    r for r in record["reports"] if r.get("public", True)
                ]

            records.append(record)
        except Exception as e:
            print(f"[ERROR] Failed to query {ip}: {e}")
            records.append({"ip": ip, "error": str(e)})

    return records


def convert_data_search(api_data):
    """
    Converts API data into a format suitable for Flask display.
    """
    record = {"ip": api_data["data"]["ipAddress"]}
    if api_data["data"].get("isPublic", False):
        record.update(api_data["data"])
    else:
        # Internal/private IP, no external data available
        record.update({
            "hostname": "",
            "domain": "",
            "abuseConfidenceScore": 0
        })
    return record

def convert_data(api_response):
    data = api_response.get("data", {})

    return {
        "ip": data.get("ipAddress", "N/A"),
        "hostname": data.get("hostnames")[0] if data.get("hostnames") else "N/A",
        "domain": data.get("domain", "N/A"),
        "abuseConfidenceScore": data.get("abuseConfidenceScore", "N/A"),
        "isp": data.get("isp", "N/A"),
        "usageType": data.get("usageType", "N/A"),
        "asn": data.get("asn", "N/A"),
        "countryCode": data.get("countryCode", "N/A"),
        "city": data.get("city", "N/A"),
        "region": data.get("region", "N/A")
    }

def fetch_blacklist(limit=100, confidence_min=90):
    """
    Fetch a list of blacklisted IPs from AbuseIPDB.
    """
    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    querystring = {'limit': limit, 'confidenceMinimum': confidence_min}
    headers = {'Accept': 'application/json', 'Key': API_KEY}

    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()
        decoded_response = response.json()

        if 'data' in decoded_response:
            ip_list = [item['ipAddress'] for item in decoded_response['data']]
            print(f"[INFO] Fetched {len(ip_list)} IPs from blacklist.")
            return ip_list
        else:
            print("[WARN] No data field in blacklist response.")
            return []
    except Exception as e:
        print(f"[ERROR] Failed to fetch blacklist: {e}")
        return []

def report_to_ipabusedb(report_ip : str, comment : str, categories : list() = [15], timestamp : str = None):
    """ generates a report to ipabusedb, default category is 15 = Hacking """
    # adjusted code from IPabuseDB API docs: https://docs.abuseipdb.com/#report-endpoint
    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/report'

    # String holding parameters to pass in json format
    params = {
        'ip': report_ip,
        'categories': str(categories)[1:-1], # categories input format a string of comma seperated values "19,15"
        'comment': comment
        # can include timestamp
    }
    if timestamp is not None:
        params['timestamp'] = timestamp

    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    return requests.request(method='POST', url=url, headers=headers, params=params)

# Optional CLI testing
def main():
    while True:
        user_input = input("Enter IP(s) (comma-separated) or 'quit': ").strip()
        if user_input.lower() == "quit":
            break
        ips = [ip.strip() for ip in user_input.split(',') if ip.strip()]
        if ips:
            results = api_query(ips)
            for r in results:
                print(json.dumps(r, indent=4))
        else:
            print("No valid IPs entered.")

if __name__ == "__main__":
    print("hey")
    main()
