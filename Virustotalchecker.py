import requests

API_KEY = 'YOUR_API_KEY'  # Replace with your free API key from VirusTotal
VT_URL = 'https://www.virustotal.com/api/v3/files/'

def check_hash(file_hash):
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(VT_URL + file_hash, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"Malicious: {stats['malicious']}")
        print(f"Harmless: {stats['harmless']}")
        print(f"Suspicious: {stats['suspicious']}")
    else:
        print("Invalid hash or issue with request.")

# Example usage
file_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test string hash
check_hash(file_hash)
