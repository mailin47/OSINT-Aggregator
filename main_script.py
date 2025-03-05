import spacy
import requests
import whois
import shodan
import json
from PIL import Image
import exiftool
import sqlite3
from datetime import datetime

# Validate input types
def is_valid_ip(ip):
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def is_valid_url(url):
    return url.startswith(("http://", "https://"))

def is_valid_hash(hash_str):
    return len(hash_str) in [32, 40, 64] and all(c in "0123456789abcdef" for c in hash_str.lower())

# Fetch data from APIs

#ABUSEIPDB
def fetch_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": 'SHODAN_API'}
    try:
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return str(e)
#VIRUSTOTAL
def fetch_virustotal(data):
    url = f"https://www.virustotal.com/api/v3/{data}"
    headers = {"x-apikey": 'VIRUSTOTAL API'}
    try:
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return str(e)

def fetch_social_media(username):
    # Example check for Twitter
    url = f"https://twitter.com/{username}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return f"Username {username} found on Twitter"
        else:
            return f"Username {username} not found on Twitter"
    except Exception as e:
        return str(e)

def extract_image_metadata(image_path):
    with exiftool.ExifToolHelper() as et:
        metadata = et.get_metadata(image_path)
    return metadata

        # Extract only relevant fields
        useful_keys = ["File:FileName", "File:FileSize", "EXIF:Make", "EXIF:Model", "EXIF:DateTimeOriginal",
                       "EXIF:GPSLatitude", "EXIF:GPSLongitude"]
        filtered_metadata = {key: metadata[0][key] for key in useful_keys if key in metadata[0]}
        
        return filtered_metadata if filtered_metadata else {"error": "No useful metadata found"}
    
    except Exception as e:
        return {"error": f"Failed to extract metadata: {e}"}

def is_valid_username(username: str) -> bool:
    # Add your username validation logic here
    return bool(username and len(username) >= 3)

SHODAN_API_KEY =  'SHODAN_API'
ABUSEIPDB_API_KEY = 'ABUSEIPDB_API'

def get_ip_info(ip: str) -> dict:
    """Fetches IP intelligence from Shodan and AbuseIPDB."""
    info = {}
    
    # Shodan Lookup
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        shodan_data = api.search(ip)
        info['Host IP'] = shodan_data.get("ip_str")
        info['HOSTNAME'] = shodan_data.get("hostnames")
        info['PORTS'] = shodan_data.get("ports")
        info['OS'] = shodan_data.get("os")
        info['ORG'] = shodan_data.get("org")
        info['ISP'] = shodan_data.get("isp")
      # info['VULNERABILE TO'] = shodan_data.get("vulns") not available for free tier
        info['TAGS'] = shodan_data.get("tags")
        
    except Exception as e:
        info['shodan_error'] = str(e)

    # AbuseIPDB Lookup
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        response = requests.get(url, headers=headers)
        info['abuseipdb'] = response.json()
    except Exception as e:
        info['abuseipdb_error'] = str(e)

# Database operations
def store_data(input_data, result):
    conn = sqlite3.connect("osint_results.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS results 
                 (input TEXT, result TEXT, timestamp TEXT)''')
    c.execute("INSERT INTO results (input, result, timestamp) VALUES (?, ?, ?)",
              (input_data, json.dumps(result), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

#whois lookup
def get_domain_info(domain: str) -> dict:
    """Fetches WHOIS information for a given domain."""
    info = {}
    try:
        domain_data = whois.whois(domain)
        info['domain_name'] = domain_data.domain_name
        info['registrar'] = domain_data.registrar
        info['registrant'] = domain_data.registrant
        info['creation_date'] = domain_data.creation_date
        info['expiration_date'] = domain_data.expiration_date
        info['name_servers'] = domain_data.name_servers
        info['Emails from WHOIS data'] = domain_data.emails
    except Exception as e:
        info['error'] = str(e)
    
    return info


def check_username_presence(username: str) -> dict:
    """Checks the presence of a username on popular social media platforms."""
    info = {}
    social_media_sites = [
        f"https://www.facebook.com/{username}",
        f"https://www.twitter.com/{username}",
        f"https://www.instagram.com/{username}",
        f"https://www.linkedin.com/in/{username}",
        f"https://github.com/{username}"
    ]
    
    for site in social_media_sites:
        try:
            response = requests.get(site, allow_redirects=True, timeout=5)
            if response.status_code == 200:
                info[site] = "Found"
            else:
                info[site] = "Not Found"
        except Exception as e:
            info[site] = f"Error: {str(e)}"    
    return info

VIRUSTOTAL_API_KEY = 'VIRUSTOTAL_API'

def get_hash_info(file_hash: str) -> dict:
    """Fetches file hash information from VirusTotal."""
    info = {}
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            info['virustotal'] = response.json()
        else:
            info['error'] = f"Status Code: {response.status_code}"
    except Exception as e:
        info['error'] = str(e)
    
    return info

# Load SpaCy's English model
nlp = spacy.load("en_core_web_sm")
def perform_nlp_analysis(text: str) -> dict:
    """Performs NLP analysis on the provided text using SpaCy."""
    info = {}
    try:
        doc = nlp(text)
        
        # Extract named entities
        entities = [(ent.text, ent.label_) for ent in doc.ents]
        info['entities'] = entities
        
        # Extract keywords (simple approach using nouns)
        keywords = [chunk.text for chunk in doc.noun_chunks]
        info['keywords'] = keywords
    
    except Exception as e:
        info['error'] = str(e)
    
    return info
