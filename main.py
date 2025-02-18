import psutil
import hashlib
import requests
import logging
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASEURL = os.getenv("VIRUSTOTAL_BASEURL")
NTFY_URL = os.getenv('NTFY_URL')
LOG_FILE = os.getenv('LOG_FILE')
MAX_UPLOADS = os.getenv('VIRUSTOTAL_MAX_UPLOADS')
upload_count = 0

# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s %(levelname)s %(message)s',
#     handlers=[
#         logging.FileHandler(LOG_FILE),
#         logging.StreamHandler(sys.stdout)
#     ]
# )


def get_sha256(path):
    try:
        with open(path, 'rb') as f:
            sha256 = hashlib.sha256()
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
            return sha256.hexdigest()
    except Exception as e:
        logging.error(f'Error calculating sha256: {e}')
        return None


def get_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe = proc.info['exe']
            if exe and os.path.exists(exe):
                processes.append(exe)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return list(set(processes))


def query_vt(hash):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    url = f"{VIRUSTOTAL_BASEURL}/files/${hash}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        logging.error(f"Error querying VirusTotal: {response.status_code}")
        return None



