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
from pythonjsonlogger import jsonlogger

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASEURL = os.getenv("VIRUSTOTAL_BASEURL")
NTFY_URL = os.getenv('NTFY_URL')
LOG_FILE = os.getenv('LOG_FILE')
MAX_UPLOADS = os.getenv('VIRUSTOTAL_MAX_UPLOADS')
upload_count = 0

logger = logging.getLogger('vt_scan')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.DEBUG)
file_formatter = jsonlogger.JsonFormatter(
    '%(levelname)s %(name)s %(message)s',
    timestamp=True
)
file_handler.setFormatter(file_formatter)

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.DEBUG)
stream_formatter = jsonlogger.JsonFormatter(
    '%(levelname)s %(name)s %(message)s',
    timestamp=True
)
stream_handler.setFormatter(stream_formatter)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)


def get_hash(path):
    try:
        with open(path, 'rb') as f:
            sha256 = hashlib.sha256()
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
            hash = sha256.hexdigest()
            logger.debug('get_hash', extra={
                'path': path,
                'hash': hash
            })
            return hash
    except Exception as e:
        logger.error(json.dumps({
            'path': path,
            'error': str(e)
        }))
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
        'x-apikey': VIRUSTOTAL_API_KEY,
        'accept': 'application/json'
    }
    try:
        url = f"{VIRUSTOTAL_BASEURL}/files/{hash}"
        print(f"url: {url}")
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            logger.info('query_vt', extra={
                'hash': hash,
                'status': response.status_code,
                'detail': 'Hash found in VirusTotal database'
            })
            return response.json()
        elif response.status_code == 404:
            logger.info('query_vt', extra={
                'hash': hash,
                'status': response.status_code,
                'detail': 'Hash not found in VirusTotal database'
            })
            return None
        elif response.status_code == 429:
            logger.error('query_vt', extra={
                'status': response.status_code,
                'detail': 'Rate limit exceeded'
            })
        else:
            logging.error('query_vt', extra={
                'hash': hash,
                'status': response.status_code,
                'detail': response.text
            })
            return None
    except Exception as e:
        logger.error('query_vt', extra={
            'hash': hash,
            'error': str(e)
        })

def ntfy_send(message):
    try:
        response = requests.post(NTFY_URL, data=message.encode('utf-8'))
        if response.status_code != 200:
            logging.error(
                f"Error sending ntfy message: {response.status_code}")
    except Exception as e:
        logging.error(f"Error sending ntfy message: {e}")


def main():
    logging.info(f"Starting VirusTotal scan at {datetime.now()}")
    processes = get_processes()
    logging.info(f"Found {len(processes)} processes to scan")
    findings = []

    for exe in processes:
        hash = get_hash(exe)
        if not hash:
            continue
        vt_result = query_vt(hash)
        if vt_result:
            data = vt_result.get('data', {})
            attributes = data.get('attributes', {})
            last_anlaysis_stats = attributes.get('last_analysis_stats', {})
            malicious = last_anlaysis_stats.get('malicious', 0)
            logging.info(json.dumps({
                'file': exe,
                'hash': hash,
                'malicious': malicious
            }))

            if malicious > 0:
                findings.append({
                    'file': exe,
                    'hash': hash,
                    'malicious': malicious
                })

    if findings:
        logging.info("Findings sent via ntfy")
        ntfy_send(
            f"VirusTotal scan findings at {datetime.now().isoformat()}:\n" + json.dumps(findings))
    else:
        logging.info("No findings")

