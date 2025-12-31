import os
import json
import logging
import urllib.parse
from functools import wraps

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
from flask import Flask, request, Response

load_dotenv()

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ROBLOSECURITY = os.getenv('ROBLOSECURITY')
ROBLOX_ACCESS_TOKEN = os.getenv('ROBLOX_ACCESS_TOKEN')
PROXY_TOKEN = os.getenv('PROXY_TOKEN')

# Create session with connection pooling and retries
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(
    pool_connections=10,
    pool_maxsize=20,
    max_retries=retry_strategy
)
session.mount("http://", adapter)
session.mount("https://", adapter)

def require_proxy_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for proxy-token in headers OR query params (for RobloxStudio)
        token = request.headers.get('proxy-token') or request.args.get('proxy-token')
        if token != PROXY_TOKEN:
            return Response(f'Unauthorized - Token received: {token}', 401)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/health')
def health_check():
    return {'status': 'healthy'}, 200

@app.route('/', methods=['GET', 'POST'])
@require_proxy_token
def proxy():
    url = request.args.get('link')
    if not url:
        return "Missing 'link' parameter", 400

    url = urllib.parse.unquote(url)
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    headers = {
        'User-Agent': 'RobloxStudio/WinInet',
        'Content-Type': 'application/json',
        'roblox-access-token': ROBLOX_ACCESS_TOKEN
    }

    if request.args.get('use_roblo_security') == 'true':
        headers['Cookie'] = f".ROBLOSECURITY={ROBLOSECURITY}"

    logger.debug(f"Outgoing request: URL: {url}, Method: {request.method}")

    try:
        # Use session with 30 second timeout
        resp = session.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(),
            allow_redirects=False,
            timeout=30  # 30 second timeout
        )

        logger.debug(f"Response: Status: {resp.status_code}, Content: {resp.text}")

        if resp.status_code in [401, 403]:
            logger.error(f"{resp.status_code} Error: URL: {url}, Response: {resp.text}")

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [(name, value) for (name, value) in resp.raw.headers.items()
                            if name.lower() not in excluded_headers]

        return Response(resp.content, resp.status_code, response_headers)
    
    except requests.exceptions.Timeout:
        logger.error(f"Request timeout: {url}")
        return "Request timeout", 504
    except requests.RequestException as e:
        logger.error(f"Request Exception: {str(e)}")
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
