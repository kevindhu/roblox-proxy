import os
import json
import logging
import urllib.parse
from functools import wraps

import requests
from dotenv import load_dotenv
from flask import Flask, request, Response

load_dotenv()

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ROBLOSECURITY = os.getenv('ROBLOSECURITY')
ROBLOX_ACCESS_TOKEN = os.getenv('ROBLOX_ACCESS_TOKEN')
PROXY_TOKEN = os.getenv('PROXY_TOKEN')

def require_proxy_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('proxy-token') != PROXY_TOKEN:
            return Response('Unauthorized', 401)
        return f(*args, **kwargs)
    return decorated_function

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

    logger.debug(f"Outgoing request: URL: {url}, Method: {request.method}, Headers: {json.dumps({k: '***' if k in ['Cookie', 'roblox-access-token'] else v for k, v in headers.items()})}")

    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(),
            allow_redirects=False
        )

        logger.debug(f"Response: Status: {resp.status_code}, Headers: {json.dumps(dict(resp.headers))}, Content: {resp.text}")

        if resp.status_code in [401, 403]:
            logger.error(f"{resp.status_code} Error: URL: {url}, Headers: {json.dumps({k: '***' if k in ['Cookie', 'roblox-access-token'] else v for k, v in headers.items()})}, Response: {resp.text}")

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [(name, value) for (name, value) in resp.raw.headers.items()
                            if name.lower() not in excluded_headers]

        return Response(resp.content, resp.status_code, response_headers)
    except requests.RequestException as e:
        logger.error(f"Request Exception: {str(e)}")
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)