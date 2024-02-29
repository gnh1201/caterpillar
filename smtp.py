#!/usr/bin/python3
#
# smtp.py
#
# Caterpillar - The simple and parasitic web proxy with spam filter
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-03-01
# Updated at: 2024-03-01
#

import asyncore
from smtpd import SMTPServer
import re
import json
import requests

from decouple import config

def extract_credentials(url):
    pattern = re.compile(r'(?P<scheme>\w+://)?(?P<username>[^:/]+):(?P<password>[^@]+)@(?P<url>.+)')
    match = pattern.match(url)
    if match:
        scheme = match.group('scheme') if match.group('scheme') else 'https://'
        username = match.group('username')
        password = match.group('password')
        url = match.group('url')
        return username, password, scheme + url
    else:
        return None, None, url

try:
    smtp_host = config('SMTP_HOST', default='127.0.0.1')
    smtp_port = config('SMTP_PORT', default=25, cast=int)
    _username, _password, server_url = extract_credentials(config('SERVER_URL'))
except KeyboardInterrupt:
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

auth = None
if _username:
    auth = HTTPBasicAuth(_username, _password)

def jsonrpc2_create_id(data):
    return hashlib.sha1(json.dumps(data).encode(client_encoding)).hexdigest()

def jsonrpc2_encode(method, params = None):
    data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }
    id = jsonrpc2_create_id(data)
    data['id'] = id
    return (id, json.dumps(data))

def jsonrpc2_decode(data):
    type, id, method, rpcdata = (None, None, None, None)
    typemap = {
        "params": "call",
        "error": "error",
        "result": "result"
    }

    jsondata = json.loads(data)
    if jsondata['jsonrpc'] == "2.0":
        for k, v in typemap.items():
            if k in jsondata:
                type = v
                rpcdata = jsondata[k]
        id = jsondata['id']

    if type == "call":
        method = jsondata['method']

    return type, id, method, rpcdata

class CaterpillarSMTPServer(SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        message_lines = data.decode('utf-8').split('\n')
        subject = ''
        to = ''
        for line in message_lines:
            pos = line.find(':')
            if pos > -1:
                k = line[0:pos]
                v = line[pos+1:]
                if k = 'Subject':
                    subject = v
                elif k = 'To':
                    to = v

        # build a data
        _, raw_data = jsonrpc2_encode('relay_sendmail', {
            "to": to,
            "from": mailfrom,
            "subject": subject,
            "message": data.decode('utf-8')
        })

        # send HTTP POST request
        try:
            response = requests.post(server_url, data=raw_data, auth=auth)
            response_json = response.json()
            success = response_json.get('result', {}).get('success', False)
            if success:
                print("[*] Email sent successfully.")
            else:
                print("[*] Failed to send email.")
        except Exception as e:
            print("[*] Failed to send email:", str(e))

# Start SMTP server
smtp_server = CaterpillarSMTPServer((smtp_host, smtp_port), None)

# Start asynchronous event loop
asyncore.loop()
