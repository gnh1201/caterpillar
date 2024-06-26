#!/usr/bin/python3
#
# smtp.py
# SMTP over HTTP gateway
#
# Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-03-01
# Updated at: 2024-05-20
#

import asyncore
from smtpd import SMTPServer
import re
import json
import requests

from decouple import config
from requests.auth import HTTPBasicAuth
from base import extract_credentials, jsonrpc2_create_id, jsonrpc2_encode, jsonrpc2_result_encode

try:
    smtp_host = config('SMTP_HOST', default='127.0.0.1')
    smtp_port = config('SMTP_PORT', default=25, cast=int)
    _username, _password, server_url = extract_credentials(config('SERVER_URL', default=''))
except KeyboardInterrupt:
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

auth = None
if _username:
    auth = HTTPBasicAuth(_username, _password)

class CaterpillarSMTPServer(SMTPServer):
    def __init__(self, localaddr, remoteaddr):
        self.__class__.smtpd_hostname = "CaterpillarSMTPServer"
        self.__class__.smtp_version = "0.1.6"
        super().__init__(localaddr, remoteaddr)

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        message_lines = data.decode('utf-8').split('\n')
        subject = ''
        to = ''
        for line in message_lines:
            pos = line.find(':')
            if pos > -1:
                k = line[0:pos]
                v = line[pos+1:]
                if k == 'Subject':
                    subject = v
                elif k == 'To':
                    to = v

        # build a data
        proxy_data = {
            'headers': {
                "User-Agent": "php-httpproxy/0.1.6 (Client; Python " + python_version() + "; Caterpillar; abuse@catswords.net)",
            },
            'data': {
                "to": to,
                "from": mailfrom,
                "subject": subject,
                "message": data.decode('utf-8')
            }
        }
        _, raw_data = jsonrpc2_encode('relay_sendmail', proxy_data['data'])

        # send HTTP POST request
        try:
            response = requests.post(server_url, headers=proxy_data['headers'], data=raw_data, auth=auth)
            if response.status_code == 200:
                type, id, method, rpcdata = jsonrpc2_decode(response.text)
                if rpcdata['success']:
                    print("[*] Email sent successfully.")
                else:
                    raise Exception("(%s) %s" % (str(rpcdata['code']), rpcdata['message']))
            else:
                raise Exception("Status %s" % (str(response.status_code)))
        except Exception as e:
            print("[*] Failed to send email:", str(e))

# Start SMTP server
smtp_server = CaterpillarSMTPServer((smtp_host, smtp_port), None)

# Start asynchronous event loop
asyncore.loop()
