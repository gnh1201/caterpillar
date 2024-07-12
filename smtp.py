#!/usr/bin/python3
#
# smtp.py
# SMTP mail sender over HTTP/S
#
# Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-03-01
# Updated at: 2024-07-12
#
import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from email.message import EmailMessage
import re
import sys
import json
import requests
from platform import python_version
from decouple import config
from requests.auth import HTTPBasicAuth
from base import extract_credentials, jsonrpc2_create_id, jsonrpc2_encode, jsonrpc2_decode, jsonrpc2_result_encode, Logger

logger = Logger(name="smtp")

try:
    smtp_host = config('SMTP_HOST', default='127.0.0.1')
    smtp_port = config('SMTP_PORT', default=25, cast=int)
    _username, _password, server_url = extract_credentials(config('SERVER_URL', default=''))
except KeyboardInterrupt:
    logger.warning("[*] User has requested an interrupt")
    logger.warning("[*] Application Exiting.....")
    sys.exit()

auth = None
if _username:
    auth = HTTPBasicAuth(_username, _password)

class CaterpillarSMTPHandler:
    def __init__(self):
        self.smtpd_hostname = "CaterpillarSMTPServer"
        self.smtp_version = "0.1.6"

    async def handle_DATA(self, server, session, envelope):
        mailfrom = envelope.mail_from
        rcpttos = envelope.rcpt_tos
        data = envelope.content

        message = EmailMessage()
        message.set_content(data)

        subject = message.get('Subject', '')
        to = message.get('To', '')

        proxy_data = {
            'headers': {
                "User-Agent": f"php-httpproxy/0.1.6 (Client; Python {python_version()}; Caterpillar; abuse@catswords.net)",
            },
            'data': {
                "to": to,
                "from": mailfrom,
                "subject": subject,
                "message": data.decode('utf-8')
            }
        }
        _, raw_data = jsonrpc2_encode('relay_sendmail', proxy_data['data'])

        try:
            response = await asyncio.to_thread(
                requests.post,
                server_url,
                headers=proxy_data['headers'],
                data=raw_data,
                auth=auth
            )
            if response.status_code == 200:
                type, id, rpcdata = jsonrpc2_decode(response.text)
                if rpcdata['success']:
                    logger.info("[*] Email sent successfully.")
                else:
                    raise Exception(f"({rpcdata['code']}) {rpcdata['message']}")
            else:
                raise Exception(f"Status {response.status_code}")
        except Exception as e:
            logger.error("[*] Failed to send email", exc_info=e)
            return '500 Could not process your message. ' + str(e)

        return '250 OK'

# https://aiosmtpd-pepoluan.readthedocs.io/en/latest/migrating.html
def main():
    handler = CaterpillarSMTPHandler()
    controller = Controller(handler, hostname=smtp_host, port=smtp_port)
    # Run the event loop in a separate thread.
    controller.start()
    # Wait for the user to press Return.
    input('SMTP server running. Press Return to stop server and exit.')
    controller.stop()
    logger.warning("[*] User has requested an interrupt")
    logger.warning("[*] Application Exiting.....")
    sys.exit()

if __name__ == "__main__":
    main()
