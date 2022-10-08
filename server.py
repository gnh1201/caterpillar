# gnh1201/php-httpproxy
# Go Namyheon <gnh1201@gmail.com>
# Created at: 2022-10-06
# Updated at: 2022-10-07

import argparse
import socket
import sys
from _thread import *
import base64
import json
from datetime import datetime
from platform import python_version

import requests
from decouple import config

try:
    listening_port = config('PORT', cast=int)
    proxy_url = config('PROXY_URL')
except KeyboardInterrupt:
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

parser = argparse.ArgumentParser()

parser.add_argument('--max_conn', help="Maximum allowed connections", default=5, type=int)
parser.add_argument('--buffer_size', help="Number of samples to be used", default=8192, type=int)

args = parser.parse_args()
max_connection = args.max_conn
buffer_size = args.buffer_size

def start():    #Main Program
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', listening_port))
        sock.listen(max_connection)
        print("[*] Server started successfully [ %d ]" %(listening_port))
    except Exception:
        print("[*] Unable to Initialize Socket")
        print(Exception)
        sys.exit(2)

    while True:
        try:
            conn, addr = sock.accept() #Accept connection from client browser
            data = conn.recv(buffer_size) #Recieve client data
            start_new_thread(conn_string, (conn,data, addr)) #Starting a thread
        except KeyboardInterrupt:
            sock.close()
            print("\n[*] Graceful Shutdown")
            sys.exit(1)

def conn_string(conn, data, addr):
    try:
        first_line = data.split(b'\n')[0]

        url = first_line.split()[1]

        http_pos = url.find(b'://') #Finding the position of ://
        scheme = b'http'  # check http/https or other protocol
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos+3):]
            scheme = url[0:http_pos]

        port_pos = temp.find(b':')

        webserver_pos = temp.find(b'/')
        if webserver_pos == -1:
            webserver_pos = len(temp)
        webserver = ""
        port = -1
        if port_pos == -1 or webserver_pos < port_pos:
            port = 80
            webserver = temp[:webserver_pos]
        else:
            port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
            webserver = temp[:port_pos]
            if port == 443:
                scheme = b'https'

        proxy_server(webserver, port, scheme, url, conn, addr, data)
    except Exception as e:
        print("[*] Warning: %s, Line %s" % (str(e), str(sys.exc_info()[-1].tb_lineno)))

def proxy_server(webserver, port, scheme, url, conn, addr, data):
    try:
        print("[*] Starting Request... %s" % (str(addr[0])))
    
        headers = {
            "User-Agent": "php-httpproxy/0.1.2 (Client; Python " + python_version() + ")",
        }
        data = {
            "data": base64.b64encode(data).decode("utf-8"),
            "client": str(addr[0]),
            "server": webserver.decode("utf-8"),
            "port": str(port),
            "scheme": scheme.decode("utf-8"),
            "url": url.decode("utf-8"),
            "length": str(len(data)),
            "chunksize": str(buffer_size),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        }
        raw_data = json.dumps(data)

        print("[*] Sending %s bytes..." % (str(len(raw_data))))

        i = 0
        relay = requests.post(proxy_url, headers=headers, data=raw_data, stream=True)
        for chunk in relay.iter_content(chunk_size=buffer_size):
            conn.send(chunk)
            i = i + 1

        print("[*] Received %s chucks. (%s bytes/chuck)" % (str(i), str(buffer_size)))
        print("[*] Request Done. %s" % (str(addr[0])))

        conn.close()
    except socket.error:
        sock.close()
        conn.close()
        print(sock.error)
        sys.exit(1)

if __name__== "__main__":
    start()
