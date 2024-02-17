# gnh1201/php-httpproxy
# Go Namyheon <gnh1201@gmail.com>
# Created at: 2022-10-06
# Updated at: 2022-11-25

import argparse
import socket
import sys
import os
from _thread import *
import base64
import json
import ssl
import time
from subprocess import Popen, PIPE
from datetime import datetime
from platform import python_version

import requests
from decouple import config

try:
    listening_port = config('PORT', cast=int)
    server_url = config('SERVER_URL')
    cakey = config('CA_KEY')
    cacert = config('CA_CERT')
    certkey = config('CERT_KEY')
    certdir = config('CERT_DIR')
    openssl_binpath = config('OPENSSL_BINPATH')
    client_encoding = config('CLIENT_ENCODING')
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
            start_new_thread(conn_string, (conn, data, addr)) #Starting a thread
        except KeyboardInterrupt:
            sock.close()
            print("\n[*] Graceful Shutdown")
            sys.exit(1)

def conn_string(conn, data, addr):
    try:
        first_line = data.split(b'\n')[0]

        method, url = first_line.split()[0:2]

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
    except Exception as e:
        conn.close()
        print("[*] Exception on parsing the header of %s. Because of %s" % (str(addr[0]), str(e)))
        return

    proxy_server(webserver, port, scheme, method, url, conn, addr, data)

def proxy_connect(webserver, conn):
    hostname = webserver.decode(client_encoding)
    certpath = "%s/%s.crt" % (certdir.rstrip('/'), hostname)

    # https://stackoverflow.com/questions/24055036/handle-https-request-in-proxy-server-by-c-sharp-connect-tunnel
    conn.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')

    # https://github.com/inaz2/proxy2/blob/master/proxy2.py
    try:
        if not os.path.isfile(certpath):
            epoch = "%d" % (time.time() * 1000)
            p1 = Popen([openssl_binpath, "req", "-new", "-key", certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
            p2 = Popen([openssl_binpath, "x509", "-req", "-days", "3650", "-CA", cacert, "-CAkey", cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
            p2.communicate()
    except Exception as e:
        print("[*] Skipped generating the certificate. Because of %s" % (str(e)))

    # https://stackoverflow.com/questions/11255530/python-simple-ssl-socket-server
    # https://docs.python.org/3/library/ssl.html
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certpath, certkey)

    # https://stackoverflow.com/questions/11255530/python-simple-ssl-socket-server
    conn = context.wrap_socket(conn, server_side=True)
    data = conn.recv(buffer_size)

    return (conn, data)

def proxy_server(webserver, port, scheme, method, url, conn, addr, data):
    try:
        print("[*] Started Request. %s" % (str(addr[0])))

        try:
            if scheme in [b'https', b'tls', b'ssl'] and method == b'CONNECT':
                conn, data = proxy_connect(webserver, conn)
        except Exception as e:
            raise Exception("SSL negotiation failed. %s" % (str(e)))

        if server_url == "localhost":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=webserver)
            ssl_sock.connect((webserver, port))
            ssl_sock.sendall(data)

            while True:
                data = ssl_sock.recv(1024)
                if not data:
                    break
                conn.send(data)
            print("[*] Request and received. Done. %s" % (str(addr[0])))
        else:
            proxy_data = {
                'headers': {
                    "User-Agent": "php-httpproxy/0.1.3 (Client; Python " + python_version() + "; abuse@catswords.net)",
                },
                'data': {
                    "data": base64.b64encode(data).decode(client_encoding),
                    "client": str(addr[0]),
                    "server": webserver.decode(client_encoding),
                    "port": str(port),
                    "scheme": scheme.decode(client_encoding),
                    "url": url.decode(client_encoding),
                    "length": str(len(data)),
                    "chunksize": str(buffer_size),
                    "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                }
            }
            raw_data = json.dumps(proxy_data['data'])
    
            print("[*] Sending %s bytes..." % (str(len(raw_data))))
    
            i = 0
            relay = requests.post(server_url, headers=proxy_data['headers'], data=raw_data, stream=True)
            for chunk in relay.iter_content(chunk_size=buffer_size):
                conn.send(chunk)
                i = i + 1
    
            print("[*] Received %s chucks. (%s bytes per chuck)" % (str(i), str(buffer_size)))
            print("[*] Request and received. Done. %s" % (str(addr[0])))

        conn.close()
    except Exception as e:
        print("[*] Exception on requesting the data. Because of %s" % (str(e)))
        conn.close()

if __name__== "__main__":
    start()
