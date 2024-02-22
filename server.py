# Caterpillar - The simple and parasitic web proxy with spam filter
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2022-10-06
# Updated at: 2024-12-20

import argparse
import socket
import sys
import os
from _thread import *
import base64
import json
import ssl
import time
import re
import hashlib
import resource
#import traceback
import io
from subprocess import Popen, PIPE
from datetime import datetime
from platform import python_version
from PIL import Image

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
    local_domain = config('LOCAL_DOMAIN')
    proxy_pass = config('PROXY_PASS')
    mastodon_server = config('MASTODON_SERVER')   # catswords.social
    mastodon_user_token = config('MASTODON_USER_TOKEN')   # catswords.social
    truecaptcha_userid = config('TRUECAPTCHA_USERID')   # truecaptcha.org
    truecaptcha_apikey = config('TRUECAPTCHA_APIKEY')   # truecaptcha.org
except KeyboardInterrupt:
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

parser = argparse.ArgumentParser()

parser.add_argument('--max_conn', help="Maximum allowed connections", default=255, type=int)
parser.add_argument('--buffer_size', help="Number of samples to be used", default=8192, type=int)

args = parser.parse_args()
max_connection = args.max_conn
buffer_size = args.buffer_size

# https://stackoverflow.com/questions/25475906/set-ulimit-c-from-outside-shell
resource.setrlimit(
    resource.RLIMIT_CORE,
    (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

# load data to use KnownWords5 strategy
# Download data: https://github.com/dwyl/english-words
known_words = []
if os.path.exists("words_alpha.txt"):
    with open("words_alpha.txt", "r") as file:
        words = file.readlines()
        known_words = [word.strip() for word in words if len(word.strip()) > 5]
        print ("[*] data loaded to use KnownWords5 strategy")

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
        webserver = b''
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
        print("[*] Exception on parsing the header of %s. Cause: %s" % (str(addr[0]), str(e)))
        return

    # if it is reverse proxy
    if local_domain != '':
        localserver = local_domain.encode(client_encoding)
        if webserver == localserver or data.find(b'\nHost: ' + localserver) > -1:
            print ("[*] ** Detected the reverse proxy request: %s" % (local_domain))
            scheme, _webserver, _port = proxy_pass.encode(client_encoding).split(b':')
            webserver = _webserver[2:]
            port = int(_port.decode(client_encoding))

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
        print("[*] Skipped generating the certificate. Cause: %s" % (str(e)))

    # https://stackoverflow.com/questions/11255530/python-simple-ssl-socket-server
    # https://docs.python.org/3/library/ssl.html
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certpath, certkey)

    # https://stackoverflow.com/questions/11255530/python-simple-ssl-socket-server
    conn = context.wrap_socket(conn, server_side=True)
    data = conn.recv(buffer_size)

    return (conn, data)

def proxy_check_filtered(data, webserver, port, scheme, method, url):
    filtered = False

    # prevent cache confusing
    if data.find(b'<title>Welcome to nginx!</title>') > -1:
        return True

    # ctkpaarr
    if data.find(b'ctkpaarr') > -1:
        return True

    # allowed conditions
    if method == b'GET' or url.find(b'/api') > -1:
        return False

    # convert to text
    data_length = len(data)
    text = data.decode(client_encoding, errors='ignore')
    error_rate = (data_length - len(text)) / data_length
    if error_rate > 0.2:    # it is a binary data
        return False

    # check ID with K-Anonymity strategy
    pattern = r'\b(?:(?<=\/@)|(?<=acct:))([a-zA-Z0-9]{10})\b'
    matches = list(set(re.findall(pattern, text)))
    if len(matches) > 0:
        print ("[*] Found ID: %s" % (', '.join(matches)))
        try:
            filtered = not all(map(pwnedpasswords_test, matches))
        except Exception as e:
            print ("[*] K-Anonymity strategy not working! %s" % (str(e)))
            filtered = True

    # feedback
    if filtered and len(matches) > 0:
        score = 0

        # check ID with VowelRatio10 strategy
        def vowel_ratio_test(s):
            ratio = calculate_vowel_ratio(s)
            return ratio > 0.2 and ratio < 0.7
        if all(map(vowel_ratio_test, matches)):
            score += 1

        # check ID with Palindrome5 strategy
        if all(map(has_palindrome, matches)):
            score += 1

        # check ID with EnglishWords5 strategy
        if all(map(has_known_word, matches)):
            score += 2

        # make decision
        if score > 1:
            filtered = False

    # check an attached images (check images with Not-CAPTCHA strategy)
    if not filtered and len(matches) > 0 and truecaptcha_userid != '':
        def webp_to_png_base64(url):
            try:
                response = requests.get(url)
                img = Image.open(io.BytesIO(response.content))
                img_png = img.convert("RGBA")
                buffered = io.BytesIO()
                img_png.save(buffered, format="PNG")
                encoded_image = base64.b64encode(buffered.getvalue()).decode(client_encoding)
                return encoded_image
            except:
                return None

        urls = re.findall(r'https://[^\s"]+\.webp', text)
        if len(urls) > 0:
            for url in urls:
                if filtered:
                    break

                print ("[*] downloading... %s" % (url))
                encoded_image = webp_to_png_base64(url)
                print ("[*] downloaded.")
                if encoded_image:
                    print ("[*] solving...")
                    try:
                        solved = truecaptcha_solve(encoded_image)
                        if solved:
                            print ("[*] solved: %s" % (solved))
                            filtered = solved.lower() in ['ctkpaarr', 'spam']
                        else:
                            print ("[*] not solved")
                    except Exception as e:
                        print ("[*] Not CAPTCHA strategy not working! %s" % (str(e)))

    # take action
    if filtered:
        print ("[*] Filtered from %s:%s" % (webserver.decode(client_encoding), str(port)))

        try:
            savedir = './savedfiles'
            if not os.path.exists(savedir):
                os.makedirs(savedir)
            current_time = datetime.now().strftime("%Y%m%d%H%M%S")
            file_path = os.path.join(savedir, ("%s_%s.bin" % (current_time, webserver.decode(client_encoding))))
            with open(file_path, 'wb') as file:
                file.write(data)
            print ("[*] Saved the file: %s" % (file_path))
        except Exception as e:
            print ("[*] Failed to save the file: %s" % (str(e)))

    return filtered

def proxy_server(webserver, port, scheme, method, url, conn, addr, data):
    try:
        print("[*] Started the request. %s" % (str(addr[0])))

        # SSL negotiation
        if scheme in [b'https', b'tls', b'ssl'] and method == b'CONNECT':
            while True:
                try:
                    conn, data = proxy_connect(webserver, conn)
                    break   # success
                #except OSError as e:
                #    print ("[*] Retrying SSL negotiation... (%s:%s) %s" % (webserver.decode(client_encoding), str(port), str(e)))
                except Exception as e:
                    raise Exception("SSL negotiation failed. (%s:%s) %s" % (webserver.decode(client_encoding), str(port), str(e)))

        # Wait to see if there is more data to transmit
        def sendall(sock, conn, data):
            # send first chuck
            if proxy_check_filtered(data, webserver, port, scheme, method, url):
                sock.close()
                raise Exception("Filtered request")
            sock.send(data)
            if len(data) < buffer_size:
                return

            # send following chunks
            buffered = b''
            conn.settimeout(1)
            while True:
                try:
                    chunk = conn.recv(buffer_size)
                    if not chunk:
                        break
                    buffered += chunk
                    if proxy_check_filtered(buffered, webserver, port, scheme, method, url):
                        sock.close()
                        raise Exception("Filtered request")
                    sock.send(chunk)
                    if len(buffered) > buffer_size*2:
                        buffered = buffered[-buffer_size*2:]
                except:
                    break

        # do response
        if server_url == "localhost":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if scheme in [b'https', b'tls', b'ssl']:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                sock = context.wrap_socket(sock, server_hostname=webserver.decode(client_encoding))
                sock.connect((webserver, port))
                #sock.sendall(data)
                sendall(sock, conn, data)
            else:
                sock.connect((webserver, port))
                #sock.sendall(data)
                sendall(sock, conn, data)

            i = 0
            buffered = b''
            while True:
                chunk = sock.recv(buffer_size)
                if not chunk:
                    break
                buffered += chunk
                if proxy_check_filtered(buffered, webserver, port, scheme, method, url):
                    sock.close()
                    add_filtered_host(webserver.decode(client_encoding), '127.0.0.1')
                    raise Exception("Filtered response")
                conn.send(chunk)
                if len(buffered) > buffer_size*2:
                    buffered = buffered[-buffer_size*2:]
                i += 1

            print("[*] Received %s chunks. (%s bytes per chunk)" % (str(i), str(buffer_size)))

        else:

            proxy_data = {
                'headers': {
                    "User-Agent": "php-httpproxy/0.1.4 (Client; Python " + python_version() + "; abuse@catswords.net)",
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
            buffered = b''
            for chunk in relay.iter_content(chunk_size=buffer_size):
                buffered += chunk
                if proxy_check_filtered(buffered, webserver, port, scheme, method, url):
                    add_filtered_host(webserver.decode(client_encoding), '127.0.0.1')
                    raise Exception("Filtered response")
                conn.send(chunk)
                if len(buffered) > buffer_size*2:
                    buffered = buffered[-buffer_size*2:]
                i += 1

            print("[*] Received %s chunks. (%s bytes per chunk)" % (str(i), str(buffer_size)))

        print("[*] Request and received. Done. %s" % (str(addr[0])))
        conn.close()
    except Exception as e:
        #print(traceback.format_exc())
        print("[*] Exception on requesting the data. Cause: %s" % (str(e)))
        conn.sendall(b"HTTP/1.1 403 Forbidden\n\n{\"status\":403}")
        conn.close()

# journaling a filtered hosts
def add_filtered_host(domain, ip_address):
    hosts_path = './filtered.hosts'
    with open(hosts_path, 'r') as file:
        lines = file.readlines()

    domain_exists = any(domain in line for line in lines)
    if not domain_exists:
        lines.append(f"{ip_address}\t{domain}\n")
        with open(hosts_path, 'w') as file:
            file.writelines(lines)
        if mastodon_user_token != '':    # notify to catswords.social
            post_status_to_mastodon(f"[{mastodon_server} user]\r\n\r\n{domain} is a domain with suspicious spam activity.\r\n\r\n#catswords")

# notify to mastodon server
def post_status_to_mastodon(text, media_ids=None, poll_options=None, poll_expires_in=None, scheduled_at=None, idempotency_key=None):
    url = f"https://{mastodon_server}/api/v1/statuses"
    headers = {
        "Authorization": f"Bearer {user_token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    form_data = {
        "status": text,
        "media_ids[]": media_ids,
        "poll[options][]": poll_options,
        "poll[expires_in]": poll_expires_in,
        "scheduled_at": scheduled_at,
    }
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    response = requests.post(url, headers=headers, data=form_data)
    return response.json()

# Strategy: K-Anonymity test - use api.pwnedpasswords.com
def pwnedpasswords_test(s):
    # convert to lowercase
    s.lower()

    # SHA1 of the password
    p_sha1 = hashlib.sha1(s.encode()).hexdigest()

    # First 5 char of SHA1 for k-anonymity API use
    f5_sha1 = p_sha1[:5]

    # Last 5 char of SHA1 to match API output
    l5_sha1 = p_sha1[-5:]

    # Making GET request using Requests library
    response = requests.get(f'https://api.pwnedpasswords.com/range/{f5_sha1}')

    # Checking if request was successful
    if response.status_code == 200:
        # Parsing response text
        hashes = response.text.split('\r\n')

        # Using list comprehension to find matching hashes
        matching_hashes = [line.split(':')[0] for line in hashes if line.endswith(l5_sha1)]

        # If there are matching hashes, return True, else return False
        return bool(matching_hashes)
    else:
        raise Exception("api.pwnedpasswords.com response status: %s" % (str(response.status_code)))

    return False

# Strategy: Not-CAPTCHA - use truecaptcha.org
def truecaptcha_solve(encoded_image):
    url = 'https://api.apitruecaptcha.org/one/gettext'
    data = {
        'userid': truecaptcha_userid,
        'apikey': truecaptcha_apikey,
        'data': encoded_image,
        'mode': 'human'
    }
    response = requests.post(url = url, json = data)

    if response.status_code == 200:
        data = response.json()

        if 'error_message' in data:
            print ("[*] Error: %s" % (data['error_message']))
            return None
        if 'result' in data:
            return data['result']
    else:
        raise Exception("api.apitruecaptcha.org response status: %s" % (str(response.status_code)))

    return None

# Strategy: VowelRatio10
def calculate_vowel_ratio(s):
    # Calculate the length of the string.
    length = len(s)
    if length == 0:
        return 0.0

    # Count the number of vowels ('a', 'e', 'i', 'o', 'u', 'w', 'y') in the string.
    vowel_count = sum(1 for char in s if char.lower() in 'aeiouwy')

    # Calculate the ratio of vowels to the total length of the string.
    vowel_ratio = vowel_count / length

    return vowel_ratio

# Strategy: Palindrome5
def has_palindrome(input_string):
    def is_palindrome(s):
        return s == s[::-1]

    input_string = input_string.lower()
    n = len(input_string)
    for i in range(n):
        for j in range(i + 5, n + 1):  # Find substrings of at least 5 characters
            substring = input_string[i:j]
            if is_palindrome(substring):
                return True
    return False

# Strategy: KnownWords5
def has_known_word(input_string):
    def is_known_word(s):
        return s in known_words

    input_string = input_string.lower()
    n = len(input_string)
    for i in range(n):
        for j in range(i + 5, n + 1):  # Find substrings of at least 5 characters
            substring = input_string[i:j]
            if is_known_word(substring):
                return True
    return False

if __name__== "__main__":
    start()
