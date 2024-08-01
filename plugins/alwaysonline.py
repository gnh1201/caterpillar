#!/usr/bin/python3
#
# alwaysonline.py
# Always Online implementation for Caterpillar Proxy
#
# Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-07-31
# Updated at: 2024-07-31
#
import socket
import ssl
import requests
from decouple import config
from elasticsearch import Elasticsearch, NotFoundError
import hashlib
from datetime import datetime
from base import Extension, Logger

logger = Logger(name="wayback")

try:
    client_encoding = config("CLIENT_ENCODING")
    es_host = config("ES_HOST")
    es_index = config("ES_INDEX")
except Exception as e:
    logger.error("[*] Invalid configuration", exc_info=e)

es = Elasticsearch([es_host])

def generate_id(url):
    """Generate a unique ID for a URL by hashing it."""
    return hashlib.sha256(url.encode('utf-8')).hexdigest()

def get_cached_page_from_google(url):
    status_code, content = (0, b"")

    # Google Cache URL
    google_cache_url = "https://webcache.googleusercontent.com/search?q=cache:" + url

    # Send a GET request to Google Cache URL
    response = requests.get(google_cache_url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        content = response.content  # Extract content from response
    else:
        status_code = response.status_code

    return status_code, content

# API documentation: https://archive.org/help/wayback_api.php
def get_cached_page_from_wayback(url):
    status_code, content = (0, b"")

    # Wayback Machine API URL
    wayback_api_url = "http://archive.org/wayback/available?url=" + url

    # Send a GET request to Wayback Machine API
    response = requests.get(wayback_api_url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        try:
            # Parse JSON response
            data = response.json()
            archived_snapshots = data.get("archived_snapshots", {})
            closest_snapshot = archived_snapshots.get("closest", {})

            # Check if the URL is available in the archive
            if closest_snapshot:
                archived_url = closest_snapshot.get("url", "")

                # If URL is available, fetch the content of the archived page
                if archived_url:
                    archived_page_response = requests.get(archived_url)
                    status_code = archived_page_response.status_code
                    if status_code == 200:
                        content = archived_page_response.content
                else:
                    status_code = 404
            else:
                status_code = 404
        except:
            status_code = 502
    else:
        status_code = response.status_code

    return status_code, content

def get_cached_page_from_elasticsearch(url):
    url_id = generate_id(url)
    try:
        result = es.get(index=es_index, id=url_id)
        logger.info(result['_source'])
        return 200, result['_source']['content'].encode(client_encoding)
    except NotFoundError:
        return 404, b""
    except Exception as e:
        logger.error(f"Error fetching from Elasticsearch: {e}")
        return 502, b""

def cache_to_elasticsearch(url, data):
    url_id = generate_id(url)
    timestamp = datetime.utcnow().isoformat()
    try:
        es.index(index=es_index, id=url_id, body={
            "url": url,
            "content": data.decode(client_encoding),
            "timestamp": timestamp
        })
    except Exception as e:
        logger.error(f"Error caching to Elasticsearch: {e}")

def get_page_from_origin_server(url):
    try:
        response = requests.get(url)
        return response.status_code, response.content
    except Exception as e:
        return 502, str(e).encode(client_encoding)

class AlwaysOnline(Extension):
    def __init__(self):
        self.type = "connector"  # this is a connector
        self.connection_type = "alwaysonline"
        self.buffer_size = 8192

    def connect(self, conn, data, webserver, port, scheme, method, url):
        logger.info("[*] Connecting... Connecting...")
    
        connected = False
        
        is_ssl = scheme in [b"https", b"tls", b"ssl"]
        cache_hit = 0
        buffered = b""
        
        def sendall(sock, conn, data):
            # send first chuck
            sock.send(data)
            if len(data) < self.buffer_size:
                return

            # send following chunks
            conn.settimeout(1)
            while True:
                try:
                    chunk = conn.recv(self.buffer_size)
                    if not chunk:
                        break
                    sock.send(chunk)
                except:
                    break
        
        target_url = url.decode(client_encoding)
        target_scheme = scheme.decode(client_encoding)
        target_webserver = webserver.decode(client_encoding)
        
        if "://" not in target_url:
            target_url = f"{target_scheme}://{target_webserver}:{port}{target_url}"

        if method == b"GET":
            if not connected:
                logger.info("Trying get data from Elasticsearch...")
                status_code, content = get_cached_page_from_elasticsearch(target_url)
                if status_code == 200:
                    buffered += content
                    cache_hit += 1
                    connected = True

            if not connected:
                logger.info("Trying get data from Wayback Machine...")
                status_code, content = get_cached_page_from_wayback(target_url)
                if status_code == 200:
                    buffered += content
                    cache_hit += 1
                    connected = True

            if not connected:
                logger.info("Trying get data from Google Website Cache...")
                status_code, content = get_cached_page_from_google(target_url)
                if status_code == 200:
                    buffered += content
                    cache_hit += 1
                    connected = True

            if cache_hit == 0:
                status_code, content = get_page_from_origin_server(target_url)
                buffered += content
                cache_to_elasticsearch(target_url, buffered)

            conn.send(buffered)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if is_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                sock = context.wrap_socket(
                    sock, server_hostname=webserver.decode(client_encoding)
                )
                sock.connect((webserver, port))
                # sock.sendall(data)
                sendall(sock, conn, data)
            else:
                sock.connect((webserver, port))
                # sock.sendall(data)
                sendall(sock, conn, data)

        return connected
