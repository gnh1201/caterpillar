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
import requests
from decouple import config
from elasticsearch import Elasticsearch, NotFoundError
import hashlib
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
    status_code, text = (0, "")

    # Google Cache URL
    google_cache_url = "https://webcache.googleusercontent.com/search?q=cache:" + url

    # Send a GET request to Google Cache URL
    response = requests.get(google_cache_url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        text = response.text  # Extract content from response
    else:
        status_code = response.status_code

    return status_code, text

# API documentation: https://archive.org/help/wayback_api.php
def get_cached_page_from_wayback(url):
    status_code, text = (0, "")

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
                        text = archived_page_response.text
                else:
                    status_code = 404
            else:
                status_code = 404
        except:
            status_code = 502
    else:
        status_code = response.status_code

    return status_code, text

def get_cached_page_from_elasticsearch(url):
    url_id = generate_id(url)
    try:
        result = es.get(index=es_index, id=url_id)
        return 200, result['_source']['content']
    except NotFoundError:
        return 404, ""
    except Exception as e:
        logger.error(f"Error fetching from Elasticsearch: {e}")
        return 500, ""

def cache_to_elasticsearch(url, data):
    url_id = generate_id(url)
    try:
        es.index(index=es_index, id=url_id, body={"content": data.decode(client_encoding)})
    except Exception as e:
        logger.error(f"Error caching to Elasticsearch: {e}")

class AlwaysOnline(Extension):
    def __init__(self):
        self.type = "connector"  # this is a connector
        self.connection_type = "alwaysonline"

    def connect(self, conn, data, webserver, port, scheme, method, url):
        connected = False
        cache_hit = 0
        buffered = b""
        
        target_url = url.decode(client_encoding)
        
        if method == "GET":
            if not connected:
                status_code, text = get_cached_page_from_elasticsearch(target_url)
                if status_code == 200:
                    buffered += text.encode(client_encoding)
                    cache_hit += 1
                    connected = True

            if not connected:
                status_code, text = get_cached_page_from_google(target_url)
                if status_code == 200:
                    buffered += text.encode(client_encoding)
                    cache_hit += 1
                    connected = True

            if not connected:
                status_code, text = get_cached_page_from_wayback(target_url)
                if status_code == 200:
                    buffered += text.encode(client_encoding)
                    cache_hit += 1
                    connected = True
                    
        conn.send(buffered)
        
        if cache_hit == 0 and buffered:
            cache_to_elasticsearch(target_url, buffered)

        return connected