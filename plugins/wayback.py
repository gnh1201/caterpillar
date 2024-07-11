#!/usr/bin/python3
#
# wayback.py
# Cached previous page (e.g. Wayback Machine) integration plugin for Caterpillar Proxy
#
# Caterpillar Proxy - The simple and parasitic web proxy with SPAM filter
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-03-13
# Updated at: 2024-07-06
#

import requests
from decouple import config

from base import Extension, Logger

logger = Logger(name="wayback")

try:
    client_encoding = config("CLIENT_ENCODING")
except Exception as e:
    logger.error("[*] Invalid configuration", exc_info=e)


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


class Wayback(Extension):
    def __init__(self):
        self.type = "connector"  # this is a connctor
        self.connection_type = "wayback"

    def connect(self, conn, data, webserver, port, scheme, method, url):
        connected = False

        target_url = url.decode(client_encoding)

        if not connected:
            status_code, text = get_cached_page_from_google(target_url)
            if status_code == 200:
                conn.send(text.encode(client_encoding))
                connected = True

        if not connected:
            status_code, text = get_cached_page_from_wayback(target_url)
            if status_code == 200:
                conn.send(text.encode(client_encoding))
                connected = True

        return connected
