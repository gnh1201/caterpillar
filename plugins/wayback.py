#!/usr/bin/python3
#
# wayback.py
# Wayback Machine plugin for Caterpillar Proxy
#
# Caterpillar Proxy - The simple and parasitic web proxy with SPAM filter
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-03-13
# Updated at: 2024-03-13
#

import requests

from server import Extension

try:
    client_encoding = config('CLIENT_ENCODING')
except Exception as e:
    print ("[*] Invaild configration: %s" % (str(e)))

# API documentation: https://archive.org/help/wayback_api.php
def get_previous_page_content(url):
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
                    if archived_page_response.status_code == 200:
                        return archived_page_response.text
                    else:
                        return "Error fetching archived page content. Status code: " + str(archived_page_response.status_code)
                else:
                    return "No archived URL found."
            else:
                return "URL is not available in the archive."
        except Exception as e:
            return "Error processing response: " + str(e)
    else:
        return "Error accessing Wayback Machine API. Status code: " + str(response.status_code)

class Wayback(Extension):
    def __init__(self):
        self.type = "connector"   # this is a connctor
        self.connection_type = "wayback"

    def connect(self, conn, data, webserver, port, scheme, method, url):
        previous_page_content = get_previous_page_content(url.decode(client_encoding))
        conn.send(previous_page_content.encode(client_encoding)
