#!/usr/bin/python3
#
# portscanner.py
# NMAP port scanning wrapper for Caterpillar Proxy
#
# Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2022-01-26 (from github.com/gnh1201/welsonjs)
# Updated at: 2024-07-11
#
import sys
import nmap
import json

from base import Extension

class PortScanner(Extension):
    def __init__(self):
        self.type = "rpcmethod"
        self.method = "scan_ports_by_hosts"
        self.exported_methods = []
    
    def dispatch(self, type, id, params, conn):
        hosts = params['hosts']
        binpath = params['binpath']

        nm = nmap.PortScanner(nmap_search_path=(binpath,))
        result = nm.scan(hosts=hosts, arguments='-T5 -sV -p0-65535 --max-retries 0')

        return result;

if __name__ == "__main__":
    main(sys.argv)
