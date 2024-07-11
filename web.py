#!/usr/bin/python3
#
# web.py
# server file with HTTP connection mode
#
# Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-05-20
# Updated at: 2024-07-10
#

from flask import Flask, request, redirect, url_for, render_template
import os
import sys
import json
import importlib

import hashlib
from decouple import config

from base import Extension, jsonrpc2_create_id, jsonrpc2_result_encode, jsonrpc2_error_encode

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'data/'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def upload_form():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def process_upload():
    # make connection profile from Flask request
    conn = Connection(request)

    # pass to the method
    method = request.form['method']
    filename = request.files['file'].filename
    params = {
        'filename': filename
    }
    
    # just do it
    return Extension.dispatch_rpcmethod(method, 'call', '', params, conn)

@app.route('/jsonrpc2', methods=['POST'])
def process_jsonrpc2():
    # make connection profile from Flask request
    conn = Connection(request)

    # JSON-RPC 2.0 request
    jsondata = request.get_json(silent=True)
    if jsondata['jsonrpc'] == "2.0":
        return Extension.dispatch_rpcmethod(jsondata['method'], 'call', jsondata['id'], jsondata['params'], conn)

    # when error
    return jsonrpc2_error_encode({
        'message': "Not vaild JSON-RPC 2.0 request"
    })

def jsonrpc2_server(conn, id, method, params):
    return Extension.dispatch_rpcmethod(method, "call", id, params, conn)

class Connection():
    def send(self, data):
        self.messages.append(data)

    def recv(self, size):
        print ("Not allowed method")

    def close(self):
        print ("Not allowed method")

    def __init__(self, req):
        self.messages = []
        self.request = req

if __name__ == "__main__":
    # initalization
    try:
        listening_port = config('PORT', default=5555, cast=int)
        client_encoding = config('CLIENT_ENCODING', default='utf-8')
    except KeyboardInterrupt:
        print("\n[*] User has requested an interrupt")
        print("[*] Application Exiting.....")
        sys.exit()
    except Exception as e:
        print("[*] Failed to initialize:", str(e))

    # set environment of Extension
    Extension.set_protocol('http')

    # load extensions
    for s in use_extensions.split(','):
        Extension.register(s)

    app.run(debug=True, host='0.0.0.0', port=listening_port)
