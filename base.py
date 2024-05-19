#!/usr/bin/python3
#
# base.py
# base (common) file
#
# Caterpillar Proxy - The simple and parasitic web proxy SPAM spam filter
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-05-20
# Updated at: 2024-05-20
#

import hashlib
import json

client_encoding = 'utf-8'

def jsonrpc2_create_id(data):
    return hashlib.sha1(json.dumps(data).encode(client_encoding)).hexdigest()

def jsonrpc2_encode(method, params = None):
    data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }
    id = jsonrpc2_create_id(data)
    data['id'] = id
    return (id, json.dumps(data))

def jsonrpc2_result_encode(result, id = ''):
    data = {
        "jsonrpc": "2.0",
        "result": result,
        "id": id
    }
    return json.dumps(data)

def jsonrpc2_error_encode(error, id = ''):
    data = {
        "jsonrpc": "2.0",
        "error": error,
        "id": id
    }
    return json.dumps(data)

class Extension():
    extensions = []
    protocols = []
    buffer_size = 8192

    @classmethod
    def set_protocol(cls, protocol):
        cls.protocols.append(protocol)

    @classmethod
    def set_buffer_size(cls, _buffer_size):
        cls.buffer_size = _buffer_size

    @classmethod
    def register(cls, f):
        cls.extensions.append(f)

    @classmethod
    def get_filters(cls):
        filters = []
        for extension in cls.extensions:
            if extension.type == "filter":
                filters.append(extension)
        return filters

    @classmethod
    def get_rpcmethod(cls, method):
        for extension in cls.extensions:
            is_exported_method = (method == extension.method) or (method in extension.exported_methods)
            if extension.type == "rpcmethod" and is_exported_method:
                return extension
        return None

    @classmethod
    def dispatch_rpcmethod(cls, method, type, id, params, conn):
        rpcmethod = cls.get_rpcmethod(method)
        if rpcmethod:
            if rpcmethod.method == method:
                return rpcmethod.dispatch(type, id, params, conn)
            else:
                f = getattr(rpcmethod, method, None)
                if f:
                    return f(type, id, params, conn)

    @classmethod
    def get_connector(cls, connection_type):
        for extension in cls.extensions:
            if extension.type == "connector" and extension.connection_type == connection_type:
                return extension
        return None

    @classmethod
    def send_accept(cls, conn, method, success = True):
        if 'tcp' in cls.protocols:
            _, message = jsonrpc2_encode(f"{method}_accept", {
                "success": success
            })
            conn.send(message.encode(client_encoding))

        print (f"Accepted request with {cls.protocols[0]} protocol")

    @classmethod
    def readall(cls, conn):
        if 'tcp' in cls.protocols:
            data = b''
            while True:
                try:
                    chunk = conn.recv(cls.buffer_size)
                    if not chunk:
                        break
                    data += chunk
                except:
                    pass

            return data
        
        elif 'http' in cls.protocols:
            # empty binary when an file not exists
            if 'file' not in conn.request.files:
                return b''

            # read an uploaded file with binary mode
            file = conn.request.files['file']
            return file.read()
    
    def __init__(self):
        self.type = None
        self.method = None
        self.exported_methods = []
        self.connection_type = None

    def test(self, filtered, data, webserver, port, scheme, method, url):
        raise NotImplementedError

    def dispatch(self, type, id, params, method = None, conn = None):
        raise NotImplementedError

    def connect(self, conn, data, webserver, port, scheme, method, url):
        raise NotImplementedError
