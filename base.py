#!/usr/bin/python3
#
# base.py
# base (common) file
#
# Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# Euiseo Cha (Wonkwang University) <zeroday0619_dev@outlook.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-05-20
# Updated at: 2024-10-08
#
import logging
import hashlib
import json
import os
import re
import importlib
import subprocess
import platform

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Union, List

client_encoding = "utf-8"


def extract_credentials(url):
    pattern = re.compile(
        r"(?P<scheme>\w+://)?(?P<username>[^:/]+):(?P<password>[^@]+)@(?P<url>.+)"
    )
    match = pattern.match(url)
    if match:
        scheme = match.group("scheme") if match.group("scheme") else "https://"
        username = match.group("username")
        password = match.group("password")
        url = match.group("url")
        return username, password, scheme + url
    else:
        return None, None, url


def jsonrpc2_create_id(data):
    return hashlib.sha1(json.dumps(data).encode(client_encoding)).hexdigest()


def jsonrpc2_encode(method, params=None):
    data = {"jsonrpc": "2.0", "method": method, "params": params}
    id = jsonrpc2_create_id(data)
    id = data.get("id")
    return (id, json.dumps(data))


def jsonrpc2_decode(text):
    data = json.loads(text)
    type = "error" if "error" in data else "result" if "result" in data else None
    id = data.get("id")
    rpcdata = data.get(type) if type else None
    return type, id, rpcdata


def jsonrpc2_result_encode(result, id=""):
    data = {"jsonrpc": "2.0", "result": result, "id": id}
    return json.dumps(data)


def jsonrpc2_error_encode(error, id=""):
    data = {"jsonrpc": "2.0", "error": error, "id": id}
    return json.dumps(data)


def find_openssl_binpath():
    system = platform.system()

    if system == "Windows":
        possible_paths = [
            os.path.join(
                os.getenv("ProgramFiles", "C:\\Program Files"),
                "OpenSSL-Win64",
                "bin",
                "openssl.exe",
            ),
            os.path.join(
                os.getenv("ProgramFiles", "C:\\Program Files"),
                "OpenSSL-Win32",
                "bin",
                "openssl.exe",
            ),
            os.path.join(
                os.getenv("ProgramFiles(x86)", "C:\\Program Files (x86)"),
                "OpenSSL-Win32",
                "bin",
                "openssl.exe",
            ),
            os.path.join(
                os.getenv("ProgramW6432", "C:\\Program Files"),
                "OpenSSL-Win64",
                "bin",
                "openssl.exe",
            ),
            os.path.join(
                os.getenv("ProgramW6432", "C:\\Program Files"),
                "OpenSSL-Win32",
                "bin",
                "openssl.exe",
            ),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
    else:
        try:
            result = subprocess.run(
                ["which", "openssl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            path = result.stdout.decode().strip()
            if path:
                return path
        except Exception:
            pass

    return "openssl"


class ExtensionType:
    def __init__(self):
        self.type: str = None
        self.method: str = None
        self.exported_methods: list[str] = []
        self.connection_type: str = None

class Extension:
    extensions: list[ExtensionType] = []
    protocols = []
    buffer_size = 8192

    @classmethod
    def set_protocol(cls, protocol):
        cls.protocols.append(protocol)

    @classmethod
    def set_buffer_size(cls, _buffer_size):
        cls.buffer_size = _buffer_size

    @classmethod
    def register(cls, s):
        module_name, class_name = s.strip().split(".")[0:2]
        module_path = "plugins." + module_name

        try:
            module = importlib.import_module(module_path)
            _class = getattr(module, class_name)
            cls.extensions.append(_class())
        except (ImportError, AttributeError):
            raise ImportError(class_name + " in the extension " + module_name)

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
            is_exported_method = (method == extension.method) or (
                method in extension.exported_methods
            )
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
            if (
                extension.type == "connector"
                and extension.connection_type == connection_type
            ):
                return extension
        return None

    @classmethod
    def send_accept(cls, conn, method, success=True):
        if "tcp" in cls.protocols:
            _, message = jsonrpc2_encode(f"{method}_accept", {"success": success})
            conn.send(message.encode(client_encoding))

        print(f"Accepted request with {cls.protocols[0]} protocol")

    @classmethod
    def readall(cls, conn):
        if "tcp" in cls.protocols:
            data = b""
            while True:
                try:
                    chunk = conn.recv(cls.buffer_size)
                    if not chunk:
                        break
                    data += chunk
                except:
                    pass

            return data

        elif "http" in cls.protocols:
            # empty binary when an file not exists
            if "file" not in conn.request.files:
                return b""

            # read an uploaded file with binary mode
            file = conn.request.files["file"]
            return file.read()

    def __init__(self):
        self.type = None
        self.method = None
        self.exported_methods = []
        self.connection_type = None

    def test(self, filtered, data, webserver, port, scheme, method, url):
        raise NotImplementedError

    def dispatch(self, type, id, params, method=None, conn=None):
        raise NotImplementedError

    def connect(self, conn, data, webserver, port, scheme, method, url):
        raise NotImplementedError


class Logger(logging.Logger):
    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name, level)
        self.formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s %(module)s: %(message)s"
        )

        if not os.path.isdir("logs"):
            os.mkdir("logs")
        stream_handler = logging.StreamHandler()
        file_handler = logging.FileHandler(
            "logs/" + name + "-" + self._generate_timestamp() + ".log"
        )

        self._set_formatters([stream_handler, file_handler])
        self._add_handlers([stream_handler, file_handler])

    @staticmethod
    def _generate_timestamp():
        date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        return date

    def _set_formatters(
        self, handlers: List[Union[logging.StreamHandler, logging.FileHandler]]
    ):
        for handler in handlers:
            handler.setFormatter(self.formatter)

    def _add_handlers(
        self, handlers: List[Union[logging.StreamHandler, logging.FileHandler]]
    ):
        for handler in handlers:
            self.addHandler(handler)
