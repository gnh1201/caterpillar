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

import os
import sys
from decouple import config
from flask import Flask, request, render_template
from base import Extension, jsonrpc2_error_encode, Logger

# TODO: 나중에 Flask 커스텀 핸들러 구현 해야 함
logger = Logger(name="web")
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "data/"
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])


@app.route("/")
def upload_form():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def process_upload():
    # make connection profile from Flask request
    conn = Connection(request)

    # pass to the method
    method = request.form["method"]
    filename = request.files["file"].filename
    params = {"filename": filename}

    # just do it
    return Extension.dispatch_rpcmethod(method, "call", "", params, conn)


@app.route("/jsonrpc2", methods=["POST"])
def process_jsonrpc2():
    # make connection profile from Flask request
    conn = Connection(request)

    # JSON-RPC 2.0 request
    jsondata = request.get_json(silent=True)
    if jsondata["jsonrpc"] == "2.0":
        return Extension.dispatch_rpcmethod(
            jsondata["method"], "call", jsondata["id"], jsondata["params"], conn
        )

    # when error
    return jsonrpc2_error_encode({"message": "Not vaild JSON-RPC 2.0 request"})


def jsonrpc2_server(conn, id, method, params):
    return Extension.dispatch_rpcmethod(method, "call", id, params, conn)


class Connection:
    def send(self, data):
        self.messages.append(data)

    def recv(self, size):
        logger.info("Not allowed method")

    def close(self):
        logger.info("Not allowed method")

    def __init__(self, req):
        self.messages = []
        self.request = req


if __name__ == "__main__":
    # initialization
    try:
        listening_port = config("PORT", default=5555, cast=int)
        client_encoding = config("CLIENT_ENCODING", default="utf-8")
        use_extensions = config("USE_EXTENSIONS", default="")
    except KeyboardInterrupt:
        logger.warning("[*] User has requested an interrupt")
        logger.warning("[*] Application Exiting.....")
        sys.exit()
    except Exception as e:
        logger.error("[*] Failed to initialize", exc_info=e)

    # set environment of Extension
    Extension.set_protocol("http")

    # Fix Value error
    if use_extensions:
        # load extensions
        for s in use_extensions.split(","):
            Extension.register(s)
    else:
        logger.warning("[*] No extensions registered")

    app.run(debug=True, host="0.0.0.0", port=listening_port)
