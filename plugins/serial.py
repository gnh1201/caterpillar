#!/usr/bin/python3
#
# serial.py
# Serial integration plugin for Caterpillar Proxy
#
# Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
# Teakwoo Kim <catry.me@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-08-11
# Updated at: 2024-08-11
#

import serial
from decouple import config
from base import Extension, Logger

logger = Logger(name="serial")

try:
    client_encoding = config("CLIENT_ENCODING")
except Exception as e:
    logger.error("[*] Invalid configuration", exc_info=e)

import logging

logger = logging.getLogger(__name__)


class Serial(Extension):
    def __init__(self):
        self.type = "connector"
        self.connection_type = "serial"

    def dispatch(self, type, id, params, conn):
        logger.info("[*] Greeting! dispatch")
        conn.send(b"Greeting! dispatch")

    def connect(self, conn, data, webserver, port, scheme, method, url):
        connected = False
        ser = None
        try:
            port_path = url.decode(client_encoding).replace("/", "")
            if not ser:
                ser = serial.Serial(port_path, baudrate=9600, timeout=2)
                connected = True
            logger.debug(f"Connected to {port_path} at 9600 baudrate")

            ser.write(data)
            logger.debug(f"Data sent to {port_path}: {data}")

            ser_data = ser.read_all()
            logger.debug(f"Data received: {ser_data}")

            if ser_data:
                conn.send(ser_data.decode(client_encoding))
        except serial.SerialException as e:
            logger.error(f"Failed to connect to {port}", exc_info=e)
        finally:
            if ser and ser.is_open:
                ser.close()
            logger.debug(f"Serial port {port_path} closed")
        return connected
