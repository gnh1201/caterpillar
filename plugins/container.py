#!/usr/bin/python3
#
# container.py
# Linux Container (e.g. Docker) plugin for Caterpillar Proxy
#
# Caterpillar Proxy - The simple and parasitic web proxy with SPAM filter
# Namyheon Go (Catswords Research) <gnh1201@gmail.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-03-04
# Updated at: 2024-07-06
#

import docker
from socket import socket
from base import Extension, Logger

logger = Logger("Container")


class Container(Extension):
    def __init__(self):
        self.type = "rpcmethod"
        self.method = "container_init"
        self.exported_methods = [
            "container_cteate",
            "container_start",
            "container_run",
            "container_stop",
            "container_pause",
            "container_unpause",
            "container_restart",
            "container_kill",
            "container_remove",
        ]

        # docker
        self.client = docker.from_env()

    def dispatch(self, type, id, params, conn: socket):
        logger.info("[*] Greeting! dispatch")
        conn.send(b"Greeting! dispatch")

    def container_cteate(self, type, id, params, conn: socket):
        # todo: -
        return b"[*] Created"

    def container_start(self, type, id, params, conn: socket):
        name = params["name"]

        container = self.client.containers.get(name)
        container.start()

    def container_run(self, type, id, params, conn: socket):
        devices = params["devices"]
        image = params["image"]
        devices = params["devices"]
        name = params["name"]
        environment = params["environment"]
        volumes = params["volumes"]

        container = self.client.containers.run(
            image,
            devices=devices,
            name=name,
            volumes=volumes,
            environment=environment,
            detach=True,
        )
        container.logs()
        logger.info("[*] Running...")
        return b"[*] Running..."

    def container_stop(self, type, id, params, conn: socket):
        name = params["name"]

        container = self.client.containers.get(name)
        container.stop()

        logger.info("[*] Stopped")
        return b"[*] Stopped"

    def container_pause(self, type, id, params, conn: socket):
        name = params["name"]

        container = self.client.containers.get(name)
        container.pause()
        return b"[*] Paused"

    def container_unpause(self, type, id, params, conn: socket):
        name = params["name"]

        container = self.client.containers.get(name)
        container.unpause()
        return b"[*] Unpaused"

    def container_restart(self, type, id, params, conn: socket):
        name = params["name"]

        container = self.client.containers.get(name)
        container.restart()
        return b"[*] Restarted"

    def container_kill(self, type, id, params, conn: socket):
        # TODO: -
        return b"[*] Killed"

    def container_remove(self, type, id, params, conn: socket):
        name = params["name"]

        container = self.client.containers.get(name)
        container.remove()
        return b"[*] Removed"
