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

from base import Extension, Logger

logger = Logger("Container")


class Container(Extension):
    def __init__(self):
        self.type = "rpcmethod"
        self.method = "container_init"
        self.exported_methods = ["container_run", "container_stop"]

        # docker
        self.client = docker.from_env()

    def dispatch(self, type, id, params, conn):
        logger.info("[*] Greeting! dispatch")
        conn.send(b'Greeting! dispatch')

    def container_run(self, type, id, params, conn):
        devices = params['devices']
        image = params['image']
        devices = params['devices']
        name = params['name']
        environment = params['environment']
        volumes = params['volumes']

        container = self.client.containers.run(
            image,
            devices=devices,
            name=name,
            volumes=volumes,
            environment=environment,
            detach=True
        )
        container.logs()

        logger.info("[*] Running...")

    def container_stop(self, type, id, params, conn):
        name = params['name']

        container = self.client.containers.get(name)
        container.stop()

        logger.info("[*] Stopped")

