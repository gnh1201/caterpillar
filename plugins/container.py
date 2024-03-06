import docker

from server import Extension

class Container(Extension):
    def __init__(self):
        self.type = "rpcmethod"
        self.method = "container_init"
        self.exported_methods = ["container_run", "container_stop"]

        # docker
        self.client = docker.from_env()

    def dispatch(self, type, id, params, conn):
        print ("[*] Greeting! dispatch")
        pass

    def container_run(self, type, id, params, conn):
        devices = params['devices']
        image = params['image']
        devices = params['devices']
        name = params['name']
        environment = params['environment']
        volumes = params['volumes']

        container = client.containers.run(
            image,
            devices=devices,
            name=name,
            volumes=volumes,
            environment=environment,
            detach=True
        )
        container.logs()

        print ("[*] Running...")

    def container_stop(self, type, id, params, conn):
        name = params['name']

        container = client.containers.get(name)
        container.stop()

        print ("[*] Stopped")

