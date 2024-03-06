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
        image = params['image']
        environment = params['environment']

        container = client.containers.run(image=image, environment=environment, detach=True)
        container.logs()

    def container_stop(self, type, id, params, conn):
        print ("[*] Greeting! container_stop")
        # todo
        pass
