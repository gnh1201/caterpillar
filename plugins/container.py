import docker

class Container(Extension):
    def __init__(self):
        self.type = "rpcmethod"
        self.method = "container_init"
        self.exported_methods = ["container_run", "container_stop"]

    def dispatch(self, type, id, params, conn):
        pass

    def container_run(self, type, id, params, conn):
        # todo
        pass

    def container_stop(self, type, id, params, conn):
        # todo
        pass
