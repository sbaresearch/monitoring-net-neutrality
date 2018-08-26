import json
import logging
import socketserver
import uuid
from threading import Thread
from time import sleep
from scapy.all import *
from scapy.layers.inet import IP, TCP

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

class ClientSyn4:
    # https://github.com/arthurnn/SynFlood/blob/master/synflood

    def sendSingleSyn(self, host, port, source_port):
        """
        Send a single SYN packet to the given host
        :param host:
        :param port:
        :param source_port:
        :return: True, if a SYN-ACK was received
        """
        LOGGER.debug("sending SYN packet to {}:{} from port {}".
                     format(host, port, source_port))
        i = IP()
        i.dst = host

        t = TCP()
        t.sport = source_port
        t.dport = port
        t.flags = 'S'

        p = sr1(i / t, timeout=2) # wait for max 2 seconds
        return p is not None


    def conductTest(self, test_params):
        results = {}
        used_ports = []
        answers=0
        for i in range(test_params["count"]):
            random_port = random.randint(test_params["source_port"]["min"], test_params["source_port"]["max"])
            used_ports.append(random_port)
            synack = self.sendSingleSyn(test_params["host"], test_params["port"],random_port)
            if synack:
                answers += 1

        return {
            "used_ports": used_ports,
            "answers" : answers
        }


class ServerSyn4:
    is_running = False

    def __init__(self):
        self.is_running = False

    class CMRequestHandler(socketserver.BaseRequestHandler):
        def handle(self):
            print("message from {}".format(self.client_address[0]))

    def startupServer(self, config, startInThread=True):
        print("Starting test server for syn4")
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer(("", config["configuration"]["port"]), self.CMRequestHandler)

        # start in new thread so we can listen for shutdown requests
        t = Thread(target=self.server.serve_forever)
        if startInThread:
            t.start()
        else:
            t.run()
        self.is_running = True

    def shutdownServer(self):
        if self.is_running:
            print("Stopping test server for syn4")
            self.server.server_close()

def main():
    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "port": 12348,
        "count": 20,
        "source_port": {
            "min": 40234,
            "max" : 41453
        }
    }
    config = {
        "configuration": test_config
    }

    server = ServerSyn4()
    server.startupServer(config, True)
    sleep(3)

    client = ClientSyn4()
    result = client.conductTest(test_config)
    LOGGER.info(json.dumps(result,indent=4))

    server.shutdownServer()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')
    main()