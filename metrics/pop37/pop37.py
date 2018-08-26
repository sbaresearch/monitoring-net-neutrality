import json
import logging
import socket
import socketserver
import uuid
from threading import Thread
from time import sleep


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

class ClientPOP37:

    def conductSingePortTest(self, host, port, test_uuid):
        """
        Simulate a POP3 client
        :param host:
        :param port:
        :param test_uuid:
        :return:
        """
        received = ""

        # Connect to server and send data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # wait for server greetings
        data = str(sock.recv(1024), "utf-8")
        received += data

        # send USER
        sock.sendall(bytes("USER info@secure,ail.org {}\r\n".format(test_uuid),"utf-8"))

        # wait for server response
        data = str(sock.recv(1024), "utf-8")
        received += data

        # send PASS
        sock.sendall(bytes("PASS {}\r\n".format(test_uuid), "utf-8"))

        #close connection
        sock.close()

        return received


    def conductTest(self, test_params):
        received_answers = {}

        for port in test_params["ports"]:
            received_answers[port] = {}
            received = self.conductSingePortTest(test_params["host"], port, test_params["test_uuid"])
            received_answers[port]["received"] = received
            LOGGER.info("conducted POP37 test, got: {}".format(received))

        return received_answers

received_answers = {}
port_offset = 0
class ServerPOP37:

    class POP3RequestHandler(socketserver.BaseRequestHandler):
        def handle(self):
            """
            Simulate a POP3 server
            :return:
            """

            complete_conversation = ""
            (host, port) = self.server.server_address

            # maybe there is a port offset
            if port_offset > 0:
                if port_offset < port and port < (port_offset+1024):
                    port -= port_offset

            # send 220 ready
            self.request.sendall(bytes("+OK POP3 perditon ready on mail.secure.org 000391eb\r\n", "utf-8"))

            # client sends USER
            self.data = self.request.recv(1024)
            complete_conversation += str(self.data,"utf-8")
            if (len(self.data) == 0):
                return

            if str(self.data,"utf-8").startswith("USER"):
                self.request.sendall(bytes("+OK USER info@secure,ail.org, Please enter password\r\n","utf-8"))
                self.data = self.request.recv(1024)
                complete_conversation += str(self.data, "utf-8")

            # extract test uuid
            if str(self.data,"utf-8").startswith("PASS"):
                test_uuid = str(self.data[5:], "utf-8")


            # end it here
            self.request.close()

            received_answers[port][test_uuid] = complete_conversation


    def startupServer(self, config, startInThread=True):
        global port_offset
        self.server = {}
        ports = config["configuration"]["ports"]
        if "port_offset" in config["configuration"]:
            port_offset = int(config["configuration"]["port_offset"])

        # So we dont have to wait for TCP TIME_WAIT
        socketserver.TCPServer.allow_reuse_address = True
        for port in ports:
            received_answers[port] = {}
            received_answers[port - port_offset] = {}
            self.server[port] = socketserver.TCPServer(("", port), self.POP3RequestHandler)

            # start in new thread so we can listen for shutdown requests
            t = Thread(target=self.server[port].serve_forever)
            if startInThread:
                t.start()
            else:
                t.run()
        self.is_running = True
        LOGGER.info("started pop37 server on ports: " + str(ports))


    def shutdownServer(self):
        if self.is_running:
            LOGGER.info("stopping test servers for stls7")
            for server in self.server.values():
                server.shutdown()
                # Close the server to free the port
                server.server_close()
            self.is_running = False


def validateClientResults(test_uuid, results):
    """
    Validate if the client received "STARTTLS" and if the server received
    the "STARTTLS"-command from the client
    :param test_uuid:
    :param results:
    :return:
    """
    test_results = {}
    for (port,v) in results.items():
        test_results[port] = {}
        int_port = int(port)
        if test_uuid in received_answers[int_port] and \
                        received_answers[int_port][test_uuid] == "secure,ail.org":
            del received_answers[int_port][test_uuid]
            test_results[port]["invalid_address_received"] = True
        else:
            test_results[port]["invalid_address_received"] = False

        if "secure,ail.org" in results[port]["received"]:
            test_results[port]["invalid_address_received"] = True
        else:
            test_results[port]["invalid_address_received"] = False


    return test_results


def main():
    # sent from the server when requesting permission to conduct a test

    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "ports": [444,8026],
        "port_offset" : 400,
        "test_uuid" : test_uuid
    }
    config = {
        "configuration" : test_config
    }

    server = ServerPOP37()
    server.startupServer(config, True)
    sleep(1)

    client = ClientPOP37()
    result = client.conductTest(test_config)
    print(json.dumps(result,indent=4))
    s_result = validateClientResults(test_uuid,result)
    print(json.dumps(s_result, indent=4))

    server.shutdownServer()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

    main()
