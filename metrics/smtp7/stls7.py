import json
import logging
import random
import socket
import socketserver
import uuid
from threading import Thread
from time import sleep


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

class ClientSTLS7:

    def conductSingePortTest(self, host, port, test_uuid):
        """
        Simulate a SMTP client
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

        # send EHLO
        sock.sendall(bytes("EHLO {}\r\n".format(test_uuid),"utf-8"))

        # wait for server response
        data = str(sock.recv(1024), "utf-8")
        received += data

        # send STARTTLS
        sock.sendall(bytes("STARTTLS\r\n", "utf-8"))

        # wait for server response
        data = str(sock.recv(1024), "utf-8")
        received += data

        #close connection
        sock.close()

        return received


    def conductTest(self, test_params):
        received_answers = {}

        for port in test_params["ports"]:
            received_answers[port] = {}
            received = self.conductSingePortTest(test_params["host"], port, test_params["test_uuid"])
            received_answers[port]["received"] = received
            LOGGER.info("conducted STLS7 test, got: {}".format(received))

        return received_answers

received_answers = {}
sent_answers = {}
use_valid_responses = True
port_offset = 0

class ServerSTLS7:

    class SMTPRequestHandler(socketserver.BaseRequestHandler):
        def handle(self):
            """
            Simulate a SMTP server
            :return:
            """

            # send 220 ready
            self.request.sendall(bytes("220 mail.secure.org ESMTP service ready\r\n", "utf-8"))

            # client sends EHLO
            self.data = self.request.recv(1024).strip()
            if (len(self.data) == 0):
                return

            # extract test uuid
            test_uuid = str(self.data[5:],"utf-8")
            (host, port) = self.server.server_address

            # maybe there is a port offset
            if port_offset > 0:
                if port_offset < port and port < (port_offset + 1024):
                    port -= port_offset

            server_response = "250-mail.secure.org\r\n" \
                              "250-PIPELINING\r\n250-SIZE 15728640\r\n250-VRFY\r\n250-ETRN\r\n" \
                              "250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n"

            if not use_valid_responses:
                server_response = server_response.replace("250",str(random.randint(1,400)))

            # send back some server info
            self.request.sendall(bytes(server_response,"utf-8"))

            sent_answers[port][test_uuid] = server_response

            # receive again
            self.data = self.request.recv(1024).strip()

            received_answers[port][test_uuid] = str(self.data,"utf-8")

            self.request.sendall(bytes("220 2.0.0 Ready to start TLS\r\n","utf-8"))

            # end it here


    def startupServer(self, config, startInThread=True):
        global port_offset, use_valid_responses

        self.is_running = True
        self.server = {}
        ports = config["configuration"]["ports"]
        if "port_offset" in config["configuration"]:
            port_offset = int(config["configuration"]["port_offset"])

        use_valid_responses = config["configuration"]["valid_response"]

        # So we dont have to wait for TCP TIME_WAIT
        socketserver.TCPServer.allow_reuse_address = True
        for port in ports:
            received_answers[port] = {}
            received_answers[port - port_offset] = {}
            sent_answers[port] = {}
            sent_answers[port - port_offset] = {}
            self.server[port] = socketserver.TCPServer(("", port), self.SMTPRequestHandler)

            # start in new thread so we can listen for shutdown requests
            t = Thread(target=self.server[port].serve_forever)
            if startInThread:
                t.start()
            else:
                t.run()
        LOGGER.info("started stls7 server on ports: " + str(ports))


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
                        received_answers[int_port][test_uuid] == "STARTTLS":
            del received_answers[int_port][test_uuid]
            test_results[port]["starttls_server_received"] = True
        else:
            test_results[port]["starttls_server_received"] = False

        if "STARTTLS" in results[port]["received"]:
            test_results[port]["starttls_client_received"] = True
        else:
            test_results[port]["starttls_client_received"] = False

        # identical server-response
        if test_uuid in sent_answers[int_port] and \
                        sent_answers[int_port][test_uuid] in v["received"]:
            test_results[port]["content_integrity"] = True
            del sent_answers[int_port][test_uuid]
        else:
            test_results[port]["content_integrity"] = False


    return test_results


def main():
    # sent from the server when requesting permission to conduct a test

    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "ports": [8025,8026],
        "test_uuid" : test_uuid,
        "valid_response" : True
    }
    config = {
        "configuration" : test_config
    }

    server = ServerSTLS7()
    server.startupServer(config, True)
    sleep(1)

    client = ClientSTLS7()
    result = client.conductTest(test_config)
    print(json.dumps(result,indent=4))
    s_result = validateClientResults(test_uuid,result)
    print(json.dumps(s_result, indent=4))

    server.shutdownServer()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

    main()
