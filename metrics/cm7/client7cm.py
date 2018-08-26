import logging
import socket
import sys
import hashlib
import uuid
import json

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

class Client7cm:

    def sendRequest(self, host, port, request):
        try:
            # Connect to server and send data
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.sendall(bytes(request + "\r\n\r\n", "utf-8"))

            # Receive data from the server and shut down

            length = 0
            socket_as_file = sock.makefile("rb")
            http_header = ""
            while True:
                line = str(socket_as_file.readline().rstrip(), "utf-8")
                http_header += line + "\r\n"
                LOGGER.debug("line: " + line)
                if line.find("Content-Length") == 0:
                    length = int(line.split(" ")[1])
                if len(line) == 0:
                    # last line - break
                    break

            # This is HTTP - check out the body length
            LOGGER.debug("expecting {} bytes".format(length))
            received = socket_as_file.read(length)

            result = {
                "header": hashlib.sha256(bytes(http_header, "utf-8")).hexdigest(),
                "body": hashlib.sha256(received).hexdigest()
            }

            LOGGER.debug("hash of HTTP header: " + result["header"])
            LOGGER.debug("hash of HTTP body: " + result["body"])

            return result


        finally:
            sock.close()


    def conductTest(self, config):
        test_result = {"requests": []}

        for request in config["requests"]:
            result = self.sendRequest(config["host"], config["port"], request)
            result["request"] = request
            test_result["requests"].append(result)

        json_result = json.dumps(test_result, indent=4)
        LOGGER.debug("Results: " + json_result)
        return test_result


def main():
    # sent from the server when requesting permission to conduct a test
    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "port": 8081,
        "requests": [
            "GET /{0}/image1.bmp HTTP/1.1",
            "GET /{0}/image1.jpg HTTP/1.1",
            "GET /{0}/image2.jpg HTTP/1.1",
            "GET /{0}/image2.jpg HTTP/1.1",
            "GET /{0}/image2.jpg HTTP/1.1",
            "GET /{0}/faultyResponse HTTP/1.1"
        ]
    }
    test_config["requests"] = [r.format(test_uuid) for r in test_config["requests"]]

    test7cm = Client7cm()
    test7cm.conductTest(test_config)


if __name__ == "__main__":
   main()
