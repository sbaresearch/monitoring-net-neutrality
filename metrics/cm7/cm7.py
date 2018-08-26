import logging
import mimetypes
import re
import socket
import socketserver
import sys
import hashlib
import uuid
import json
from threading import Thread
from time import sleep

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

PATH_TO_RESOURCES = "./metrics/cm7/resources/"

CUSTOM_RESPONSES = {
    "googlevideo": {
        "header": "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Credentials: true\r\nAlt-Svc: quic=\":443\"; ma=2592000\r\nAlternate-Protocol: 443:quic\r\nCache-Control: private, max-age=21293\r\nConnection: keep-alive\r\nContent-Length: 10\r\nContent-Type: video/webm",
        "body" : "0123456789"
    }
}

class ClientCM7:

    def sendRequest(self, host, port, request):
        try:
            # Connect to server and send data
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))

            get_request = request["resource"]
            if "header" in request:
                get_request += "\r\n" + "\r\n".join(request["header"])
            get_request += "\r\n\r\n"

            sock.sendall(bytes(get_request, "utf-8"))

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
            repeat = config["repeat"] if "repeat" in config else 1
            for i in range(repeat):
                result = self.sendRequest(config["host"], config["port"], request)
                result["request"] = request
                test_result["requests"].append(result)

        json_result = json.dumps(test_result, indent=4)
        LOGGER.debug("Results: " + json_result)
        return test_result



sentResponses = {}

class ServerCM7:
    is_runnung = True

    def __init__(self):
        self.is_running = False

    class CMRequestHandler (socketserver.BaseRequestHandler):
        def handle(self):
            self.data = self.request.recv(1024)

            # receive until \r\n\r\n is reached
            while self.data is None or not str(self.data,"utf-8").endswith("\r\n\r\n"):
                self.data += self.request.recv(1024)

            print("message from {}".format(self.client_address[0]))
            full_request = str(self.data,"utf-8")

            #extract get resource
            firstLine = str(self.data,"utf-8").split("\r\n")[0]
            getResource = firstLine.split(" ")[1]


            #switch depending on test
            if getResource.find("image1.bmp")>0:
                ret = self.buildHttpResourceResponse("image1.bmp")
            elif getResource.find("image1.jpg") > 0:
                ret = self.buildHttpResourceResponse("image1.jpg")
            elif getResource.find("image2.jpg") > 0:
                ret = self.buildHttpResourceResponse("image2.jpg",True,"Cache-Control: max-age=600, public\r\n")
            elif getResource.find("faultyResponse") > 0:
                ret = self.buildHttpResourceResponse("testfile.txt",False)
            elif getResource.find("eicar.exe") > 0:
                ret = self.buildHttpResourceResponse("eicar.exe")
            elif full_request.find("googlevideo.com")>0:
                ret = self.buildCustomHttpResponse("googlevideo")

            #get test uuid from resource anywhere
            uuid_pattern = re.compile(".*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).*", re.IGNORECASE)
            test_uuid = uuid_pattern.search(full_request).group(1)

            # test_uuid = getResource.split("/")[1]


            #send back answer
            self.request.sendall(ret[0])

            ret[1]["request"] = firstLine
            print("test uuid: {} \r\n{}".format(test_uuid,json.dumps(ret[1],indent=4)))

            if not test_uuid in sentResponses:
                sentResponses[test_uuid] = []
            sentResponses[test_uuid].append(ret[1])

        def buildCustomHttpResponse(self, key):
            """
            Builds a custom http response as given by the key
            :param key:
            :return:
            """

            header = bytes(CUSTOM_RESPONSES[key]["header"] + "\r\n\r\n","utf-8")
            body = bytes(CUSTOM_RESPONSES[key]["body"],"utf-8")

            ret = header + body
            response = {
                "header" : hashlib.sha256(header).hexdigest(),
                "body": hashlib.sha256(body).hexdigest()
            }
            return (ret, response)

        def buildHttpResourceResponse(self, filename, validRequest=True, additionalFields=""):
            """
            Build a HTTP response
            :param filename: the filename located in cm7/resources or "eicar.exe" for a eicar test payload
            :param validRequest: True if the request should be valid http
            :param additionalFields: additional header fields
            :return:
            """
            if filename == "eicar.exe":
                body = bytes("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*","utf-8")
            else:
                file = open(PATH_TO_RESOURCES + filename, "rb")
                body = file.read()
                file.close()
            length = len(body)
            mimetype = mimetypes.guess_type(filename)[0]

            # build HTTP response
            http_header = "{}\r\n" \
                          "Content-Length: {}\r\n" \
                          "Content-Language: en\r\n" \
                          "Content-Type: {}\r\n" \
                          "\r\n".format(
                ("HTTP/1.1 200 OK" if validRequest else self.getFaultyResponse()),
                length, mimetype, additionalFields)
            http_header = bytes(http_header, "utf-8")

            ret = http_header + body

            response = {
                "header": hashlib.sha256(http_header).hexdigest(),
                "body": hashlib.sha256(body).hexdigest()
            }

            return (ret, response)

        def getFaultyResponse(self):
            # @TODO randomize?
            return "HTTP/79.2 404 OK"

    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        pass


    #create socket server

    def startupServer(self, config, startInThread = True):
        print("Starting test server for cm7")
        # So we dont have to wait for TCP TIME_WAIT
        socketserver.TCPServer.allow_reuse_address = True
        self.server = self.ThreadedTCPServer(("", config["configuration"]["port"]), self.CMRequestHandler)


        #start in new thread so we can listen for shutdown requests
        t = Thread(target=self.server.serve_forever)
        if startInThread:
            t.start()
        else:
            t.run()
        self.is_running=True

    def shutdownServer(self):
        if self.is_running:
            print("Stopping test server for cm7")
            self.server.shutdown()
            # Close the server to free the port
            self.server.server_close()
            self.is_running=False



def validateClientResults(testuuid, results):
    testresults = {}
    #testresults["client"] = list(results)
    #testresults["server"] = list(sentResponses[testuuid])
    testresults["matches"] = []
    testresults["mismatches"] = []

    sent = sentResponses[testuuid]
    for result in list(results["requests"]): #iterate over a shallow copy to allow removing elements
        #find matching sent response from server and compare all fields
        match = list(filter(lambda s:s["request"]==result["request"]["resource"],sent))
        if len(match) == 0:
            print("Missing server request: " + result["request"]["resource"])
        match = match[0]
        sent.remove(match)

        matchResult = {
            "request": result["request"],
            "header": {
                "server": result["header"],
                "client": match["header"]
            },
            "body": {
                "server": result["body"],
                "client": result["body"]
            }
        }

        #compare
        if (match["request"] == result["request"]["resource"] and
            match["header"] == result["header"] and
            match["body"] == result["body"]):
            print("Matching for {}".format(match["request"]))
            testresults["matches"].append(matchResult)
        else:
            print("Mismatch! {}\n{} - {}\n{} {}".format(result["request"]["resource"],
                                                        match["header"],result["header"],
                                                        match["body"], result["body"]))
            testresults["mismatches"].append(matchResult)

        #remove from the array
        results["requests"].remove(result)

    #if there are any server responses left - fail!
    if len(sent) > 0:
        print("No matching response for: {}".format(str(sent)))
        testresults["leftover"] = list(sent)
    else:
        testresults["leftover"] = []
        print("Test cm7 for {} successful".format(testuuid))

    return testresults


def main():
    global PATH_TO_RESOURCES
    PATH_TO_RESOURCES = "./resources/"

    # sent from the server when requesting permission to conduct a test
    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "port": 8081,
        "requests": [
            {
                "resource" : "GET /{0}/image1.bmp HTTP/1.1".format(test_uuid)
            },
            {
                "resource": "GET /{0}/image1.bmp HTTP/1.1".format(test_uuid)
            },
            {
                "resource": "GET /{0}/image2.jpg HTTP/1.1".format(test_uuid),
                "repeat": 3
            },
            {
                "resource" : "GET /{0}/faultyResponse HTTP/1.1".format(test_uuid)
            },
            {
                "resource" : "GET /videoplayback?mime=video/webm&dur=610.640&upn=q_PY3To1fWI HTTP/1.1",
                "header": [
                    "Host: r1---sn-4g5edne7.googlevideo.com",
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language: de,en-US;q=0.7,en;q=0.3",
                    "Accept-Encoding: gzip, deflate, br",
                    "X-Test: {}".format(test_uuid)
                    ]
            }
        ]
    }

    config = {
        "configuration": test_config
    }

    server = ServerCM7()
    server.startupServer(config, True)
    sleep(1)

    client = ClientCM7()
    result = client.conductTest(test_config)
    print(json.dumps(result, indent=4))

    s_result = validateClientResults(test_uuid,result)
    print(json.dumps(s_result, indent=4))

    server.shutdownServer()


if __name__ == "__main__":
    main()
