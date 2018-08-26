import socketserver
import mimetypes
import hashlib
import json
from threading import Thread


sentResponses = {}

class Server7cm:
    is_runnung = True

    def __init__(self):
        self.is_running = False

    class CMRequestHandler (socketserver.BaseRequestHandler):
        def handle(self):
            self.data = self.request.recv(1024).strip()
            print("message from {}".format(self.client_address[0]))

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

            #get test uuid from resource
            test_uuid = getResource.split("/")[1]


            #send back answer
            self.request.sendall(ret[0])

            ret[1]["request"] = firstLine
            print("test uuid: {} \r\n{}".format(test_uuid,json.dumps(ret[1],indent=4)))

            if not test_uuid in sentResponses:
                sentResponses[test_uuid] = []
            sentResponses[test_uuid].append(ret[1])

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
                file = open("./metrics/cm7/resources/" + filename, "rb")
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


    #create socket server

    def startupServer(self, config, startInThread = True):
        print("Starting test server for cm7")
        self.is_running = True
        # So we dont have to wait for TCP TIME_WAIT
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer(("", config["configuration"]["port"]), self.CMRequestHandler)


        #start in new thread so we can listen for shutdown requests
        t = Thread(target=self.server.serve_forever)
        if startInThread:
            t.start()
        else:
            t.run()

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
        match = list(filter(lambda s:s["request"]==result["request"],sent))
        if len(match) == 0:
            print("Missing server request: " + result["request"])
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
        if (match["request"] == result["request"] and
            match["header"] == result["header"] and
            match["body"] == result["body"]):
            print("Matching for {}".format(match["request"]))
            testresults["matches"].append(matchResult)
        else:
            print("Mismatch! {}\n{} - {}\n{} {}".format(result["request"],
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
    # sent from the server when requesting permission to conduct a test
    server = Server7cm()
    config = {
        "configuration": {
            "port": 8082
        }
    }
    server.startupServer(config, False)



if __name__ == "__main__":
    main()
