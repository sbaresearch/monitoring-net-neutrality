import json
import logging
import os
import re
import socket
import socketserver
import uuid
import time
from threading import Thread
from time import sleep

import select

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

_TIMESTAMP_DIFF_MS = 50

def _downloadBytes(socket, packet_size, request_with = None):
    """
    Download byte arrays of size packet_size until a byte ends with 0xff
    :param socket:
    :param packet_size:
    :return:
    """

    # if specified, begin with a http request
    if request_with:
        socket.sendall(bytes(request_with,"utf-8"))

        # and wait for answer from the server
        lines = ""
        while True:
            lines += str(socket.recv(1),"utf-8");
            if lines.endswith("\r\n\r\n"):
                break;
        LOGGER.debug(lines)

    # receive packets, count
    received_bytes = 0
    timestamp_start = time.time()
    last_timestamp = time.time()
    speed_curve = []
    socket_closed = False

    while True:
        received = b''
        while len(received) < packet_size:
            missing = packet_size - len(received)

            r, _, _ = select.select([socket], [], [], 2)
            if not r:
                socket_closed = True
                break
            now_received = socket.recv(missing)
            if len(now_received) == 0:
                socket_closed = True
                break

            received += now_received
        received_bytes += packet_size
        current_time = time.time()
        if (current_time - last_timestamp)*1e3>_TIMESTAMP_DIFF_MS:
            speed_curve.append({
                "time_elapsed": int((current_time - timestamp_start) * 1e3),
                "bytes_total": received_bytes
            })
            last_timestamp = current_time

        if socket_closed or received[packet_size - 1] == 0xff:
            break

    duration_down = time.time() - timestamp_start

    # append last item
    speed_curve.append({
        "time_elapsed": int(duration_down * 1e3),
        "bytes_total": received_bytes
    })

    return {
        "duration_ms": int(duration_down * 1e3),
        "bytes": received_bytes,
        "speed_curve": speed_curve
    }


def _uploadBytes(socket, duration_ms, packet_size, answer_with = None):
    """
    Send byte arrays of size packet_size with end 0x00 until the duration_ms milliseconds
    have passed, then send a byte array with end 0xff
    :param socket:
    :param duration_ms:
    :param packet_size:
    :return:
    """

    # if answer_with is specified, we wait for a request
    if answer_with:
        lines = ""
        while True:
            lines += str(socket.recv(1), "utf-8");
            if lines.endswith("\r\n\r\n"):
                break;
        LOGGER.debug(lines)

        # send answer
        socket.sendall(bytes(answer_with,"utf-8"))

    timestamp_start = time.time() * 1000
    sent_packets = 0
    while (time.time() * 1000 - timestamp_start) < duration_ms:
        random_bytes = os.urandom(packet_size - 1)
        random_bytes += b'\x00'
        socket.sendall(random_bytes)
        sent_packets +=1

    random_bytes = os.urandom(packet_size - 1)
    random_bytes += b'\xff'
    socket.sendall(random_bytes)
    sent_packets += 1
    duration_up = time.time() * 1000 - timestamp_start


    return {
        "duration_ms" : int(duration_up),
        "bytes" : sent_packets * packet_size
    }

class ClientTCPS4:
    def conductSinglePortTest(self, host, port, duration_ms, packet_size, test_uuid, request_with = None, answer_with = None):
        # Connect to server and send data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # initiate directly with a HTTP GET request if simulating a HTTP stream
        # after that, directly start the download test
        if request_with:
            get_request = "GET /{0}/{1}/{2}/".format(test_uuid,str(duration_ms),str(answer_with))
            get_request = request_with.splitlines()[0].replace("GET /",get_request)

            sock.sendall(bytes(get_request,"utf-8"))

        else:
            # send TEST test_uuid
            sock.sendall(bytes("TEST {}\n".format(test_uuid), "utf-8"))

            # wait for OK
            data = str(sock.recv(1024), "utf-8")

            if not data == "OK\n":
                return

            # initiate download test
            sock.sendall(bytes("DOWN {}\n".format(duration_ms), "utf-8"))

        # start DOWN
        LOGGER.debug("Starting download speed test on port {} with size {}b for {}ms".format(port, packet_size, duration_ms))

        download_test_result = _downloadBytes(sock, packet_size, request_with)
        LOGGER.debug("download test finished")

        upload_test_result = {}
        # no upload test for mm7
        if not request_with:
            # start UP
            LOGGER.debug("Starting upload speed test on port {} with size {}b for {}ms".format(port, packet_size, duration_ms))
            sock.sendall(bytes("UP {}\n".format(duration_ms), "utf-8"))

            # wait for OK
            data = str(sock.recv(1024), "utf-8")

            if not data == "OK\n":
                return

            upload_test_result = _uploadBytes(sock, duration_ms, packet_size)
            LOGGER.debug("upload test finished")

            #send END
            sock.sendall(bytes("END {}\n".format(duration_ms), "utf-8"))

            # wait for OK (or socket close)
            data = str(sock.recv(1024), "utf-8")

        sock.close()

        return {
            "download" : download_test_result,
            "upload" : upload_test_result
        }



    def conductTest(self, test_params):
        results={}
        # start recording
        for port in test_params["ports"]:
            result = self.conductSinglePortTest(test_params["host"], port["port"], test_params["test_duration_ms"],
                                       test_params["packet_size"], test_params["test_uuid"],
                                                request_with= test_params["http_headers"][port["request_with"]]["header"] if "request_with" in port else None,
                                                answer_with= port["answer_with"] if "answer_with" in port else None)
            results[port["port"]] = result
            if "answer_with" in port:
                results[port["port"]]["answer_with"] = port["answer_with"]
            if "request_with" in port:
                results[port["port"]]["request_with"] = port["request_with"]



        return results

packet_size = -1
server_test_results={}
server_answers=[]
port_offset = 0

class ServerTCPS4:
    is_running = False

    class CMRequestHandler(socketserver.BaseRequestHandler):

        def handle(self):
            global server_test_results
            (host, port) = self.server.server_address
            if port_offset > 0:
                if port_offset < port and port < (port_offset + 1024):
                    port -= port_offset

            LOGGER.debug("Starting speed test on server side for port {} on host {}".format(host,port))

            # inspired by the RMBT-Protocol

            test_uuid = duration_ms = answer_with = None

            # client has to identify itself
            self.data = self.request.recv(50).strip()
            if str(self.data,"utf-8").startswith("TEST "):
                test_uuid = str(self.data,"utf-8").strip()[5:]

                LOGGER.debug("Starting speed test for test uuid: {}".format(test_uuid))

                # send back "OK"
                self.request.sendall(bytes("OK\n","utf-8"))

                self.data = self.request.recv(1024)

                # maybe an answer id is set
                answer_with = None
                if str(self.data,"utf-8").startswith("ANSWER "):
                    answer_with = int(str(self.data,"utf-8").strip()[6:])
                    # send back "OK"
                    self.request.sendall(bytes("OK\n", "utf-8"))
                    self.data = self.request.recv(1024)

                # download test
                if not str(self.data,"utf-8").startswith("DOWN "):
                    return

                duration_ms = int(str(self.data, "utf-8").strip()[5:])

            elif str(self.data,"utf-8").startswith("GET"):
                get_request = str(self.data,"utf-8")

                # receive until newline is reached
                while not get_request.endswith("\r\n"):
                    get_request += str(self.request.recv(1),"utf-8")

                regex_get = re.compile("GET /(.*?)/(.*?)/(.*?)/.*")
                test_uuid = regex_get.match(get_request).group(1)
                duration_ms = int(regex_get.match(get_request).group(2))
                answer_with = int(regex_get.match(get_request).group(3))


            #send random packets of size X for xx milliseconds
            download_test_result = _uploadBytes(self.request, duration_ms, packet_size, server_answers[answer_with]["header"] if not answer_with is None else None)

            LOGGER.debug("download test finished")

            # only conduct upload test for tcps4, not for mm7
            upload_test_result = {}
            if answer_with is None:
                # upload test
                self.data = self.request.recv(1024)
                if not str(self.data, "utf-8").startswith("UP "):
                    return

                # send back "OK"
                self.request.sendall(bytes("OK\n", "utf-8"))

                # receive all bytes until 0xFF
                upload_test_result = _downloadBytes(self.request, packet_size)

                LOGGER.debug("upload test finished")

                # end
                self.data = self.request.recv(1024)
                if not str(self.data, "utf-8").startswith("END"):
                    return

                # send back "OK"
                self.request.sendall(bytes("OK\n", "utf-8"))

            if not test_uuid in server_test_results:
                server_test_results[test_uuid] = {}

            server_test_results[test_uuid][port] = {
                "download" : download_test_result,
                "upload" : upload_test_result
            }

    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        pass

    def startupServer(self, config, startInThread = True):
        global packet_size, port_offset, server_answers
        packet_size = config["configuration"]["packet_size"]

        if "port_offset" in config["configuration"]:
            port_offset = int(config["configuration"]["port_offset"])

        self.server = {}
        server_answers = config["configuration"]["http_headers"]
        ports = config["configuration"]["ports"]
        # So we dont have to wait for TCP TIME_WAIT
        socketserver.TCPServer.allow_reuse_address = True
        for port in ports:
            int_port = port["port"]
            self.server[int_port] = self.ThreadedTCPServer(("", int_port), self.CMRequestHandler)

            # start in new thread so we can listen for shutdown requests
            t = Thread(target=self.server[int_port].serve_forever)
            if startInThread:
                t.start()
            else:
                t.run()
        self.is_running=True
        LOGGER.info("started server tcps4 on ports: " + str(ports))


    def shutdownServer(self):
        if self.is_running:
            LOGGER.info("stopping test servers for tcps4")
            for server in self.server.values():
                server.shutdown()
                # Close the server to free the port
                server.server_close()
            self.is_running = False

def validateClientResults(test_uuid, results):
    # combine results from upload tests only
    test_results={}
    if not test_uuid in server_test_results:
        print(server_test_results)

    # iterate through all ports
    for port in results:
        int_port = int(port)
        test_results[port] = {}
        test_results[port]["upload"] = server_test_results[test_uuid][int_port]["upload"]
        test_results[port]["download"] = results[port]["download"]

        if "answer_with" in results[port]:
            test_results[port]["answer_with"] = results[port]["answer_with"]
        if "request_with" in results[port]:
            test_results[port]["request_with"] = results[port]["request_with"]
    del server_test_results[test_uuid]
    return test_results



def main():
    # sent from the server when requesting permission to conduct a test

    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "ports": [
            {
                "port": 8091,
                "answer_with": 0,  # http header no 1
                "request_with": 1

            },
            {
                "port": 8080
            }
        ],
        "packet_size": 4096,
        "test_duration_ms": 1000,
        "concurrent": False,
        "test_uuid": test_uuid,
        "http_headers": [
            {
                "id": 0,
                "header": "HTTP/1.1 200 OK\r\n" \
                          "Accept-Ranges: bytes\r\n" \
                          "Access-Control-Allow-Credentials: true\r\n" \
                          "Alt-Svc: quic=\":443\"; ma=2592000\r\n" \
                          "Alternate-Protocol: 443:quic\r\n" \
                          "Cache-Control: private, max-age=21293\r\n" \
                          "Connection: keep-alive\r\n" \
                          "Content-Length: 1718030\r\n" \
                          "Content-Type: video/webm\r\n\r\n"
            },
            {
                "id": 1,
                "header": "GET /videoplayback?mime=video/webm&dur=610.640&upn=q_PY3To1fWI HTTP/1.1\r\n" \
                          "Host: r1---sn-4g5edne7.googlevideo.com\r\n" \
                          "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0\r\n" \
                          "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" \
                          "Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n" \
                          "Accept-Encoding: gzip, deflate, br\r\n\r\n"
            }
        ]
    }
    config = {
        "configuration" : test_config
    }

    server = ServerTCPS4()
    server.startupServer(config, True)
    sleep(1)

    client = ClientTCPS4()
    result = client.conductTest(test_config)
    print(json.dumps(result,indent=4))

    s_result = validateClientResults(test_uuid, result)
    print(json.dumps(s_result, indent=4))

    server.shutdownServer()



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

    main()
