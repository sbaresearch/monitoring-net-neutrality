import json
import logging
import re
import socket
import socketserver
import statistics
import uuid
import time
from threading import Thread
from time import sleep

import scapy.all

import utils

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


class ClientUDP4:
    def conductSinglePortTest(self, host, port, num_packets):
        ping_results = {}

        # Connect to server and send data
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_to_socket = True

        regex_pong = re.compile("PONG ([0-9]+)\n")
        regex_time = re.compile("TIME ([0-9]+) ([0-9]+)\n")

        # listen in thread for UDP responses
        def receive_data():
            received_packets = 0
            received_ok_packets = 0
            while listen_to_socket:
                try:
                    data = str(sock.recv(1024), "utf-8")

                    # measurement starts as soon as PONG x is received
                    if data.startswith("PONG"):
                        i = int(regex_pong.match(data).group(1))
                        ping_results[i]["received_as"] = received_packets

                        # send back OK
                        ping_results[i]["begin"] = time.time()
                        sock.sendto(bytes("OK {}\n".format(i), "utf-8"), (host, port))
                        received_packets += 1

                    # if TIME is received - store server time and measure client time
                    elif data.startswith("TIME"):
                        received_ok_packets += 1
                        match = regex_time.match(data)
                        i = int(match.group(1))
                        server_duration_ns = int(match.group(2))
                        ping_results[i]["server"] = server_duration_ns / 1e6  # nanosec to millisecs
                        ping_results[i]["client"] = (time.time() - ping_results[i]["begin"]) * 1e3

                    if received_ok_packets == num_packets:
                        LOGGER.debug("all packets received")
                        break
                except socket.error:
                    pass

        # start receiving
        receiveThread = Thread(target=receive_data)
        receiveThread.start()

        for i in range(num_packets):
            ping_results[i] = {}
            sock.sendto(bytes("PING {}\n".format(i), "utf-8"), (host, port))

        sleep(2)  # wait for all (most) of the packets to arrive, @TODO: dynamically stop earlier if all received

        listen_to_socket = False
        sock.close()

        def statistic_or_null(method, list, field):
            if len(list) == 0:
                return None
            elif len([list[x][field] for x in list if field in list[x]]) == 0:
                return None
            else:
                return method([list[x][field] for x in list if field in list[x]])

        if len(ping_results) == 0:
            return {
                "pings" : {}
            }
        else:
            return {
                "pings": ping_results,
                # when doing statistics only consider measurements that exist (since UDP is unreliable)
                "ping_client_mean": statistic_or_null(statistics.mean,ping_results,"client"),
                "ping_client_median": statistic_or_null(statistics.median,ping_results,"client"),
                "ping_server_mean": statistic_or_null(statistics.mean,ping_results,"server"),
                "ping_server_median": statistic_or_null(statistics.median,ping_results,"server"),
            }

        # print("Sent:     {}".format(data))
        # print("Received: {}".format(received))

    def conductTest(self, test_params):
        results = {}

        # start recording
        capture_process = utils.start_network_capture(temporary=True)

        for port in test_params["ports"]:
            LOGGER.info("conducting udp4 test on port {}".format(port))
            results[port] = self.conductSinglePortTest(test_params["host"], port, test_params["packets"])

        # stop recording
        capture_process.stop_capture()
        filename = capture_process.get_capture_filename()
        all_packets = scapy.all.rdpcap(filename)

        for port in test_params["ports"]:
            LOGGER.debug("getting statistics for port {}".format(port))
            port_packets_source = all_packets.filter(
                lambda p: hasattr(p,"len") and p.len > 40 and p.sport and p.sport == port)

            # get TTL of all packets
            ttl_source = list(map(lambda p: p.ttl, port_packets_source))
            if len(ttl_source)>0:
                results[port]["ttl_source"] = ttl_source

                results[port]["ttl_source_mean"] = statistics.mean(ttl_source)
                results[port]["ttl_source_median"] = statistics.median(ttl_source)
                results[port]["ttl_source_min"] = min(ttl_source)
                results[port]["ttl_source_max"] = max(ttl_source)

        return results


class ServerUDP4:
    is_running = False

    class RequestHandler(socketserver.BaseRequestHandler):
        timestamps = {}  # client timestamps

        def handle(self):
            data = str(self.request[0], "utf-8").strip()
            ip = self.client_address[0]
            socket = self.request[1]

            if ip not in self.timestamps:
                LOGGER.info("starting udp4 test with client ip {}".format(ip))
                self.timestamps[ip] = {}

            # answer PING with PONG, start time measurement
            if data.startswith("PING"):
                i = data[5:]
                self.timestamps[ip][i] = {}
                self.timestamps[ip][i]["begin"] = time.time()
                socket.sendto(bytes("PONG {}\n".format(i), "utf-8"), self.client_address)

            # answer OK with TIME, stop time measurement
            elif data.startswith("OK"):
                i = data[3:]
                timestamp_ok = time.time()
                timediff_ns = int((time.time() - self.timestamps[ip][i]["begin"]) * 1e9)
                socket.sendto(bytes("TIME {} {}\n".format(i, timediff_ns), "utf-8"), self.client_address)

    class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
        pass

    def startupServer(self, config, startInThread=True):
        self.server = {}
        self.is_running = True
        ports = config["configuration"]["ports"]
        # So we dont have to wait for TCP TIME_WAIT
        socketserver.UDPServer.allow_reuse_address = True
        for port in ports:
            self.server[port] = self.ThreadedUDPServer(("", port), self.RequestHandler)

            # start in new thread so we can listen for shutdown requests
            t = Thread(target=self.server[port].serve_forever)
            if startInThread:
                t.start()
            else:
                t.run()
        LOGGER.info("started server udp4 on ports: " + str(ports))

    def shutdownServer(self):
        if self.is_running:
            LOGGER.info("stopping test servers for udp4")
            for server in self.server.values():
                server.shutdown()
                # Close the server to free the port
                server.server_close()
            LOGGER.info("stopped test servers for udp4")
            self.is_running = False


def main():
    # sent from the server when requesting permission to conduct a test

    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "ports": [8087, 8088, 8089],
        "packets": 5
    }
    config = {
        "configuration": test_config
    }

    server = ServerUDP4()
    server.startupServer(config, True)
    sleep(2)

    client = ClientUDP4()
    result = client.conductTest(test_config)
    print(json.dumps(result, indent=4))

    server.shutdownServer()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

    main()
