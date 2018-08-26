import json
import logging
import socketserver
import socket
import uuid
import subprocess
import os
import re
from threading import Thread
from time import sleep
import time

import scapy.all


import utils

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


# https://wiki.wireshark.org/RTP_statistics

def play_voip_stream(udpsocket, address, packets):
    # replay packets (one every 1/8000*160 = 20 ms)
    interval_ms = 20
    previous_time = int(time.time() * 1e3)
    current_packet_counter = 0

    while True:
        current_time = int(time.time() * 1e3)
        missing_ms = interval_ms - (current_time - previous_time)
        if missing_ms <= 0:
            # send packet
            payload = packets[current_packet_counter]["UDP"]["Raw"]
            udpsocket.sendto(bytes(payload), address)

            previous_time += interval_ms
            current_packet_counter += 1
            if current_packet_counter == len(packets):
                break
            # LOGGER.debug("sent p {}".format(str(current_packet_counter)))

        else:
            sleep(missing_ms / 1e3)  # in seconds

class ClientVOIP7:
    def conductSingleVOIPCall(self, host, port, pcap_filename, duration_ms):
        # open file
        all_packets = scapy.all.rdpcap(pcap_filename)

        # filter packets coming from server
        client_packets = all_packets.filter(lambda p: "UDP" in p and p["IP"].src == "192.168.0.10")

        LOGGER.info("conducting rtp call test on port {}".format(port))

        # Connect to server and send data
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # sock.sendto(bytes("OK\n", "utf-8"), (host, port))

        # no need to receive packets at this stage

        start_time = time.time()

        # simulate client stream
        play_voip_stream(sock, (host,port),client_packets)

        # wait for the server stream to end
        test_duration = time.time()-start_time
        sleep(max(0,duration_ms/1e3-test_duration))

    def conductTest(self, test_params):
        # start recording
        capture_process = utils.start_network_capture(temporary=True)

        for port in test_params["ports"]:
            self.conductSingleVOIPCall(test_params["host"], port, test_params["replay_pcap"], test_params["call_duration_ms"])

        # stop recording
        capture_process.stop_capture()
        filename = capture_process.get_capture_filename()
        #filename = "rtpstream.pcap"

        # get statistics from tshark
        self.__tshark_process = subprocess.Popen(
            "{} -r {} -d udp.port==2222,rtp -q -z rtp,streams".format(utils.get_config()["tshark"]["path_to_executable"],filename),
            shell=True,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)

        stdout, stderr = self.__tshark_process.communicate()  # wait

        LOGGER.debug("{} {}".format(stdout,stderr))

        result = []
        regex_stream = re.compile(
            "([^ ]+) +([0-9]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+).*")
        lines = stdout.splitlines()
        for line in lines:
            match = regex_stream.match(line.strip())
            if match:
                res = {
                    "src_ip": match.group(1),
                    "src_port": int(match.group(2)),
                    "dst_ip": match.group(3),
                    "dst_port": int(match.group(4)),
                    "ssrc": match.group(5) + " " + match.group(6) + " " + match.group(7),
                    "payload": match.group(8),
                    "packets": int(match.group(9)),
                    "loss_packets": int(match.group(10)),
                    "loss_percent": float(match.group(11)[1:-2]),
                    "delta_ms_max": float(match.group(12)),
                    "jitter_ms_max": float(match.group(13)),
                    "jitter_ms_mean": float(match.group(14))
                }
                result.append(res)



        return {
            "statistics" : result
        }



server_packets = None
class ServerVOIP7:
    class RequestHandler(socketserver.BaseRequestHandler):
        current_calling_ips = {}

        def handle(self):
            ip = self.client_address[0]
            socket = self.request[1]

            if ip not in self.current_calling_ips:
                LOGGER.info("starting voip test with client ip {}".format(ip))
                self.current_calling_ips[ip] = {}

                LOGGER.debug("begin voip answer for: {}".format(ip))
                self.answer_call(socket, ip, self.client_address[1])


        def answer_call(self, udpsocket, ip_address, dst_port):
            address = (ip_address, dst_port)
            play_voip_stream(udpsocket, address, server_packets)

    class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
        pass

    def startupServer(self, config, startInThread=True):
        global server_packets

        self.server = {}
        ports = config["configuration"]["ports"]
        pcap_filename = config["configuration"]["replay_pcap"]

        # fetch pcap file, load into scapy since this is really slow
        all_packets = scapy.all.rdpcap(pcap_filename)

        # filter packets coming from server
        server_packets = all_packets.filter(lambda p: "UDP" in p and p["IP"].dst == "192.168.0.10")

        # So we dont have to wait for TCP TIME_WAIT
        socketserver.TCPServer.allow_reuse_address = True
        for port in ports:
            self.server[port] = self.ThreadedUDPServer(("", port), self.RequestHandler)

            # start in new thread so we can listen for shutdown requests
            t = Thread(target=self.server[port].serve_forever)
            if startInThread:
                t.start()
            else:
                t.run()
        self.is_running = True
        LOGGER.info("started voip server on ports: " + str(ports))

    def shutdownServer(self):
        if self.is_running:
            LOGGER.info("stopping test servers for voip7")
            for server in self.server.values():
                server.shutdown()
                # Close the server to free the port
                server.server_close()
            LOGGER.info("stopped test servers for voip7")
            self.is_running = False



def main():
    # sent from the server when requesting permission to conduct a test

    utils.set_config("../../client-config.json")

    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "ports": [2222],
        "test_uuid": test_uuid,
        "replay_pcap": "./rtpstream.pcap",
        "call_duration_ms": 1400
    }
    config = {
        "configuration" : test_config
    }

    server = ServerVOIP7()
    server.startupServer(config, True)
    sleep(1)

    client = ClientVOIP7()
    result = client.conductTest(test_config)
    print(json.dumps(result,indent=4))
    #s_result = validateClientResults(test_uuid,result)
    #print(json.dumps(s_result, indent=4))

    server.shutdownServer()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

    main()
