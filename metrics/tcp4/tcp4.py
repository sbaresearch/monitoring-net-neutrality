import json
import logging
import socket
import socketserver
import statistics
import time
import uuid
from threading import Thread
from time import sleep
import utils
import scapy.all


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

class ClientTCP4:
    def conductSinglePortTest(self, host, port, pings):
        LOGGER.debug("starting ping test on port {}".format(port))

        # Connect to server and send data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))


        #do ping test
        ping_results=[]
        for i in range(pings):
            begin = time.time()
            sock.sendall(bytes("PING\n","utf-8"))
            data = str(sock.recv(1024),"utf-8").strip()
            if data != "PONG":
                raise Exception("invalid response: " + str(data))
            clientDuration = (time.time()-begin)*1e3

            sock.sendall(bytes("OK\n","utf-8"))
            data = str(sock.recv(1024),"utf-8").strip()
            if not data.startswith("TIME "):
                raise Exception("invalid response: {}".format(str(data)))
            serverDuration = int(data[5:])/1e6 #nanosec to millisecs

            ping_results.append({
                "client" : clientDuration,
                "server" : serverDuration,
                "begin" : int(begin)
            })

        #@TODO large fiels

        sock.close()

        return {
            "pings" : ping_results,
            "ping_client_mean" : statistics.mean([x["client"] for x in ping_results]),
            "ping_client_median" : statistics.median([x["client"] for x in ping_results]),
            "ping_server_mean" : statistics.mean([x["server"] for x  in ping_results]),
            "ping_server_median" : statistics.median([x["server"] for x in ping_results])
        }

    def conductTest(self, test_params):
        results={}
        # start recording
        capture_process = utils.start_network_capture(temporary=True)

        for port in test_params["ports"]:
            results[port] = self.conductSinglePortTest(test_params["host"],port, test_params["pings"])

        def statistic_or_null(method, list):
            if len(list) == 0:
                return None
            else:
                return method(list)

        # stop recording
        capture_process.stop_capture()
        filename = capture_process.get_capture_filename()
        all_packets = scapy.all.rdpcap(filename)
        for port in test_params["ports"]:
            LOGGER.debug("getting statistics for port {}".format(port))
            port_packets_source = all_packets.filter(
                lambda p: hasattr(p, 'len') and hasattr(p, 'sport') and p.len > 40 and p.sport == port)
            port_packets_dst = all_packets.filter(
                lambda p: hasattr(p, 'len') and hasattr(p, 'dport') and p.len > 40 and p.dport == port)
            #get TTL of all packets
            ttl_source = list(map(lambda p : p.ttl, port_packets_source))
            ttl_dst = list(map(lambda p : p.ttl, port_packets_dst))
            results[port]["ttl_source"] = ttl_source
            #results[port]["ttl_dst"] = ttl_dst

            results[port]["ttl_source_mean"] = statistic_or_null(statistics.mean, ttl_source)
            results[port]["ttl_source_median"] = statistic_or_null(statistics.median, ttl_source)
            results[port]["ttl_source_min"] = statistic_or_null(min, ttl_source)
            results[port]["ttl_source_max"] = statistic_or_null(max, ttl_source)
            #results[port]["ttl_dst_mean"] = statistics.mean(ttl_dst)
            #results[port]["ttl_dst_median"] = statistics.median(ttl_dst)
            #results[port]["ttl_dst_min"] = min(ttl_dst)
            #results[port]["ttl_dst_max"] = max(ttl_dst)
            results[port]["sent"] = len(port_packets_dst)
            results[port]["received"] = len(port_packets_source)

        return results


class ServerTCP4:
    is_running = False

    class CMRequestHandler(socketserver.BaseRequestHandler):

        def handle(self):
            while(True):
                self.data = self.request.recv(1024).strip()
                if (len(self.data) == 0):
                    return

                LOGGER.debug("message from {}".format(self.client_address[0]))
                #respond to PINGs with PONG and start to measure time
                if str(self.data,"utf-8") == "PING":
                    self.timestamp_ping = time.time()
                    #LOGGER.debug("got PING, sending PONG")
                    self.request.sendall(bytes("PONG\n","utf-8"))

                #respond to OKs with the measured time
                if str(self.data,"utf-8") == "OK":
                    timestamp_ok = time.time()
                    timediff_ns = int((timestamp_ok-self.timestamp_ping)*1e9)
                    #LOGGER.debug("got OK, sending back TIME {}".format(timediff_ns))
                    self.request.sendall(bytes("TIME {}\n".format(timediff_ns),"utf-8"))

    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        pass

    def startupServer(self, config, startInThread = True):
        self.server = {}
        self.is_running = True
        ports = config["configuration"]["ports"]
        # So we dont have to wait for TCP TIME_WAIT
        socketserver.TCPServer.allow_reuse_address = True
        for port in ports:
            self.server[port] = self.ThreadedTCPServer(("", port), self.CMRequestHandler)

            # start in new thread so we can listen for shutdown requests
            t = Thread(target=self.server[port].serve_forever)
            if startInThread:
                t.start()
            else:
                t.run()
        LOGGER.info("started server on ports: " + str(ports))


    def shutdownServer(self):
        if self.is_running:
            LOGGER.info("stopping test servers for tcp4")
            for server in self.server.values():
                server.shutdown()
                # Close the server to free the port
                server.server_close()
            self.is_running = False

def validateClientResults(testuuid, results):
    #nothing to validate at server side?
    return results



def main():
    # sent from the server when requesting permission to conduct a test

    test_uuid = str(uuid.uuid4())
    test_config = {
        "host": "localhost",
        "ports": [8081,8082,8083,8084],
        "pings": 5
    }
    config = {
        "configuration" : test_config
    }

    server = ServerTCP4()
    server.startupServer(config, True)
    sleep(3)

    client = ClientTCP4()
    result = client.conductTest(test_config)
    print(json.dumps(result,indent=4))

    server.shutdownServer()



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

    main()
