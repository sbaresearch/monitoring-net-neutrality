import base64
import ctypes
import hashlib
import json
import logging
import os
import random
import socket
import socketserver
import binascii

import time

import datetime
import uuid
from threading import Thread

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

_CLIENT_HELLO_LENGTH = 224
_SERVER_HELLO_LENGTH = 4780
_USE_REAL_LENGTH = False

class ClientTLS4:

    def generate_client_hello(self, host, test_uuid):
        # https://tools.ietf.org/html/rfc5246#section-7.4.1
        # http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session

        a = 0x01
        handshake_hello = b'\x01'

        version = b'\x03\x03' # TLS 1.0


        unix_time =int(datetime.datetime.utcnow().timestamp())
        unix_time_bytes = int.to_bytes(unix_time,4,byteorder='big')

        random_bytes = os.urandom(28)
        random_part = unix_time_bytes + random_bytes


        session_id_length = b'\x00'

        # cipher suites


        length = ctypes.c_uint16(2)


        # cipher suites
        tls_rsa_with_aes_256_cbc_sha = b'\x00\x35'
        # from a wireshark dump with win10
        full_suites = b'\x16\xb9\x16\xba\x16\xb7\x16\xb8\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8' \
                      b'\xcc\x14\xcc\x13\xc0\x09\xc0\x13\xc0\x0a\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a'
        cipher_suites = full_suites
        cipher_suites_length = int.to_bytes(len(cipher_suites),2,byteorder='big')

        # compression
        no_compression = b'\x00'
        compression_length = int.to_bytes(len(no_compression),1,byteorder='big')

        # extensions
        server_name_extension_type = b'\x00\x00'

        server_name_host_name_type = b'\x00'
        server_name_name = bytes("{}.com".format(test_uuid), "utf-8")
        server_name_name_length = len(server_name_name)
        server_name_list = server_name_host_name_type + int.to_bytes(server_name_name_length,2,byteorder='big') + server_name_name
        server_name_list_length = len(server_name_list)
        server_name_list = int.to_bytes(server_name_list_length,2,byteorder='big')+server_name_list
        server_name_extension_length = len(server_name_list)
        server_name_extension = server_name_extension_type + int.to_bytes(server_name_extension_length,2,byteorder='big') + server_name_list

        # from a wireshark dump with win10
        full_extensions = b'\xff\x01\x00\x01\x00' + server_name_extension + b'\x00\x17\x00\x00\x00\x23\x00\x00\x00\x0d\x00\x12\x00\x10\x06\x01\x06\x03\x05\x01\x05' \
                                                                  b'\x03\x04\x01\x04\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00' \
                                                                  b'\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x75\x50\x00\x00\x00' \
                                                                  b'\x0b\x00\x02\x01\x00\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18'

        extensions_length = len(full_extensions)

        extensions = int.to_bytes(extensions_length,2,byteorder='big') + full_extensions

        # full body
        body = version + random_part + session_id_length + cipher_suites_length + \
               cipher_suites + compression_length + no_compression + extensions


        body_length = int.to_bytes(len(body),3,byteorder='big')
        if not _USE_REAL_LENGTH:
            body_length = int.to_bytes(random.randrange(_CLIENT_HELLO_LENGTH - 100, _CLIENT_HELLO_LENGTH + 100),3,byteorder='big')

        handshake_protocol_hello = handshake_hello + body_length + body

        #tlsv1.1 layer
        handshake_prococol_handshake_type = b'\x16'
        handshake_protocol_handshake_version = b'\x03\x01'
        handshake_protocol_hello_length = int.to_bytes(len(body) +
                                                       len(handshake_prococol_handshake_type) +
                                                       len(handshake_protocol_handshake_version) +
                                                       len(handshake_hello), 2, byteorder='big')

        if not _USE_REAL_LENGTH:
            handshake_protocol_hello_length = int.to_bytes(random.randrange(_CLIENT_HELLO_LENGTH - 100, _CLIENT_HELLO_LENGTH + 100),2,byteorder='big')

        handshake_protocol = handshake_prococol_handshake_type + handshake_protocol_handshake_version + \
            handshake_protocol_hello_length + handshake_protocol_hello



        return handshake_protocol


    def conductTest(self, test_params):
        client_hello = self.generate_client_hello(test_params["host"],test_params["test_uuid"])

        # Create normal socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((test_params["host"],test_params["port"]))

        # send client hello
        sock.sendall(client_hello)

        # wait for server hello
        answer = sock.recv(5)

        #length is in bytes 4 and 5
        length = int.from_bytes(answer[3:5], byteorder='big')
        if not _USE_REAL_LENGTH:
            length = _SERVER_HELLO_LENGTH
        received = 0
        while (received < length):
            t_ans = sock.recv(length)
            received += len(t_ans)
            answer += t_ans


        # sha256
        sha = hashlib.sha256(answer).hexdigest()
        return {
            "checksum" : sha
        }


sent_answers = {}
class ServerTLS4:
    def __init__(self):
        self.is_running = False


    class TLS4RequestHandler(socketserver.BaseRequestHandler):
        def generate_server_hello(self):
            handshake_type = b'\x02'
            handshake_version = b'\x03\x02'

            unix_time = int(datetime.datetime.utcnow().timestamp())
            unix_time_bytes = int.to_bytes(unix_time, 4, byteorder='big')

            random_bytes = os.urandom(28)
            random = unix_time_bytes + random_bytes

            session_id = b'\x00'
            cipher = b'\xc0\x13'  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            compression = b'\x00'

            # extensions
            all_extensions = b'\x00\x0b\x00\x02\x01\x00\xff\x01\x00\x01\x00\x00\x17\x00\x00'
            extensions_length = int.to_bytes(len(all_extensions), 2, byteorder='big')

            body = handshake_version + random + session_id + cipher + compression + extensions_length + all_extensions
            server_hello = handshake_type + int.to_bytes(len(body), 3, byteorder='big') + body
            print(binascii.hexlify(server_hello))
            return server_hello

        def generate_certificate(self):
            handshake_type = b'\x0b'

            def load_cert(filename):
                filename = filename.replace("/", "")  # no cross-directory
                # open certs
                file = open("./metrics/tls4/certs/{}".format(filename))
                cert = file.read()
                file.close()
                cert = cert.split("\n")
                cert = list(filter(None, cert))
                cert = cert[1:-1]
                cert = "".join(cert)

                cert = base64.b64decode(cert)
                len_cert = len(cert)
                if not _USE_REAL_LENGTH:
                    len_cert = random.randrange(len_cert - 10, len_cert + 10)

                complete = int.to_bytes(len_cert, 3, byteorder='big') + cert
                return complete

            certs = load_cert("cert1.crt") + load_cert("cert3.crt") + load_cert("cert2.crt")
            len_certs = int.to_bytes(len(certs), 3, byteorder='big')

            complete = handshake_type + int.to_bytes(len(len_certs + certs), 3, byteorder='big') + len_certs + certs

            return complete

        def generate_server_key_exchange(self):
            handshake_type = b'\x0c'

            # ec diffie-hellman server params from wireshark dump of gitlab.sba-research.org
            ec = b'\x03\x00\x17\x41\x04\xa4\x14\xa6\xe0\x7e\x32\x6c\x84\x01\xba\x02\x0d\x12\x64\x34\x29\xce\xb2\x23\xda\xbc\xc1\x16\x24\x3f\x74\x80\x6c\xd2\x15\xeb\x2f\xaf\x77\xe5\x88\x15\xa0\x8a\x0b\x36\x08\x7b\x62\x24\xfe\xdb\x7b\x1f\x33\x94\x47\x44\x70\xbd\x02\x5e\xd9\x91\x24\x8e\x98\x2a\xe4\x02\x00\x42\x75\xd1\x82\x3f\xf0\x95\x4b\x23\x8f\xe9\xed\x8b\x00\x70\x2e\xd0\xed\x7a\x9b\x0d\x89\xd2\x34\xef\x67\xe1\xd5\xec\x93\x5c\xcd\x7c\xdb\xec\x02\x83\x87\x38\x4f\x12\xc6\x83\x42\x10\xd0\x83\xa5\x34\x83\x49\x25\x0c\xa9\x59\x8d\x38\xdd\x74\xa0\xf7\x94\x9a\x25\xd0\x1e\xfe\xd9\x2b\x42\x67\xe6\xb8\xd2\xf9\x2f\xdd\xea\x42\x5e\x5d\x4f\xf5\x7b\x91\x62\xaa\x53\x06\x95\xb9\xa1\x39\x1a\xd0\x59\x15\x69\xa9\x01\xe3\x73\xcf\x94\x1a\x47\x06\x13\x34\x10\xba\x51\xd1\xb9\x59\xb0\xcb\x09\x51\x33\x22\xcd\x64\x84\x4a\x97\x4a\x19\x68\x55\xf0\xc8\x09\xd1\xc3\x7b\x4f\x36\xc3\x7a\xf1\x14\xea\x29\xcf\x33\x1d\x7f\x82\xb4\x0d\xa7\xbe\x2a\x88\xc4\x16\xdf\x17\xb3\x51\xe9\xba\x0e\xf0\xbf\x3e\x7c\x67\x3a\x6b\x81\xdf\x00\x80\xbd\x3a\xd4\x66\xb9\x1e\x93\xa6\x6d\x97\x25\x5a\x59\x33\x8c\x4a\x15\x79\x93\x71\xa7\xdf\x0a\x33\x06\x95\x6e\x3d\x49\x25\x5b\x18\x14\x60\x1b\xad\xcd\x48\x6b\x88\xba\xd8\x95\x27\x9e\xa7\xbc\x95\xd9\xd2\x92\xc4\x5f\xd5\x32\xc4\xbc\xef\x3e\x7a\xa2\x95\x18\xc8\xc3\xd7\xb3\x7a\x0d\x32\xaf\x17\xf7\x37\xa3\x67\x85\x79\xeb\xdb\x33\xa0\xf0\xc0\x64\x35\xf0\xd6\xf6\xa8\x17\x85\x0a\x70\x1e\x45\x36\xd7\xfb\x19\x31\xb8\x15\x00\x5f\xea\xcd\x1e\x72\x0d\x71\x46\x95\x7f\x9e\xf0\x74\x65\x22\x91\x76\xd3\xf4\x88\xbd\x48\x73\xe7\x76\x7d\x4f\xe0\x3f\x12\x69\xe0\x9b\xe2\x3e\x76\xbe\x49\x15\x19\x5b\xee\x49\xed\xe8\x3a\x7a\x9b\xe4\x18\xfb\x22\xf0\xa9\x1d\x56\xaf\x39\x9f\x2e\x6d\x0c\x61\xbe\x50\x5a\xb0\x3f\x8d\xc9\x52\xe6\x51\x43\x1f\x0e\x59\x62\xc5\x78\x74\x5c\x95\xa6\xe8\x1d\x0f\x35\x95\x7a\xbf\x0d\x52\x25\x7c\x6d\x18\x34\xd8\x2c\x53\xea\x16\x0c\xde\x52\x66\xe2\x89\x36\x81\x6e\xe4\xc7\x41\x57\x6e\xbe\x57\x09\xf4\xb9\x61\x4f\x84\x92\x16\xcf\x0b\x1f\x02\x64\x7e\x1c\xd1\x17\xfe\xac\x6c\x84\x12\xe9\xcf\x98\x7c\xeb\x20\xaa\xaa\xd7\xe8\xe0\xb9\x36\x9b\x79\xd6\x1f\xa4\xff\xa4\x28\xf1\x27\x4a\xc0\x8d\x6e\x93\x81\xed\x94\xe2\x98\xea\x2e\xb4\x32\xd7\xb4\xf4\x10\xf6\xac\x5f\x0c\x1b\x3d\xb9\xf3\xa2\x26\x55\x00\x88\x90\xdd\x52\x88\x06\x32\xa4\x49\x9e\x74\xd7\x2f\x6f\xed\x31\x74\xf5\x23\x8f\x0d\xa2\x61\xe3\x13\x7b\xf2\xd7\x1b\x01\x3f\x86\x18\xff\xbc\x57\x8c\xa9\xab';

            len_key_exchange = int.to_bytes(len(ec), 3, byteorder='big');

            complete = handshake_type + len_key_exchange + ec

            print(binascii.hexlify(complete))

            return complete

        def generate_server_done(self):
            handshake_type = b'\x0e'
            len_done = int.to_bytes(0, 3, byteorder='big')
            return handshake_type + len_done

        def handle(self):
            # receive the "client hello"

            # wait for server hello
            client_hello = self.request.recv(5)

            # length is in bytes 4 and 5
            length = int.from_bytes(client_hello[3:5], byteorder='big')
            if not _USE_REAL_LENGTH:
                length = _CLIENT_HELLO_LENGTH

            received = 0
            while (received < length):
                t_ans = self.request.recv(length)
                received += len(t_ans)
                client_hello += t_ans

            # extract uuid
            # position 106 to 142
            test_uuid = client_hello[106:142]
            test_uuid = str(test_uuid, "utf-8")


            # resond to a "client hello"
            handshake_type = b'\x16'
            version = b'\x03\x02'
            answer = self.generate_server_hello() + self.generate_certificate() + self.generate_server_key_exchange() + self.generate_server_done()
            handshake_length = int.to_bytes(len(answer),2,byteorder='big')
            if not _USE_REAL_LENGTH:
                handshake_length = int.to_bytes(random.randrange(_SERVER_HELLO_LENGTH-100, _SERVER_HELLO_LENGTH+1000),2,byteorder='big')

            answer = handshake_type + version + handshake_length + answer

            # save the sha value for later
            sha = hashlib.sha256(answer).hexdigest()
            sent_answers[test_uuid] = sha

            self.request.sendall(answer)



    def startupServer(self, config, startInThread=True):
        self.server = {}
        port = config["configuration"]["port"]
        # So we dont have to wait for TCP TIME_WAIT
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer(("", port), self.TLS4RequestHandler)

        # start in new thread so we can listen for shutdown requests
        t = Thread(target=self.server.serve_forever)
        if startInThread:
            t.start()
        else:
            t.run()
        self.is_running = True
        LOGGER.info("started tls4 server on port: " + str(port))

    def shutdownServer(self):
        if self.is_running:
            LOGGER.info("stopping test servers for stls7")
            self.server.shutdown()
            # Close the server to free the port
            self.server.server_close()


def validateClientResults(test_uuid, results):
    result = {}
    result["client"] = results["checksum"]
    result["server"] = sent_answers[test_uuid]
    if result["client"] == result["server"]:
        return {
            "matches" : result
        }
    else:
        return {
            "mismatches" : result
        }





def main():
    # sent from the server when requesting permission to conduct a test

    test_uuid = str(uuid.uuid4())
    test_config = {
        "test_uuid" : test_uuid,
        "host": "localhost",
        "port": 8447
    }
    config = {
        "configuration" : test_config
    }

    server = ServerTLS4()
    server.startupServer(config, True)
    time.sleep(1)

    client = ClientTLS4()
    result = client.conductTest(test_config)
    print(json.dumps(result,indent=4))
    s_result = validateClientResults(test_uuid,result)
    print(json.dumps(s_result, indent=4))

    server.shutdownServer()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

    main()
