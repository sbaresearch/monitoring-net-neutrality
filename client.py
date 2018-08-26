import os
from time import sleep

import requests
from datetime import datetime
import utils
import logging
from threading import Timer
from argparse import ArgumentParser
from metrics import metric_loader

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


class Client:
    def __init__(self, config_filename, pcap):
        self.config = utils.set_config(config_filename)
        self.pcap = pcap
        self.initial_run = True
        LOGGER.debug("Created client with config=(%s),pcap=(%s)" % (config_filename, pcap))

    def poll_for_tests(self):
        # schedule the next polling
        Timer(self.config["client"]["poll_interval_seconds"], self.poll_for_tests).start()

        if self.config["testserver"]["enable_client_ip_handling"]:
            self.transmit_client_ip()
            LOGGER.info("transmitted client IP to clamps, waiting for firewall to adjust")
            sleep(3)

        if self.initial_run:
            self.initial_run = False
            response = requests.post("{}://{}:{}/clear_scheduled_tests/{}".format(self.config["testserver"]["protocol"],
                                                           self.config["testserver"]["host"],
                                                           self.config["testserver"]["port"],
                                                           self.config["client"]["uuid"]))


        response = requests.get("{}://{}:{}/request_tests/{}".format(self.config["testserver"]["protocol"],
                                                                     self.config["testserver"]["host"],
                                                                     self.config["testserver"]["port"],
                                                                     self.config["client"]["uuid"]))
        data = response.json()
        LOGGER.info("Got Server response, conducting {} tests".format(len(data["tests"])))

        # schedule all the tests
        for test in data["tests"]:
            diff = test["begin"] - int(datetime.utcnow().timestamp())
            if diff > 0:
                LOGGER.info("Scheduling test {} ({}) for {} ({} secs)".format(test["test_uuid"], test["test"],
                            datetime.fromtimestamp(test["begin"]), diff))
                t = Timer(diff, self.conduct_test, [test])
                t.start()
            else:
                self.conduct_test(test)

    def transmit_client_ip(self):
        """
        Transmit the IP of the client to the test server via ssh into a pre-defined file that is watched by the server
        :return:
        """
        os.system("ssh {} 'echo $SSH_CLIENT | cut -d \" \" -f 1 >> {}{}'".format(self.config["testserver"]["host"],
                                                                               self.config["testserver"]["client_ip_directory"],
                                                                               self.config["client"]["uuid"]))

    def conduct_test(self, test_params):
        try:
            LOGGER.info("Conducting test {} of type {}".format(test_params["test_uuid"], test_params["test"]))

            # start network capturing
            if self.pcap:
                LOGGER.debug("Start network capture")
                capture_process = utils.start_network_capture("{}_{}_{}".format(test_params["test"],test_params["begin"],test_params["test_uuid"]))

            # Load Client from metric_loader
            testclient = metric_loader.get_client(test_params["test"])
            results = testclient.conductTest(test_params["configuration"])

            # submit results
            response = requests.post("{}://{}:{}{}".format(self.config["testserver"]["protocol"],
                                                            self.config["testserver"]["host"],
                                                            self.config["testserver"]["port"],
                                                            test_params["result_url"]), json=results)

            LOGGER.debug(response)

        finally:
            # stop network capturing
            if self.pcap:
                LOGGER.debug("Stop network capture")
                # noinspection PyUnboundLocalVariable
                capture_process.stop_capture()



def main():
    """
    Load arguments (config file) and start Client
    :return:
    """
    logging.basicConfig(level=logging.DEBUG,
                        # filename="client.log",
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

    parser = ArgumentParser()
    parser.add_argument("-c", "--config", dest="config", metavar="CONFIG_JSON_FILE",
                        help="The client's config file", default="client-config.json")
    parser.add_argument("--no_pcap", dest="pcap", action="store_false")

    args = parser.parse_args()

    client = Client(args.config, args.pcap)
    client.poll_for_tests()

if __name__ == '__main__':
    main()
