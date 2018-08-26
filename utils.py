import json
import logging
import os
import signal
import subprocess
import tempfile

import sys
import uuid
from time import sleep

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


def set_config(config_filename):
    """
    Sets the config for the process execution, returns the loaded config object
    :param config_filename: json file to load
    :return:
    """
    global _config_file
    # Load json config
    with open(config_filename, 'r') as f:
        _config_file = json.load(f)
    return _config_file


def get_config():
    """
    Gets the currently loaded configuration
    :return: config object
    """
    global _config_file
    return _config_file


class NetworkCapturer:
    def __init__(self, filename=None, temporary=False):
        self.__filename = filename
        self.__temporary = temporary

        self.__path_to_executable = get_config()["dumpcap"]["path_to_executable"]
        self.__save_location = get_config()["dumpcap"]["save_location"]
        if temporary:
            self.__filename = "tmp{}".format(uuid.uuid4())
            self.__save_location = tempfile.gettempdir()

        self.__interface = get_config()["dumpcap"]["interface"]

    def start_capture(self):
        # start network capturing
        # noinspection PyAttributeOutsideInit
        self.__dumpcap_process = subprocess.Popen(
                [self.__path_to_executable,
                 "-i", self.__interface,
                 "-w", os.path.join(self.__save_location, "{}.pcap".format(self.__filename))],
                stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)

        # wait for dumpcap to start recording (as soon as "File:" appears on the stderr)
        while True:
            line = self.__dumpcap_process.stderr.readline()
            LOGGER.debug(line)
            if line.startswith("File:"):
                break
            elif line.strip() == "":
                raise Exception("error during capturing")
        LOGGER.debug("started network capture on {} in file {}".format(self.__interface,
                                                                       os.path.join(self.__save_location,
                                                                                    "{}.pcap".format(self.__filename))))

    def stop_capture(self):
        """
        Stops the network capture and finishes writing the file
        :return:
        """
        # stop network capturing
        sleep(1)
        if sys.platform.lower().startswith("win"):
            # noinspection PyUnresolvedReferences
            os.kill(self.__dumpcap_process.pid, signal.CTRL_C_EVENT)  # send CTRL+C for windows
            sleep(1)  # @TODO find some better alternative for windows
            self.__dumpcap_process.communicate(timeout=5)  # wait
        else:
            os.kill(self.__dumpcap_process.pid, signal.SIGINT)  # send SIGINT for *nix
            stdout, stderr = self.__dumpcap_process.communicate()  # wait
            LOGGER.debug("{}".format(stderr.split("\n")[-2])) # print packet statistics

        LOGGER.debug(
                "stopped network capture on {} in file {}".format(self.__interface, os.path.join(self.__save_location,
                                                                                                 "{}.pcap".format(
                                                                                                     self.__filename))))

    def get_capture_filename(self):
        """
        Get the capture filename
        :return:
        """
        # open and get capture
        return os.path.join(self.__save_location, "{}.pcap".format(self.__filename))


def start_network_capture(filename=None, temporary=False):
    """
    Starts a network capture using dumpcap
    :param filename: name of the pcap file (location is loaded from the config)
    :param temporary: if True, no file will be created
    :return:
    """
    if not (filename or temporary):
        raise Exception("Invalid argument: either filename or temporary must be set")

    capturer = NetworkCapturer(filename, temporary)
    capturer.start_capture()
    return capturer
