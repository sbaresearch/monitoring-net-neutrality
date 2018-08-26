import json
import logging
import os
import glob

import subprocess
import uuid

import utils

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

_ooniPath = "/usr/bin/ooniprobe"
_testDeck = "../deck/default.deck"
_outputDir = "/reports/"
_useConfig = False

class ClientOONI7:
    def run_ooni(self):
        LOGGER.info("starting ooni test")
        self.__dumpcap_process = subprocess.Popen(
            [_ooniPath,
             "-i", _testDeck,
             "-n"], cwd=_outputDir,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)

        (stdout,stderr) = self.__dumpcap_process.communicate(timeout=180)
        # LOGGER.info("{} ||\n\n||\n {}".format(stdout,stderr))

        LOGGER.info("stopped ooni test")

        # get report files
        files = glob.glob("{}/*".format(_outputDir))

        ret = {}

        for filename in files:
            with open(filename,'r') as file:
                yaml = file.read()
                key = filename[filename.rfind("/")+1:]
                key = key[:-7] # .yamloo
                ret[key] = yaml

        for filename in files:
            os.remove(filename)

        return ret

    def conductTest(self, config):
        global _ooniPath
        if _useConfig:
            _ooniPath = utils.get_config()["ooniprobe"]["path_to_executable"]

        ret = self.run_ooni()
        return {
            "results": ret
        }



def main():
    test_uuid = str(uuid.uuid4())
    test_config = {

    }

    client = ClientOONI7()
    result = client.conductTest(test_config)
    print(json.dumps(result,indent=4))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')
    _outputDir = "." + _outputDir
    main()
else:
    _outputDir= "./metrics/ooni7" + _outputDir
    _useConfig = True
