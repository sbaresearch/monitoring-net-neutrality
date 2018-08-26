import logging
import uuid

from scapy.all import *

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


class ClientTrac3:
    test_result = {"requests": []}

    def conductSingleTraceroute(self, request):
        ret = []

        target = request["host"]

        # https://stackoverflow.com/questions/1151771/how-can-i-perform-a-ping-or-traceroute-using-native-python
        try:
            result, unans = traceroute(target, maxttl=32)

            for i in range(len(result.res)):
                ip = result.res[i][1].src

                if i > 0 and ret[-1]["ip"] == ip:
                    continue

                ret.append({
                    "hop": i,
                    "ip": ip
                })

        except socket.gaierror:
            ret = []


        return ret

    def conductTest(self, config):
        test_result = {"requests": []}

        for request in config["requests"]:
            result = self.conductSingleTraceroute(request)
            LOGGER.debug("DNS results for {}: {}".format(request["host"], str(result)))
            test_result["requests"].append({
                "host": request["host"],
                "result": result
            })

        return test_result



def main():
    test_uuid = str(uuid.uuid4())
    test_config = {
        "requests": [
            {
                "host": "www.orf.at"
            },
            {
                "host": "www.123hjaf9hu32iufhuihoafine.com"
            }
        ]
    }

    client = ClientTrac3()
    client.conductTest(test_config)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')
    main()
