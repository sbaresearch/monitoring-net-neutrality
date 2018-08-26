import logging
import uuid
import dns.resolver
import time

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

class ClientDNS7:

    def sendSingleDNSRequest(self, request):
        """
        Send out a single DNS lookup request
        :param request: the hostname, e.g. google.com
        :return: dictionary containing the resolved IPs, TTL and duration of the request
        """
        result = dict(request)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        if "nameservers" in request and len(request["nameservers"])>0:
            resolver.nameservers = request["nameservers"]

        start_time = time.time()
        try:
            answer = resolver.query(request["host"])
            result["rcode"] = answer.response.rcode()
            result["ttl"] = answer.response.answer[0].ttl
            result["entries"] = [i.address for i in answer.response.answer[0].items]
        except dns.resolver.NXDOMAIN:
            result["rcode"] = dns.rcode.NXDOMAIN
        except dns.exception.Timeout:
            result["rcode"] = -1


        #response.answer[0].time also holds an (exact) time, but is not documented, so it is not used here
        duration_ms = (time.time()-start_time)*1e3

        result["duration_ms"] = round(duration_ms,6)

        return result


    def conductTest(self, config):
        test_result = {"requests": []}

        for request in config["requests"]:
            result = self.sendSingleDNSRequest(request)
            LOGGER.debug("DNS results for {}: {}".format(request["host"], str(result)))
            test_result["requests"].append(result)


        return test_result



def main():
    test_uuid = str(uuid.uuid4())
    test_config = {
        "requests": [
            {
                "host": "www.orf.at"
            },
            {
                "host": "www.thepiratebay.plus"
            },
            {
                "host": "www.kinox.to"
            },
            {
                "host": "www.kinox.to",
                "nameservers": ["8.8.8.8"]
            },
            {
                "host": "www.123hjaf9hu32iufhuihoafine.com"
            }
        ]
    }

    client = ClientDNS7()
    client.conductTest(test_config)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')
    main()
