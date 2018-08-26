import ipaddress
import logging
import os
import uuid
import time

import pymongo

import utils
import json
from bson import json_util
from pymongo import MongoClient
from argparse import ArgumentParser
from threading import Timer
from datetime import datetime
from croniter import croniter
from bottle import route, run, request, post, jinja2_view, static_file, Jinja2Template
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from metrics import metric_loader

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

# adjust jinja2 filters to include a filter to print dicts as <pre>json</pre>
Jinja2Template.settings.update({
    "filters" : {
        "dump_json_if_dict" : lambda d : "<pre>{}</pre>".format(json.dumps(d,indent=4)) if isinstance(d,dict) else d
    }
})

@route('/static/<filename:path>')
def server_static(filename):
    """
    Serve a static file
    This is necessary for serving Bootstrap JS/CSS
    :param filename:
    :return:
    """
    return static_file(filename, root='html/static')


@route('/status')
@jinja2_view('status.html', template_lookup=['html/templates'])
def status():
    """
    Return a complete status of the system
    :return:
    """

    clients = ['client1', 'client2', 'client3']

    last_test = {}
    mtime = {}
    ip = {}
    for c in clients:
        last_test[c] = TEST_COLLECTION.find_one( {'client_uuid': c, 'result': {'$exists': True}}, sort=[("begin", pymongo.DESCENDING)] )
        mtime[c] = os.path.getmtime('/home/measurement/client_ips/'+c)
        ip[c] = open('/home/measurement/client_ips/'+c).readlines()[-1]

    metrics = {}
    for m in metric_loader.get_metrics():
        metrics[m] = {}
        for c in clients:
            pos = TEST_COLLECTION.find({'test':m,'client_uuid':c, 'result': {'$exists': True}}).count()
            neg = TEST_COLLECTION.find({'test':m,'client_uuid':c, 'result': {'$exists': False}}).count()
            metrics[m][c] = str(pos) + " pos / " + str(neg) + " neg"

    return {"last_test": last_test, "mtime": mtime, "ip":ip, "metrics":metrics, "clients": clients,  "datetime":datetime}


@route('/status/tests')
@jinja2_view('tests.html', template_lookup=['html/templates'])
def status_tests():
    """
    Return all tests
    :return:
    """
    # TODO To change in the future / paging or only running tests
    return {"tests": TEST_COLLECTION.find().sort("begin",pymongo.DESCENDING).limit(3000), "datetime":datetime}



@route('/status/tests')
@jinja2_view('tests.html', template_lookup=['html/templates'])
def status_tests():
    """
    Return all tests
    :return:
    """
    # TODO To change in the future / paging or only running tests
    return {"tests": TEST_COLLECTION.find().sort("begin",pymongo.DESCENDING).limit(3000), "datetime":datetime}

@route('/status/tests/<page:int>')
@jinja2_view('tests.html', template_lookup=['html/templates'])
def status_tests_offset(page):
    """
    Return tests with an offset
    :return:
    """
    # TODO To change in the future / paging or only running tests
    return {"tests": TEST_COLLECTION.find().sort("begin",pymongo.DESCENDING).limit(3000).skip((page-1)*3000), "datetime":datetime}


@route('/status/test/<test_uuid>')
@jinja2_view('test.html', template_lookup=['html/templates'])
def status_test(test_uuid):
    """
    Render a single test
    :param test_uuid:
    :return:
    """
    return {"test": TEST_COLLECTION.find_one({"test_uuid": test_uuid}), "datetime":datetime}


@post('/clear_scheduled_tests/<client_uuid>')
def clear_scheduled_tests_for_client(client_uuid):
    LOGGER.debug("Clearing tests for client: {}".format(client_uuid))
    TEST_COLLECTION.remove({
        "begin": {
            "$gt": int(datetime.utcnow().timestamp())
        },
        "client_uuid": client_uuid,
        "result": None
    })

@route('/request_tests/<client_uuid>')
def request_tests(client_uuid):
    """
    Send the client with the given uuid which tests it should perform next
    :param client_uuid: client uuid
    :return: JSON with the test configurations and test uuids
    """

    tests = get_tests_for_client(client_uuid)

    for test in tests:
        # Additionally set the client_ip
        test["client_ip"] = request.environ.get('HTTP_X_FORWARDED_FOR') or request.environ.get('REMOTE_ADDR')
        # Insert tests, as soon as they are requested
        TEST_COLLECTION.insert_one(test)

    # Return json for the client, use json_util to also serialize object ids
    return json.dumps({"tests": tests}, default=json_util.default)


@post('/submit/<metric_id>/<test_uuid>')
def submit(metric_id, test_uuid):
    """
    Receive the test results from the clients

    :param metric_id:
    :param test_uuid:
    :return:
    """
    result = request.json

    validator = metric_loader.get_validation(metric_id)
    if validator:
        result = metric_loader.get_validation(metric_id)(test_uuid, result)
    save_result(result, test_uuid)


def save_result(result, test_uuid):
    """
    Save the result to the MongoDB
    :param result:
    :param test_uuid:
    :return:
    """

    # Get the test object from the MongoDB
    # TODO Check if stored
    TEST_COLLECTION.update_one({"test_uuid": test_uuid},
                               {"$set": {"result": result}})


def get_tests_for_client(client_uuid):
    tests = []

    # lookup which tests have to be scheduled for the client
    for metric_id in CONFIG['tests']:
        metric = CONFIG['tests'][metric_id]

        if args.run_test and not metric_id == args.run_test:
            continue

        schedule = metric['schedule']
        duration = metric['duration_seconds']
        iter = croniter(schedule, datetime.utcnow().timestamp())
        next_time = iter.get_next()

        # lookup if a test is already scheduled - if it is, continue and don't schedule
        scheduled_test = prepare_test(str(uuid.uuid4()), client_uuid, metric_id, next_time, duration)
        filter = dict(scheduled_test)
        del(filter["result_url"])
        del(filter["test_uuid"])
        del(filter["configuration"])
        if TEST_COLLECTION.find_one(filter):
            continue

        # append test to the list
        tests.append(scheduled_test)

    #schedule now for testing purposes
    if args.schedule_now:
        min_begin = min([test["begin"] for test in tests])
        diff = min_begin - int(datetime.utcnow().timestamp()) - 5 #a few extra seconds
        for test in tests:
            test["begin"] -= diff
            test["end"] -= diff

    # schedule the servers for all tests
    for test in tests:
        prepare_server(test)

    return tests

def prepare_server(test):
    """
    Schedule the server startup and shutdown for a specific test
    :param test:
    """

    metric_id = test["test"]

    # make shallow copy (enough for lists)
    test = dict(test)
    test["configuration"] = dict(test["configuration"])
    test_configuration = test["configuration"]

    # add port offset if necessary
    def add_offset(port):
        if isinstance(port, dict):
            new_port = dict(port)
            new_port["port"] = add_offset(port["port"])
            return new_port
        else:
            return port if port > 1024 else port + int(args.port_offset)

    if int(args.port_offset) > 0:
        if "port" in test_configuration:
            test_configuration["port"] = add_offset(test_configuration["port"])
        elif "ports" in test_configuration:
            test_configuration["ports"] = [add_offset(port) for port in test_configuration["ports"]]
        test_configuration["port_offset"] = args.port_offset

    if (not metric_id in SERVERS) or (not test["begin"] in SERVERS[metric_id]):
        server = metric_loader.get_server(metric_id)

        if server:
            def shutdown():
                server.shutdownServer()
                del SERVERS[metric_id][test["begin"]]

            now = int(datetime.utcnow().timestamp())

            start_timer = Timer(max(0, test["begin"] - now - 5), server.startupServer, [test]) # 5 secs in advange to boot up
            start_capture_timer = Timer(max(0, test["begin"] - now - 5), start_network_capture,
                                        [test, test["end"]])

            stop_timer = Timer(test["end"] - now, shutdown)


            TIMERS.append(start_timer)
            TIMERS.append(start_capture_timer)
            TIMERS.append(stop_timer)
            start_timer.start()
            start_capture_timer.start()
            stop_timer.start()

            if not metric_id in SERVERS:
                SERVERS[metric_id] = {}

            SERVERS[metric_id][test["begin"]] = server
            LOGGER.debug("Scheduled server {} for startup at {}, shutdown at {}".format(metric_id,
                                                                 datetime.fromtimestamp(test["begin"]),
                                                                 datetime.fromtimestamp(test["end"])))


def start_network_capture(test, stop_at):
    """
    Start the capture of the network interface for the given time interval and test
    Capture files will be named
    :param test:
    :param duration_seconds:
    :return:
    """
    capture_process = utils.start_network_capture("{}_{}_{}".format(test["test"],test["begin"],test["test_uuid"]))
    now = int(datetime.utcnow().timestamp())
    stop_timer = Timer(stop_at - now,capture_process.stop_capture,[])
    LOGGER.debug("stopping capture in {} secs".format(stop_at-now))
    TIMERS.append(stop_timer)
    stop_timer.start()



def prepare_test(test_uuid, client_uuid, metric_id, time_begin = 0, duration = 120):
    """
    Prepare a test for a client: Start up the test servers and return the test configuration
    :param test_uuid: uuid of the concrete test
    :param metric_id: e.g. tcp4
    :param time_begin: when to start the test (as unix timestamp)
    :param duration: how long the test servers are kept online in secs
    :return: the test configuration (dict)
    """
    begin = int(time_begin)
    end = int(time_begin + duration)
    test = {
        "test": metric_id,
        "test_uuid": test_uuid,
        "client_uuid": client_uuid,
        "begin": begin,
        "end": end,
        "result_url": "/submit/{metric_id}/{test_uuid}".format(metric_id=metric_id, test_uuid=test_uuid),
        "configuration": dict(CONFIG["tests"][metric_id])
    }

    # load dynamically inserted values into the test configuration
    formatting_function = lambda x : x.format(test_uuid=test_uuid) if isinstance(x,str) else x
    def format_configuration(d):
        if isinstance(d,str):
            return formatting_function(d)
        if isinstance(d,int):
            return d
        if isinstance(d,dict):
            d = dict(d)
        for k, v in d.items():
            if isinstance(v, dict):
                d[k] = format_configuration(v)
            else:
                if isinstance(v,str):
                    d[k] = formatting_function(d[k])
                elif isinstance(v,list):
                    d[k] = [format_configuration(r) for r in d[k]]
        return d


    test["configuration"] = format_configuration(test["configuration"])

    return test


def look_for_IP_changes():
    """
    Start observing a pre-defined directory for changes in text files
     which contain the IP addresses of clients
    Then, add these IP addresses to the ufw firewall
    """
    class ModificationHandler(FileSystemEventHandler):
        last_added_ip = None

        def on_modified(self, event):
            if event.event_type is 'modified' and not event.is_directory:
                source_file = event.src_path
                with open(source_file,'r') as file:
                    ips = file.read().strip().split("\n")
                    add_ip = None
                    remove_ip = None

                    # only add the new IP to the firewall if it changed
                    if len(ips) == 1:
                        # add rule (= new file)
                        add_ip = ips[0].strip()
                    # if the last IP differs -> this is the new IP, allow this IP, remove the old rule
                    elif len(ips) > 1 and not ips[-1] == ips[-2]:
                        add_ip = ips[-1].strip()
                        remove_ip = ips[-2].strip()

                    # validate correctnes of IPs
                    for ip in [i for i in [add_ip,remove_ip] if i is not None]:
                        try:
                            ip = ipaddress.ip_address(ip)
                        except ValueError:
                            LOGGER.error("invalid value for an IP: {}".format(ip))
                            return

                    if add_ip and not add_ip == self.last_added_ip:
                        # add IP to ufw
                        self.last_added_ip = add_ip
                        LOGGER.info("allowing IP {} for client {}".format(add_ip, os.path.basename(source_file)))
                        os.system("sudo ufw allow from {}".format(add_ip))

                        if remove_ip:
                            # remove IP from ufw ruleset
                            LOGGER.info("removing IP from ufw rules {} for client {}".format(remove_ip, os.path.basename(source_file)))
                            os.system("sudo ufw delete allow from {}".format(remove_ip))


    event_handler = ModificationHandler()
    observer = Observer()
    observer.schedule(event_handler, path=CONFIG["client_ip_directory"], recursive=False)
    observer.start()


def main():
    try:
        if CONFIG["enable_client_ip_handling"]:
            look_for_IP_changes()
        run(host="", port=CONFIG["server"]["port"])
    finally:
        # Shut down all test servers
        for _, metric_servers in SERVERS.items():
            for _, server in metric_servers.items():
                server.shutdownServer()
        for timer in TIMERS:
            timer.cancel()


# Load configuration, allow using a different filename
parser = ArgumentParser()
parser.add_argument("-c", "--config", dest="config", metavar="CONFIG_JSON_FILE",
                    help="The server's config file", default="server-config.json")

parser.add_argument("-p", "--port-offset", dest="port_offset", metavar="CONFIG_JSON_FILE",
                    help="Use the port offset for ports <1024", default="9000")

parser.add_argument("-t", "--run-test", dest="run_test", metavar="CONFIG_JSON_FILE",
                    help="Run only a specific test")

parser.add_argument("--clear-scheduled-tests", dest="clear", action="store_true",
                    help="Remove all scheduled tests from the database")

parser.add_argument("--schedule-now", dest="schedule_now", action="store_true",
                    help="Schedule all test requests NOW (ignoring the crontab)")


args = parser.parse_args()
CONFIG = utils.set_config(args.config)
# Stores all started servers
# servers = {'metric_id': server}
SERVERS = {}
# Stores all timers to cancel them afterwards
TIMERS = []

#get_tests_for_client("abcde")

# Initialize MongoClient
CLIENT = MongoClient(CONFIG["mongo"]["host"], CONFIG["mongo"]["port"])
MONGO_DATABASE = CLIENT[CONFIG["mongo"]["database"]]
TEST_COLLECTION = MONGO_DATABASE[CONFIG["mongo"]["test-collection"]]


logging.basicConfig(level=logging.DEBUG,
                    # filename="server.log",
                    format='%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)s')

if args.clear:
    TEST_COLLECTION.remove({
        "begin": {
            "$gt" : int(datetime.utcnow().timestamp())
        },
        "result" : None
    })
    LOGGER.info("removed all scheduled tests")
else:
    # resume planned tests
    tests = TEST_COLLECTION.find({
        "begin": {
            "$gt": int(datetime.utcnow().timestamp())
        },
        "result": None
    })

    # start corresponding servers
    for test in tests:
        prepare_server(test)



if __name__ == '__main__':
    main()
