from metrics.cm7.client7cm import Client7cm
from metrics.cm7 import server7cm
from metrics.tcp4.tcp4 import ClientTCP4, ServerTCP4
from metrics.tcp4 import tcp4
from metrics.dns7 import dns7
from metrics.syn4 import syn4
from metrics.udp4 import udp4
from metrics.smtp7 import stls7
from metrics.tcps4 import tcps4
from metrics.pop37 import pop37
from metrics.trac3 import trac3
from metrics.tls4 import tls4
from metrics.voip7 import voip7
from metrics.cm7 import cm7
from metrics.ooni7 import ooni7


def get_metrics():
    return ["cm7", "vs7", "mm7", "http7", "pop37", "smtp7", "stls7", "voip7", "ndns7", "bdns7",
                             "tcp4", "udp4", "tcps4", "syn4", "tls4", "trac3", "ooni7"]


def is_valid_metric(metric_id):
        return metric_id in get_metrics()


def get_client(metric_id):
    """
    Return the given client for a metric
    :param metric_id:
    :return: Metric object
    """
    if is_valid_metric(metric_id) and (metric_id == "vs7" or metric_id == "http7"):
        return Client7cm()
    if is_valid_metric(metric_id) and (metric_id == "cm7"):
        return cm7.ClientCM7()
    if is_valid_metric(metric_id) and metric_id == "tcp4":
        return ClientTCP4()
    if is_valid_metric(metric_id) and (metric_id == "tcps4" or metric_id == "mm7"):
        return tcps4.ClientTCPS4()
    if is_valid_metric(metric_id) and metric_id == "syn4":
        return syn4.ClientSyn4()
    if is_valid_metric(metric_id) and metric_id == "udp4":
        return udp4.ClientUDP4()
    if is_valid_metric(metric_id) and (metric_id == "stls7" or metric_id == "smtp7"):
        return stls7.ClientSTLS7()
    if is_valid_metric(metric_id) and metric_id == "pop37":
        return pop37.ClientPOP37()
    if is_valid_metric(metric_id) and metric_id == "tls4":
        return tls4.ClientTLS4()
    if is_valid_metric(metric_id) and metric_id == "trac3":
        return trac3.ClientTrac3()
    if is_valid_metric(metric_id) and \
            (metric_id == "ndns7" or metric_id == "bdns7"):
        return dns7.ClientDNS7()
    if is_valid_metric(metric_id) and metric_id == "voip7":
        return voip7.ClientVOIP7()
    if is_valid_metric(metric_id) and metric_id == "ooni7":
        return ooni7.ClientOONI7()
    else:
        raise NotImplemented

def get_server(metric_id):
    """
    Return the given server for a metric
    :param metric_id:
    :return: Metric object
    """
    if is_valid_metric(metric_id) and (metric_id == "vs7" or metric_id == "http7"):
        return server7cm.Server7cm()
    if is_valid_metric(metric_id) and (metric_id == "cm7"):
        return cm7.ServerCM7()
    if is_valid_metric(metric_id) and metric_id == "tcp4":
        return ServerTCP4()
    if is_valid_metric(metric_id) and (metric_id == "tcps4" or metric_id == "mm7"):
        return tcps4.ServerTCPS4()
    if is_valid_metric(metric_id) and metric_id == "syn4":
        return syn4.ServerSyn4()
    if is_valid_metric(metric_id) and metric_id == "udp4":
        return udp4.ServerUDP4()
    if is_valid_metric(metric_id) and (metric_id == "stls7" or metric_id == "smtp7"):
        return stls7.ServerSTLS7()
    if is_valid_metric(metric_id) and metric_id == "pop37":
        return pop37.ServerPOP37()
    if is_valid_metric(metric_id) and metric_id == "tls4":
        return tls4.ServerTLS4()
    if is_valid_metric(metric_id) and metric_id == "voip7":
        return voip7.ServerVOIP7()
    if is_valid_metric(metric_id) and \
        (metric_id == "ndns7" or metric_id == "bdns7" or metric_id == "trac3" or metric_id == "ooni7"):
        return None
    else:
        raise NotImplemented


def get_validation(metric_id):
    """
    Return the validation function for a metric
    :param metric_id:
    :return:
    """
    if is_valid_metric(metric_id) and (metric_id == "vs7" or metric_id == "http7"):
        return server7cm.validateClientResults
    if is_valid_metric(metric_id) and (metric_id == "cm7"):
        return cm7.validateClientResults
    if is_valid_metric(metric_id) and metric_id == "tcp4":
        return tcp4.validateClientResults
    if is_valid_metric(metric_id) and (metric_id == "tcps4" or metric_id == "mm7"):
        return tcps4.validateClientResults
    if is_valid_metric(metric_id) and (metric_id == "stls7" or metric_id == "smtp7"):
        return stls7.validateClientResults
    if is_valid_metric(metric_id) and metric_id == "pop37":
        return pop37.validateClientResults
    if is_valid_metric(metric_id) and metric_id == "udp4":
        return None
    if is_valid_metric(metric_id) and metric_id == "syn4":
        return None
    if is_valid_metric(metric_id) and metric_id == "tls4":
        return tls4.validateClientResults
    if is_valid_metric(metric_id) and metric_id == "voip7":
        return None
    if is_valid_metric(metric_id) and \
            (metric_id == "ndns7" or metric_id == "bdns7" or metric_id == "trac3" or metric_id == "ooni7"):
        return None
    else:
        raise NotImplemented


# def get_example_test(self, metric_id):
#     if is_valid_metric(metric_id) and metric_id == "cm7":
#         return server7cm.validateClientResults
#     else:
#         raise NotImplemented
