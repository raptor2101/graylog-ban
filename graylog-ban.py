#!/usr/bin/python3
import graylog
import firewall
import logging.handlers
import sys
import json
import ipaddress
from glob import glob


def build_commend(source_list):
    return " ".join(source_list)


if len(sys.argv) < 5:
    exit(-1)

logging.basicConfig(
        level=logging.DEBUG,
        format='%(name)s: %(message)s',
        handlers=[logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_LOCAL0)]
    )

logger = logging.getLogger('graylog-ban')
logger.setLevel(logging.DEBUG)


server = sys.argv[1]
token = sys.argv[2]

searchApi = graylog.Api(server, token, True, logger.getChild("Graylog.Api"))

whiteList = list()
ipAddresses = dict()

queriesFolder = "%s/*.json" % sys.argv[3]
files = glob(queriesFolder)
if len(files) == 0:
    logger.error("No query JSONs found in  %s." % sys.argv[3])
    exit(-1)

with open(sys.argv[4]) as whiteList_file:
    for line in whiteList_file.readlines():
        elements = line.rstrip().split(" ")
        if len(elements) == 0:
            continue
        if len(elements[0]) == 0:
            continue
        if "/" in elements[0]:
            whiteList = [*whiteList, *ipaddress.ip_network(elements[0]).hosts()]
        else:
            whiteList.append(ipaddress.ip_address(elements[0]))

for file in files:
    with open(file) as json_file:
        logger.debug("Execute query %s." % file)
        query = json.load(json_file)
        response = searchApi.query(query)
        if response is None:
            logger.error("Unable to process query %s." % file)
            continue
        report = graylog.IpReport(query, response, logger.getChild("IpReport"))
        logger.debug("Query %s results %d IP addresses." % (file, len(report.ipAddresses)))
        for ipAddress in report.ipAddresses:
            if ipAddress in whiteList:
                logger.debug("IP Address %s is whitelisted (%s)"%(ipAddress, report.name))
                continue
            if ipAddress in ipAddresses:
                ipAddresses[ipAddress].append(report.name)
            else:
                ipAddresses[ipAddress] = [report.name]

logging.debug("%d IPs loaded." % len(ipAddresses))
if len(sys.argv) < 7:
    print("No firewall parameters given. Just printing the loaded IPs")
    for ipAddress in ipAddresses:
        sources = build_commend(ipAddresses[ipAddress])
        logger.info("%s - %s" % (ipAddress, sources))
    exit(0)



chain = firewall.Chain(sys.argv[5], logger.getChild("Firewall.Chain"))
action = sys.argv[6]

rules = list(chain.list())
logging.debug("%d Firewall rules loaded." % len(rules))
for rule in rules:
    if rule.action != action:
        continue
    if rule.source not in ipAddresses:
        logger.info("IP %s not present in any source. Dropping rule!" % rule.source)
        chain.remove(rule)
    else:
        comment = build_commend(ipAddresses[rule.source])

        if rule.comment != comment:
            logger.debug("Update command %s for rule %s." % (comment, rule))
            chain.remove(rule)
            rule.comment = comment
            chain.insert(1, rule)
        del ipAddresses[rule.source]

logger.debug("%d new IPs detected. Adding them" % len(ipAddresses))

for ipAddress in ipAddresses:
    comment = build_commend(ipAddresses[ipAddress])
    logger.info("Creating rule for IP %s (present in sources [%s])" % (ipAddress, comment))
    rule = firewall.Rule()
    rule.action = action
    rule.source = ipAddress
    rule.comment = comment
    chain.insert(1, rule)
