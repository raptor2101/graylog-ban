#!/usr/bin/python3
from datetime import datetime
import graylog
import firewall
import syslog
import sys
import json
from glob import glob


def build_commend(source_list):
    return " ".join(source_list)


if len(sys.argv) < 6:
    exit(-1)

syslog.openlog(facility=syslog.LOG_LOCAL0)

server = sys.argv[1]
token = sys.argv[2]
action = sys.argv[5]

searchApi = graylog.Api(server, token)

ipAddresses = dict()
for file in glob("%s/*.json" % sys.argv[3]):
    with open(file) as json_file:
        query = json.load(json_file)
        report = graylog.IpReport(searchApi.query(query))
        for ipAddress in report.ipAddresses:
            if ipAddress in ipAddresses:
                ipAddresses[ipAddress].append(report.name)
            else:
                ipAddresses[ipAddress] = [report.name]

chain = firewall.Chain(sys.argv[4])
for rule in chain.list():
    if rule.action != "DROP":
        break
    if rule.source not in ipAddresses:
        chain.remove(rule)
    else:
        comment = build_commend(ipAddresses[rule.source])
        if rule.comment != comment:
            chain.remove(rule)
            rule.comment = comment
            chain.insert(1, rule)
        del ipAddresses[rule.source]

now = datetime.now()
for ipAddress in ipAddresses:
    rule = firewall.Rule()
    rule.action = action
    rule.source = ipAddress
    rule.comment = build_commend(ipAddresses[ipAddress])
    chain.insert(1, rule)
