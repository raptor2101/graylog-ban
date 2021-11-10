#!/usr/bin/python3
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

files = glob("%s/*.json" % sys.argv[3])
if len(files) == 0:
    syslog.syslog(syslog.LOG_ERR, "No query JSONs found in  %s." % sys.argv[3])
    exit(-1)

for file in files:
    with open(file) as json_file:
        syslog.syslog(syslog.LOG_DEBUG, "Execute query %s." % file)
        query = json.load(json_file)
        response = searchApi.query(query)
        if response is None:
            syslog.syslog(syslog.LOG_ERR, "Unable to process query %s." % file)
            continue
        report = graylog.IpReport(query, response)
        syslog.syslog(syslog.LOG_INFO, "Query %s results %d IP addresses." % (file, len(report.ipAddresses)))
        for ipAddress in report.ipAddresses:
            if ipAddress in ipAddresses:
                ipAddresses[ipAddress].append(report.name)
            else:
                ipAddresses[ipAddress] = [report.name]

syslog.syslog(syslog.LOG_DEBUG, "%d IPs loaded." % len(ipAddresses))
chain = firewall.Chain(sys.argv[4])

rules = list(chain.list())
syslog.syslog(syslog.LOG_DEBUG, "%d Firewall rules loaded." % len(rules))
for rule in rules:
    if rule.action != action:
        continue
    if rule.source not in ipAddresses:
        syslog.syslog(syslog.LOG_INFO, "IP %s not present in any source. Dropping rule!" % rule.source)
        chain.remove(rule)
    else:
        comment = build_commend(ipAddresses[rule.source])

        if rule.comment != comment:
            syslog.syslog(syslog.LOG_DEBUG, "Update command %s for rule %s." % (comment, rule))
            chain.remove(rule)
            rule.comment = comment
            chain.insert(1, rule)
        del ipAddresses[rule.source]

syslog.syslog(syslog.LOG_DEBUG, "%d new IPs detected. Adding them" % len(ipAddresses))

for ipAddress in ipAddresses:
    comment = build_commend(ipAddresses[ipAddress]);
    syslog.syslog(syslog.LOG_INFO, "Creating rule for IP %s (present in sources [%s])" % (ipAddress, comment))
    rule = firewall.Rule()
    rule.action = action
    rule.source = ipAddress
    rule.comment = comment
    chain.insert(1, rule)
