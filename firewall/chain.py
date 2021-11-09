from subprocess import check_output
from subprocess import call

import syslog
import sys
from .rule import Rule

__iptables__ = "/sbin/iptables"


class Chain:
    def __init__(self, name):
        self.ipTables = __iptables__
        self.name = name

    def list(self):
        syslog.syslog(syslog.LOG_DEBUG, "List all firewall rules of chain %s" % self.name)
        parameters = [self.ipTables, "-L", self.name, "-n", "-v"]

        for line in check_output(parameters).decode(sys.stdout.encoding).split('\n'):
            rule = Rule(line)
            if rule.isValid:
                yield rule

    def add(self, rule):
        parameters = [self.ipTables, "-A", self.name]
        self._add_rule_parameters(parameters, rule)
        syslog.syslog(syslog.LOG_INFO, "Add rule to chain %s - %s" % (self.name, rule))
        call(parameters)

    def insert(self, position, rule):
        parameters = [self.ipTables, "-I", self.name, str(position)]
        self._add_rule_parameters(parameters, rule)
        syslog.syslog(syslog.LOG_INFO, "Insert rule to chain %s pos %d - %s" % (self.name, position, rule))
        call(parameters)

    def remove(self, rule):
        parameters = [self.ipTables, "-D", self.name]
        self._add_rule_parameters(parameters, rule)
        syslog.syslog(syslog.LOG_INFO, "Remove rule from chain %s - %s" % (self.name, rule))
        call(parameters)

    def flush(self):
        call([self.ipTables, "-F", self.name])

    @staticmethod
    def _add_rule_parameters(parameters, rule):
        if rule.protocol is not None:
            parameters.extend(["-p", rule.protocol])
        if rule.source is not None:
            parameters.extend(["-s", rule.source])
        if rule.destination is not None:
            parameters.extend(["-d", rule.destination])
        if rule.comment is not None:
            parameters.extend(["-m", "comment", "--comment", rule.comment])
        parameters.extend(["-j", rule.action])
