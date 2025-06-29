import subprocess
import sys
from .rule import Rule

__iptables__ = "/sbin/iptables"


class Chain:
    def __init__(self, name, logger):
        self.ipTables = __iptables__
        self.name = name
        self.logger = logger

    def list(self):
        self.logger.debug("List all firewall rules of chain %s" % self.name)
        parameters = [self.ipTables, "-L", self.name, "-n", "-v"]

        for line in subprocess.check_output(parameters).decode(sys.stdout.encoding).split('\n'):
            rule = Rule(line)
            if rule.isValid:
                yield rule

    def add(self, rule):
        parameters = [self.ipTables, "-A", self.name]
        self._add_rule_parameters(parameters, rule)
        self.logger.debug("Add rule to chain %s - %s" % (self.name, rule))
        self._execute(parameters)

    def insert(self, position, rule):
        parameters = [self.ipTables, "-I", self.name, str(position)]
        self._add_rule_parameters(parameters, rule)
        self.logger.debug("Insert rule to chain %s pos %d - %s" % (self.name, position, rule))
        self._execute(parameters)

    def remove(self, rule):
        parameters = [self.ipTables, "-D", self.name]
        self._add_rule_parameters(parameters, rule)
        self.logger.debug("Remove rule from chain %s - %s" % (self.name, rule))
        self._execute(parameters)

    def flush(self):
        self.logger.debug("Flush chain %s" % self.name)
        self._execute([self.ipTables, "-F", self.name])

    def _execute(self, command):
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in proc.stdout:
            self.logger.debug(line.decode(sys.stdout.encoding))
        for line in proc.stderr:
            self.logger.debug(line.decode(sys.stderr.encoding))

    @staticmethod
    def _add_rule_parameters(parameters, rule):
        if rule.protocol is not None:
            parameters.extend(["-p", rule.protocol])
        if rule.source is not None:
            parameters.extend(["-s", str(rule.source)])
        if rule.destination is not None:
            parameters.extend(["-d", str(rule.destination)])
        if rule.comment is not None:
            parameters.extend(["-m", "comment", "--comment", rule.comment])
        parameters.extend(["-j", rule.action])
