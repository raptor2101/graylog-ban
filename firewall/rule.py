import re

__regex__ = re.compile("^\\s+(\\d+)\\s+\\d+\\w? (\\w+)\\s+(\\w+)\\s+--\\s+\\*\\s+\\*\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+(/\\d+)?)\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+(/\\d+)?)\\s+(/\\* (.*?) \\*/)?")


class Rule:
    def __init__(self, listing=None):
        if listing is None:
            self.isValid = True
            self.action = "DROP"
            self.hits = None
            self.protocol = None
            self.source = None
            self.destination = None
            self.comment = None
            return

        self.isValid = False
        match = __regex__.search(listing)
        if match is None:
            return

        self.isValid = True
        self.hits = match.group(1)
        self.action = match.group(2)
        self.protocol = match.group(3)
        self.source = match.group(4)
        self.destination = match.group(6)
        self.comment = match.group(9)

    def __str__(self):
        return "proto=%s src=%s dst=%s action=%s comment=%s" % (
            self.protocol, self.source, self.destination, self.action, self.comment)
