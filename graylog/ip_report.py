import syslog


class IpReport:
    def __init__(self, query, result):

        self.ipAddresses = set()
        if "errors" not in result:
            result = result["results"][query["id"]]["search_types"][query["search_types"][0]["id"]]
            self.name = result["name"]
        else:
            return
        if "rows" in result:
            for row in result["rows"]:
                if len(row["key"]) == 1:
                    self.ipAddresses.add(row["key"][0])
        else:
            syslog.syslog(syslog.LOG_INFO, "No results emitted by query %s." % self.name)
