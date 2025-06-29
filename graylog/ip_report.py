from ipaddress import ip_address

class IpReport:
    def __init__(self, query, result, logger):
        self.ipAddresses = set()
        if "errors" not in result:
            result = result["results"][query["id"]]["search_types"][query["search_types"][0]["id"]]
            self.name = result["name"]
        else:
            return
        if "rows" in result:
            for row in result["rows"]:
                if len(row["key"]) != 1:
                    continue
                if len(row["key"][0]) == 0:
                    logger.warning("%s reports empty address" % self.name)
                    continue
                ip = ip_address(row["key"][0])
                if not ip.is_global:
                    logger.warning("%s reports a non-public address" % self.name)
                    continue
                self.ipAddresses.add(ip)

        else:
            logger.info("No results emitted by query %s." % self.name)
