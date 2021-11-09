class IpReport:
    def __init__(self, result):

        self.ipAddresses = set()
        if "errors" not in result:
            result = result["results"]["?"]["search_types"]["?"]
            self.name = result["name"]
            for row in result["rows"]:
                if len(row["key"]) == 1:
                    self.ipAddresses.add(row["key"][0])
