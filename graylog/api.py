import requests
import json

class Api:
    def __init__(self, server, token, verify_server_cert, logger):
        self.url = f"{server}/api/views/search/sync"
        self.auth_token = (token, "token")
        self.headers = {"Content-Type": "application/json", "X-Requested-By": "jupyter"}
        self.logger = logger
        self.verifyServerCert = verify_server_cert

    def query(self, query):
        payload = {
            "queries": [query]
        }

        response = requests.post(self.url, data=json.dumps(payload), auth=self.auth_token, headers=self.headers, verify=self.verifyServerCert)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            self.logger.error("Unable to process query. ErrorMessage: %s." % response.content)
        else:
            self.logger.error("Unable to process query. StatusCode: %d." % response.status_code)
        return None
