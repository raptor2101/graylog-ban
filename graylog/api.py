import requests
import json


class Api:
    def __init__(self, server, token):
        self.url = f"{server}/api/views/search/sync"
        self.auth_token = (token, "token")
        self.headers = {"Content-Type": "application/json", "X-Requested-By": "jupyter"}

    def query(self, query):
        payload = {
            "queries": [query]
        }

        response = requests.post(self.url, data=json.dumps(payload), auth=self.auth_token, headers=self.headers)
        if response.status_code == 200:
            return response.json()


