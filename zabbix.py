import os
import json

import requests


class ZabbixAPI:

    def __init__(self):

        self.zabbix_url = os.environ["ZABBIX_URL"]
        self.zabbix_user = os.environ["ZABBIX_USER"]
        self.zabbix_password = os.environ["ZABBIX_PASSWORD"]
        self.token = None
        self.base_id = 10

    def send(self, method: str, params: dict) -> dict:
        """
        General purpose method for sending requests to the Zabbix API. Includes special handling for logging in
        :param method:
        :param params:
        :return:
        """

        headers = {'Content-Type': 'application/json-rpc'}

        auth_params = {"user": self.zabbix_user,
                       "password": self.zabbix_password}

        body = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if method != "user.login" else auth_params,
            "id": self.base_id,
            "auth": self.token if self.token else None
        }

        req = requests.post(self.zabbix_url,
                            data=json.dumps(body),
                            headers=headers)

        result = json.loads(req.text)

        if "error" in result.keys():
            self.base_id += 1  # <-- This is a little naive but we're not expecting to deal with inbound requests so...
            return result
        else:
            if method == "user.login":
                self.token = result["result"]

            self.base_id += 1

            return result
