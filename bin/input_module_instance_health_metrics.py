# encoding = utf-8

import datetime
import json
import os
import re
import requests
import sys
import time

class Config:
    supported_minimum_version: str = "4.4.0"
    fields: list = ["cpu_usage", "data_disk_free_space", "last_seen", "data_disk_size", "memory_free_space", "memory_size", "swap_free_space", "swap_size", "hostname", "node_id", "status"]

class API:
    def __init__(self, url, api_key, api_secret, verify=False, timeout=900):
        self._url = url
        self._api_key = api_key
        self._api_secret = api_secret
        self._verify = verify
        self._timeout = timeout

    def _rest_base(self, method, api_endpoint, data=None, params=None, headers={}):
        requests_method = getattr(requests, method)
        response = None
        exception = None
        req = None

        try:
            headers['api-key'] = self._api_key
            headers['api-secret'] = self._api_secret

            if True == self._verify:
                req = requests_method(f"{self._url}{api_endpoint}", timeout=self._timeout, params=params, data=json.dumps(data), headers=headers)
            else:
                req = requests_method(f"{self._url}{api_endpoint}", timeout=self._timeout, params=params, data=json.dumps(data), headers=headers, verify=self._verify)

        except Exception as e:
            exception = e

        req_status_code = None

        if req is not None:
            req_status_code = req.status_code

        req_json = {"data": ""}

        if req is not None:
            req_json = req.json()

        return (req_status_code, req_json, exception)

    def get(self, api_endpoint, data=None, params=None, headers={}):
        return self._rest_base("get", api_endpoint, data=data, params=params, headers=headers)

    def post(self, api_endpoint, data=None, params=None, headers={}):
        return self._rest_base("post", api_endpoint, data=data, params=params, headers=headers)

class Metadata:
    def __init__(self, api):
        self._api = api
        self._api_endpoint = "/api/settings/metadata"

    def get_version(self):
        status, response, exception = self._api.get(self._api_endpoint)

        if status == 200 and response is not None and exception is None:
            return response["Installed Version"]
        else:
            raise Exception(f"Critical Error! Status Code: '{status}' Exception: '{exception}'")
            
class Lifecycle:
    def __init__(self, api):
        self._api = api
        self._api_endpoint = "/api/dashboard/lifecycle"
        self._response = None
        self._sub_phases = {}
        self.status = None

    def update(self):
        status, response, exception = self._api.get(self._api_endpoint)

        if status == 200 and response is not None and exception is None:
             self._response = response
             status = self._response["data"]["attributes"]["status"]
             self.status = True if "done" not in status else False

             for sub_phase in self._response["data"]["attributes"]["sub_phases"]:
                 self._sub_phases[sub_phase["name"].lower()] = True if sub_phase["status"] == 1 else False
        else:
            raise Exception(f"Critical Error! Status Code: '{status}' Exception: '{exception}'")

    def discovery_is_running(self):
        if False == bool(self._sub_phases):
            self.update()

        return self.status

    def correlation_is_complete(self):
        if False == bool(self._sub_phases):
            self.update()

        return self._sub_phases["post_correlation"]


class Instances():
    def __init__(self, api):
        super().__init__()
        self._api = api

    def get(self, node_names=[], fields=[]):
        uuid = None
        queries = {}
        output = []

        status, response, exception = self._api.get(f"/api/instances")

        if exception or status != 200:
            raise Exception(f"Failure to retrieve saved query: {exception}")

        response.pop("meta")

        for instance in response["data"]:
            if instance["attributes"]["node_name"] in node_names or len(node_names) == 0:
                inst_obj = {}

                inst_obj["node_name"] = instance["attributes"]["node_name"]

                for field in instance["attributes"]:
                    if field in fields:
                        inst_obj[field] = instance["attributes"][field]

                output.append(inst_obj)

        return output

def validate_input(helper, definition):
    pass

def collect_events(helper, ew):
    # get Axonius configuration
    opt_api_host = helper.get_arg('api_host')
    opt_api_key = helper.get_arg('api_key')
    opt_api_secret = helper.get_arg('api_secret')


    opt_ssl_certificate_path = helper.get_arg('ssl_certificate_path')
    opt_enforce_ssl_validation = helper.get_arg('enforce_ssl_validation')
    
    # Logging functions
    def log_info(msg):
        helper.log_info(f"Input '{helper.get_arg('name')}' - {msg}")
        
    def log_warning(msg):
        helper.log_warning(f"Input '{helper.get_arg('name')}' - {msg}")
        
    def log_error(msg):
        helper.log_error(f"Input '{helper.get_arg('name')}' - {msg}")
        
    def log_critical(msg):
        helper.log_critical(f"Input '{helper.get_arg('name')}' - {msg}")
    
    critical_error = False

    # Set verify to True/False
    verify = opt_enforce_ssl_validation

    # Change the value of verify to the path of the ca_bundle if specified
    if opt_ssl_certificate_path:
        if len(opt_ssl_certificate_path) > 0:
            verify = opt_ssl_certificate_path
            
    api_host = opt_api_host
    
    match = re.match("(?:https?:\/\/)?([0-9A-z-.]+\:?\d*)\/?|([0-9A-z-.]+\:?\d*)(?:\/)?", opt_api_host)
    
    # Only set host if the regex exists, match should never be None.
    if match is not None:
        api_host = f"https://{match.groups()[0]}"

    # The host field will be used to set the source host in search
    host = None

    # Pull out just the host information from the Host
    match = re.match("(?:https?:\/\/)([0-9A-z-.]+)(?::\d+)?", opt_api_host)

    # Only set host if the regex exists, match should never be None.
    if match is not None:
        host=match.groups()[0]

    # Create API objects for REST calls
    api = API(api_host, opt_api_key, opt_api_secret, verify)
    
    metadata = Metadata(api)
    
    version = metadata.get_version()

    # Pull out just the host information from the Host
    match = re.match("(\d+\_\d+\_\d+)(?:_RC\d+)", version)

    # Only set host if the regex exists, match should never be None.
    if match is not None:
        version = match.groups()[0].replace("_", ".")

    log_info(f"STATS - Version: {version}")
    
    # Turn versions into tuples for equality comparison
    tup_version = tuple(map(int, (version.split("."))))
    tup_supported_version = tuple(map(int, (Config.supported_minimum_version.split("."))))
    
    # If the current version is less than supported, throw a critical exception
    if tup_version < tup_supported_version:
        raise Exception("UnsupportedVersion")

    try:
        node_names = Config.node_names
    except Exception as ex:
        node_names = []
        
    instances = Instances(api)

    # Check if a discovery is running and correlation hasn't complete, warn customer if true
    lifecycle = Lifecycle(api)
    metrics = instances.get(fields=Config.fields)
    
    for instance in metrics:
        instance["system_discovery_running"] = lifecycle.discovery_is_running()
        instance["version"] = metadata.get_version()
        
        # Create event
        event = helper.new_event(source=helper.get_arg('name'), host=host, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(instance))
        
        ew.write_event(event)
    