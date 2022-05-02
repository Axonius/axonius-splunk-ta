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
    retry_standoff: list = [0, 5, 10, 15, 30, 60]
    request_timeout: int = 900
    
class Subscribe:
    def __init__(self):
        self.__listeners = []

    def notify_listeners(self, event, **kwargs):
        for listener in self.__listeners:
            if listener['event'] == event:
                if kwargs.__len__() == 0:
                    listener['callback']()
                elif kwargs.__len__() == 1:
                    listener['callback'](kwargs[list(kwargs.keys())[0]])
                else:
                    listener['callback'](**kwargs)

    def add_event_listener(self, event, callback):
        add_event = True
        new_listener = None

        for listener in self.__listeners:
            if listener['event'] == event:
                if listener['callback'] == callback:
                    add_event = False

        if add_event:
            new_listener = {
                "event": event,
                "callback": callback
            }

            self.__listeners.append(new_listener)

        return new_listener

    def on(self, event, callback):
        return self.add_event_listener(event, callback)

    def remove_event_listener(self, event, callback):
        subject = {
            "event": event,
            "callback": callback
        }

        for listener in self.__listeners:
            if listener == subject:
                self.__listeners.remove(listener)

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


class FetchHistory(Subscribe):
    def __init__(self, api):
        super().__init__()
        self._api = api

    def get(self, date_from=None, date_to=None, page_size=1000, logger=None):
        response = { "data": "init" }
        fetches = []
        offset = 0
        
        if logger is not None:
            logger(f"Date From: {date_from}")
            logger(f"Date To: {date_to}")
        
        if date_from is None:
            date_from = datetime.datetime.now() - datetime.timedelta(days = 1)
            date_from = date_from.timestamp()
        
        df = datetime.datetime.utcfromtimestamp(date_from).isoformat()
        dt = datetime.datetime.utcfromtimestamp(date_to).isoformat()
        
        if logger is not None:
            logger(f"Date From: {df}")
            logger(f"Date To: {dt}")
        
        while response:
            data =  {
                "data": {
                    "type":"history_request_schema",
                    "attributes": {
                        "page":{
                            "offset": offset,
                            "limit": page_size
                        },
                        "date_from": df,
                        "date_to": dt,
                        "adapters_filter":[

                        ],
                        "clients_filter":[

                        ],
                        "statuses_filter":[

                        ],
                        "exclude_realtime": False
                    }
                }
            }

            status, response, exception = self._api.post("/api/adapters/history", data=data)

            if not exception or status == 200:
                self.notify_listeners("page_retrieved", page=response)

                offset += page_size
            else:
                raise Exception(f"Critical Error! Status Code: {status}\tException: {exception}")

def validate_input(helper, definition):
    # Logging functions
    def log_info(msg):
        helper.log_info(f"Input '{helper.get_arg('name')}' - {msg}")
        
    # get Axonius configuration
    api_host = definition.parameters.get('api_host', str)
    api_key = definition.parameters.get('api_key', "")
    api_secret = definition.parameters.get('api_secret', "")

    # get extra options
    page_size = definition.parameters.get('page_size', str)
    api_standoff = definition.parameters.get('standoff_ms', str)
    ssl_certificate_path = definition.parameters.get('ssl_certificate_path', "")
    enforce_ssl_validation = definition.parameters.get('enforce_ssl_validation')

    try:
        if int(page_size) < 1:
            raise ValueError("Page Size must be an integer greater than 0")

        if int(api_standoff) < 0:
            raise ValueError("API Standoff must be an integer greater or equal to 0")

    except Exception as ex:
        raise ValueError(ex)
    
    match = re.match("(?:https?:\/\/)?([0-9A-z-.]+\:?\d*)\/?|([0-9A-z-.]+\:?\d*)(?:\/)?", api_host)
    
    # Only set host if the regex exists, match should never be None.
    if match is not None:
        api_host = f"https://{match.groups()[0]}"
        
    log_info(f"VARS - API Host: {api_host}")

    # Create api object
    try:
        verify = True

        helper.log_info(f"enforce_ssl_validation: {enforce_ssl_validation}")

        if str(enforce_ssl_validation).lower() not in ["1", "true"]:
            verify = False

        helper.log_info(f"verify: {verify}")

        if ssl_certificate_path is not None:
            if len(ssl_certificate_path) > 0:
                verify = ssl_certificate_path

        api = API(api_host, str(api_key), str(api_secret), verify)
        metadata = Metadata(api)
        out = metadata.get_version()
    except Exception as ex:
        helper.log_info(ex)

        if "Could not find a suitable TLS CA certificate bundle" in str(ex):
            raise ValueError("Critical Error, check CA Bundle Path exists and the splunk user has proper permissions")
        elif "SSLCertVerificationError" in str(ex) or "Could not find a suitable TLS CA certificate bundle" in str(ex):
            raise ValueError("The Axonius host fails SSL verification, please review your SSL certificate validation settings")
        elif "401" not in str(ex):
            raise ValueError(f"Critical Error: {ex}")

    pass

def collect_events(helper, ew):
    # Retrieve checkpoint
    checkpoint_name = f"checkpoint_{helper.get_arg('name')}_adapter_fetch_history"

    # get Axonius configuration
    opt_api_host = helper.get_arg('api_host')
    opt_api_key = helper.get_arg('api_key')
    opt_api_secret = helper.get_arg('api_secret')

    # get extra options
    opt_page_size = helper.get_arg('page_size')
    opt_standoff_ms = helper.get_arg('standoff_ms')
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
    
    # Log input variables
    log_info(f"VARS - Axonius Host: {opt_page_size}")
    log_info(f"VARS - Page size: {opt_page_size}")
    log_info(f"VARS - API standoff (ms): {opt_standoff_ms}")
    log_info(f"VARS - Enforce SSL validation: {opt_enforce_ssl_validation}")
    log_info(f"VARS - CA bundle path: {opt_ssl_certificate_path}")
    
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
        
    log_info(f"VARS - API Host: {api_host}")

    # The host field will be used to set the source host in search
    host = None

    # Pull out just the host information from the Host
    match = re.match("(?:https?:\/\/)([0-9A-z-.]+)(?::\d+)?", opt_api_host)

    # Only set host if the regex exists, match should never be None.
    if match is not None:
        host=match.groups()[0]

    timeout = Config.request_timeout if helper.get_arg('name') is not None else 5
    retry_standoff = Config.retry_standoff if helper.get_arg('name') is not None else [0, 3, 3, 3]

    # Create an API object for REST calls
    api = API(api_host, opt_api_key, opt_api_secret, verify, timeout=timeout)

    # Load the input's checkpoint data
    checkpoint = helper.get_check_point(checkpoint_name)

    if checkpoint is not None:
        log_info(f"VARS - Check point: {checkpoint_name}")


    # Retry variables
    fetch_complete = False
    exception_thrown = False
    max_retries = len(retry_standoff)
    retries = 0
    version = None
    fetch_complete = False
    date_to = datetime.datetime.now().timestamp()

    while retries < max_retries and not True == critical_error and not True == fetch_complete:
        try:
            if version is None:
                # Get the raw Axonius version from the metadata endpoint
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
                    
                # Reset retries and exception_thrown
                retries = 0
                exception_thrown = False
                    
            if not True == fetch_complete:
                fetch_history = FetchHistory(api)
            
                def page_callback(page):
                    for fetch in page:
                        event = helper.new_event(source=helper.get_arg('name'), host=host, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(fetch))
                        ew.write_event(event)
            
                fetch_history.add_event_listener("page_retrieved", page_callback)
            
                date_from = checkpoint if helper.get_arg('name') is not None else None
                fetch_history.get(date_from=date_from, date_to=date_to, logger=log_info)
                
                fetch_complete = True
            
                # Reset retries and exception_thrown
                retries = 0
                exception_thrown = False
        except Exception as ex:
            # Die if running an unsupported version of Axonius, or log the error and track for retry purposes
            if "UnsupportedVersion" in str(ex):
                critical_error = True
            else:
                log_error(f"ERR - Error '{ex}'")
                exception_thrown = True



        if True == critical_error:
            log_critical(f"Critical Error: Axonius version {version} is unsupported, the minimum version is {Config.supported_minimum_version}")
        elif True == exception_thrown and not True == fetch_complete:
            # Increment retry counter
            retries += 1

            if retries < max_retries:
                #Log retry number and display the standoff
                log_info(f"COLL - Retry {retries} sleeping for {retry_standoff[retries]} seconds, then retrying")

                # Sleep the process and then retry
                time.sleep(retry_standoff[retries])
            else:
                # Log no devices after max retries
                log_critical(f"Critical Error: Unable to complete fetch due to unrecoverable errors.")
        elif True == exception_thrown and True == fetch_complete:
            # Log recovered from error during fetch
            log_warning(f"Warning: Fetch was interrupted by a transient error, review results for fetch completeness.")
        else:
            # Save new checkpoint if entity_count is greater than one
            helper.save_check_point(checkpoint_name, date_to)