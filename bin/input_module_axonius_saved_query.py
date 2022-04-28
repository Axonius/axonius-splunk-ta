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


class SavedQueries:
    def __init__(self, api, base_api_endpoint):
        self._api = api
        self._api_endpoint = base_api_endpoint
        self._queries = {}

    def get_attributes_by_name(self, query_name):
        uuid = None

        if False == bool(self._queries):
            status, response, exception = self._api.get(f"{self._api_endpoint}/views/saved")

            if exception is not None:
                raise Exception(exception)

            for query in response["data"]:
                self._queries[query["attributes"]["name"]] = query["attributes"]["uuid"]

        if query_name in self._queries.keys():
            uuid = self._queries[query_name]

        if uuid is not None:
            for query in response["data"]:
                if query["attributes"]["uuid"] == uuid:
                    query_filter = query["attributes"]["view"]["query"]["filter"]
                    query_fields = query["attributes"]["view"]["fields"]
        else:
            raise Exception(f"Critical error: The saved query '{query_name}' does not exist")

        return (uuid, query_filter, query_fields)


class EntitySearch:
    def __init__(self, api, entity_type, page_size=1000, logger_callback=None):
        if entity_type not in ["devices", "users"]:
            raise Exception(f"{entity} is not a valid entity type")

        self._api = api
        self._api_endpoint = f"/api/{entity_type}"
        self._page_size = page_size
        self._cursor = None
        self._logger_callback = logger_callback
        self._uuid = None
        self._query_filter = None
        self._query_fields = None

    def _log(self, msg):
        if self._logger_callback is not None:
            self._logger_callback(msg)

    def get(self):
        response = { "data": "init" }
        entities = []
        offset = 0
        cursor = None

        while response["data"]:
            data =  {
                "data": {
                    "type": "entity_request_schema",
                    "attributes": {
                        "page": {
                            "offset": offset,
                            "limit": self._page_size
                        },
                        "use_cache_entry": False,
                        "always_cached_query": False,
                        "get_metadata": True,
                        "include_details": True
                    }
                }
            }

            status, response, exception = self._api.post(self._api_endpoint, data)

            if status == 200 and response is not None and exception is None:
                for device in response["data"]:
                    entities.append(device["attributes"])

                offset += self._page_size
            else:
                raise Exception(f"Critical Error! Status Code: {status}\tException: {exception}")

        return entities


    def execute_saved_query(self, name, standoff=0, shorten_field_names=False, dynamic_field_mapping={}, incremental_ingest=False, include_auids=False, truncate_fields=[], batch_callback=None):
        try:
            ax_saved_queries = SavedQueries(self._api, self._api_endpoint)

            if self._uuid is None or self._query_filter is None or self._query_fields is None:
                self._uuid, self._query_filter, self._query_fields = ax_saved_queries.get_attributes_by_name(name)

            if True == incremental_ingest:
                if "specific_data.data.fetch_time" not in self._query_fields:
                    self._query_fields.append("specific_data.data.fetch_time")
            
            if True == include_auids:
                if "internal_axon_id" not in self._query_fields:
                    self._query_fields.append("internal_axon_id")

            response = { "data": "init" }
            entities = []
            entity_count = 0

            while response["data"]:
                data =  {
                    "data": {
                        "type": "entity_request_schema",
                        "attributes": {
                            "use_cache_entry": False,
                            "always_cached_query": False,
                            "filter": self._query_filter,
                            "fields": {
                                "devices": self._query_fields
                            },
                            "page": {
                                "limit": self._page_size
                            },
                            "get_metadata": True,
                            "include_details": True,
                            "use_cursor": True,
                            "cursor_id": self._cursor
                        }
                    }
                }


                status, response, exception = self._api.post(self._api_endpoint, data=data)

                if status == 200 and response is not None and exception is None:
                    if "meta" in response:
                        self._cursor = response["meta"]["cursor"]

                        for device in response["data"]:
                            entity_row = {}

                            for field in data['data']['attributes']['fields']['devices']:
                                field_name = field

                                if True == shorten_field_names:
                                    field_name = field.replace("specific_data.data.", "").replace("adapters_data.", "")
                                    
                                if field_name in dynamic_field_mapping.keys():
                                    field_name = dynamic_field_mapping[field_name]

                                if field in device['attributes']:
                                    entity_row[field_name] = device['attributes'][field]
                                else:
                                    entity_row[field_name] = device['attributes'][f"{field}_details"]

                            entities.append(entity_row)

                    else:
                        response = { "data": None }
                else:
                    raise Exception(f"Critical Error! Status Code: '{status}' Exception: '{exception}'")

                if standoff > 0:
                    time.sleep(standoff)

                if batch_callback is not None:
                    if len(entities) > 0:
                        batch_callback(entities)
                        entity_count += len(entities)
                        entities = []

        except Exception as ex:
            raise Exception(f"Critical Error! Status Code: Exception: {ex}")

class EventWriter:
    def __init__(self, incremental_data_ingest=False, remove_fetch_time_field=False, fetch_time_field_name=None, checkpoint=None, host=None, source=None, index=None, sourcetype=None, helper=None, event_writer=None):
        self._incremental_data_ingest = incremental_data_ingest
        self._remove_fetch_time_field = remove_fetch_time_field
        self._fetch_time_field_name = fetch_time_field_name
        self._checkpoint = checkpoint
        self._host = host
        self._source = source
        self._index = index
        self._sourcetype = sourcetype
        self._helper = helper
        self._event_writer = event_writer
        self._checkpoint = checkpoint
        self._entity_count = 0
        self._entity_ids = []
        self._page = 0
        self._events_written = 0

    def process_batch(self, entities):
        # Update entity count
        self._entity_count += len(entities)

        # Increment page number
        self._page += 1

        # Log page number and size
        self._helper.log_info(f"Input '{self._helper.get_arg('name')}' - STATS - Processing page {self._page}, size {len(entities)}")

        # Process each entity
        for entity in entities:
            if self._helper.get_arg('name') is None:
                self._entity_ids.append(entity["internal_axon_id"])
                
            if True == self._incremental_data_ingest:
                # Create a timestamp from the devices fetch_time field
                entity_fetch_time = datetime.datetime.strptime(entity[self._fetch_time_field_name], "%a, %d %b %Y %H:%M:%S %Z").timestamp()

                # Remove the fetch_time field if it was not part of the saved query's query_field definition
                if True == self._remove_fetch_time_field:
                    entity.pop(self._fetch_time_field_name)

                # Create event
                event = self._helper.new_event(source=self._source, host=self._host, index=self._index, sourcetype=self._sourcetype, data=json.dumps(entity))

                # Add event if no checkpoint is defined yet, or if fetch time is greater than the checkpoint time
                if self._checkpoint is None:
                    self._event_writer.write_event(event)
                    self._events_written += 1
                elif entity_fetch_time > self._checkpoint:
                    self._event_writer.write_event(event)
                    self._events_written += 1
            else:
                # Create event
                event = self._helper.new_event(source=self._source, host=self._host, index=self._index, sourcetype=self._sourcetype, data=json.dumps(entity))

                # Write event
                self._event_writer.write_event(event)
                self._events_written += 1

    def get_entity_count(self):
        return self._entity_count

    def get_events_written(self):
        return self._events_written
        
    def get_internal_axon_id_unique_count(self):
        return len(set(self._entity_ids))

def validate_input(helper, definition):
    # get Axonius configuration
    api_host = definition.parameters.get('api_host', str)
    api_key = definition.parameters.get('api_key', "")
    api_secret = definition.parameters.get('api_secret', "")

    # get selected saved query info
    entity_type = definition.parameters.get('entity_type', str)
    saved_query = definition.parameters.get('saved_query', str)

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
        search = EntitySearch(api, "devices", 1000)
        out = search.get()
    except Exception as ex:
        helper.log_info(ex)

        if "Could not find a suitable TLS CA certificate bundle" in str(ex):
            raise ValueError("Critical Error, check CA Bundle Path exists and the splunk user has proper permissions")
        elif "SSLCertVerificationError" in str(ex) or "Could not find a suitable TLS CA certificate bundle" in str(ex):
            raise ValueError("The Axonius host fails SSL verification, please review your SSL certificate validation settings")
        elif "Status Code: 401" not in str(ex):
            raise ValueError(f"Critical Error: {ex}")

    pass

def collect_events(helper, ew):
    # Retrieve checkpoint
    checkpoint_name = f"checkpoint_{helper.get_arg('name')}_{helper.get_arg('entity_type')}_{helper.get_arg('saved_query')}"

    # get Axonius configuration
    opt_api_host = helper.get_arg('api_host')
    opt_api_key = helper.get_arg('api_key')
    opt_api_secret = helper.get_arg('api_secret')

    # get selected saved query info
    opt_entity_type = helper.get_arg('entity_type')
    opt_saved_query = helper.get_arg('saved_query')

    # get extra options
    opt_page_size = helper.get_arg('page_size')
    opt_shorten_field_names = helper.get_arg('shorten_field_names')
    opt_incremental_data_ingest = helper.get_arg('incremental_data_ingest')
    opt_standoff_ms = helper.get_arg('standoff_ms')
    opt_field_mapping = helper.get_arg('dynamic_field_mapping')
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
    log_info(f"VARS - Entity type: {opt_entity_type}")
    log_info(f"VARS - Saved query: {opt_saved_query}")
    log_info(f"VARS - Page size: {opt_page_size}")
    log_info(f"VARS - Shorten field names: {opt_shorten_field_names}")
    log_info(f"VARS - Incremental data ingest: {opt_incremental_data_ingest}")
    log_info(f"VARS - API standoff (ms): {opt_standoff_ms}")
    log_info(f"VARS - Field Mapping: {opt_field_mapping}")
    log_info(f"VARS - Enforce SSL validation: {opt_enforce_ssl_validation}")
    log_info(f"VARS - CA bundle path: {opt_ssl_certificate_path}")
    
    include_auids = True if helper.get_arg('name') is None else False
    critical_error = False

    # Set verify to True/False
    verify = opt_enforce_ssl_validation

    # Change the value of verify to the path of the ca_bundle if specified
    if opt_ssl_certificate_path:
        if len(opt_ssl_certificate_path) > 0:
            verify = opt_ssl_certificate_path

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
    api = API(opt_api_host, opt_api_key, opt_api_secret, verify, timeout=timeout)

    # Create EntitySearch object with entity type and page size
    search = EntitySearch(api, opt_entity_type, opt_page_size, log_info)

    # Load the input's checkpoint data
    checkpoint = helper.get_check_point(checkpoint_name)

    if checkpoint is not None:
        log_info(f"VARS - Check point: {checkpoint_name}")

    # Default dynamic field names to an empty dict in case opt_field_mapping is empty
    dynamic_field_names = {}

    # Use dynamic mapping if specified
    if opt_field_mapping is not None:
        if len(opt_field_mapping) > 0:
            try:
                dynamic_field_names = json.loads(opt_field_mapping)
            except Exception as ex:
                pass

    # Retry variables
    fetch_complete = False
    exception_thrown = False
    max_retries = len(retry_standoff)
    entity_count = 0
    retries = 0
    version = None
    event_writer = None
    lifecycle_complete = False

    # Set the fetch_time field name, take into account the use of shorten field name
    fetch_time_field_name = "fetch_time" if True == opt_shorten_field_names else "specific_data.data.fetch_time"

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
            
            if not True == lifecycle_complete:
                # Check if a discovery is running and correlation hasn't complete, warn customer if true
                lifecycle = Lifecycle(api)
                
                if True == lifecycle.discovery_is_running() and not True == lifecycle.correlation_is_complete():
                    log_warning(f"Warning: Fetch started while correlation was not complete.")
                    
                lifecycle_complete = True
                
                # Reset retries and exception_thrown
                retries = 0
                exception_thrown = False
                    
            if event_writer is None:
                # Get definition of query_fields, used to check if the fetch_time field should be removed
                api_endpoint = f"/api/{opt_entity_type}"
                ax_saved_queries = SavedQueries(api, api_endpoint)
                uuid, query_filter, query_fields = ax_saved_queries.get_attributes_by_name(opt_saved_query)
    
                # Default remove fetch time to true
                remove_fetch_time_field = True
    
                # Look for fetch_time in the query_fields definition of the specified saved query
                if True == opt_shorten_field_names:
                    if fetch_time_field_name in query_fields:
                        remove_fetch_time_field = False
    
                # Create EventWriter instance to process batches
                event_writer = EventWriter(incremental_data_ingest=opt_incremental_data_ingest, remove_fetch_time_field=remove_fetch_time_field, fetch_time_field_name=fetch_time_field_name, checkpoint=checkpoint, host=host, source=helper.get_arg('name'), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), helper=helper, event_writer=ew)
            
                # Reset retries and exception_thrown
                retries = 0
                exception_thrown = False

            # Grab entity from the saved search
            search.execute_saved_query(opt_saved_query, int(opt_standoff_ms)/1000, opt_shorten_field_names, dynamic_field_names, incremental_ingest=opt_incremental_data_ingest, include_auids=include_auids, batch_callback=event_writer.process_batch)

            # Get Stats
            entity_count = event_writer.get_entity_count()
            events_written = event_writer.get_events_written()
            
            # Fetch is complete, see below for consistency checks if an exception was thrown during fetch
            fetch_complete = True

            # Log stats
            log_info(f"STATS - Total entities returned: {entity_count}")
            log_info(f"STATS - Total events written: {events_written}")
            
            # Sanity check for unique ids, the number needs to match entity_count
            if helper.get_arg('name') is None:
                log_info(f"STATS - Total unique ids: {event_writer.get_internal_axon_id_unique_count()}")
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
            if entity_count > 0:
                helper.save_check_point(checkpoint_name, datetime.datetime.now().timestamp())
