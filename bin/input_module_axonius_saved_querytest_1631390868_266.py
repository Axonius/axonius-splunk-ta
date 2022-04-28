
# encoding = utf-8

import datetime
import json
import os
import re
import requests
import sys
import time


class API:
    def __init__(self, url, api_key, api_secret, verify=False):
        self._url = url
        self._api_key = api_key
        self._api_secret = api_secret
        self._verify = verify

    def _rest_base(self, method, api_endpoint, data=None, params=None, headers={}):
        requests_method = getattr(requests, method)
        response = None
        exception = None
        req = None

        try:
            headers['api-key'] = self._api_key
            headers['api-secret'] = self._api_secret
            
            if True == self._verify:
                req = requests_method(f"{self._url}{api_endpoint}", params=params, data=json.dumps(data), headers=headers)
            else:
                req = requests_method(f"{self._url}{api_endpoint}", params=params, data=json.dumps(data), headers=headers, verify=self._verify)

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

            if exception is not None or status == 200:
                for device in response["data"]:
                    entities.append(device["attributes"])

                offset += self._page_size
            else:
                raise Exception(f"Critical Error! Status Code: {status}\tException: {exception}")

        return entities
        

    def execute_saved_query(self, name, standoff=0, shorten_field_names=False, dynamic_field_mapping={}, incremental_ingest=False, batch_callback=None):
        ax_saved_queries = SavedQueries(self._api, self._api_endpoint)
        uuid, query_filter, query_fields = ax_saved_queries.get_attributes_by_name(name)
        
        if True == incremental_ingest:
            if "specific_data.data.fetch_time" not in query_fields:
                    query_fields.append("specific_data.data.fetch_time")

        response = { "data": "init" }
        entities = []
        entity_count = 0
        
        # Retry variables
        retry_sleep = [5, 10, 15, 30, 60]
        retries = 0

        while response["data"]:
            if retries > 0:
                self._log(f"COLL - Retry: {retries}")
            data =  {
                "data": {
                    "type": "entity_request_schema",
                    "attributes": {
                        "use_cache_entry": False,
                        "always_cached_query": False,
                        "filter": query_filter,
                        "fields": {
                            "devices": query_fields
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

            if exception is not None or status == 200:
                if "meta" in response:
                    self._cursor = response["meta"]["cursor"]
                    self._log(f"COLL - Cursor: {self._cursor}")

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
                while retries < len(retry_sleep):
                    self._log(f"COLL - Sleeping for {retry_sleep[retries]} seconds, then retrying")
                    retries += 1
                    time.sleep(retry_sleep[retries])
                    
                raise Exception(f"Critical Error! Status Code: {status}\tException: {exception}")
            
            if standoff > 0:
                time.sleep(standoff)
            
            if batch_callback is not None:
                if len(entities) > 0:
                    batch_callback(entities)
                    entity_count += len(entities)
                    entities = []
                    
class EventWriter:
    def __init__(self, incremental_data_ingest=False, remove_fetch_time_field=False, checkpoint=None, host=None, source=None, index=None, sourcetype=None, helper=None, event_writer=None):
        self._incremental_data_ingest = incremental_data_ingest
        self._remove_fetch_time_field = remove_fetch_time_field
        self._checkpoint = checkpoint
        self._host = host
        self._source = source
        self._index = index
        self._sourcetype = sourcetype
        self._helper = helper
        self._event_writer = event_writer
        self._entity_count = 0
        self._page = 0
        self._events_written = 0
        
    def process_batch(self, entities):
        # Update entity count
        self._entity_count += len(entities)
        
        # Increment page number
        self._page += 1
        
        # Log page number and size
        self._helper.log_info(f"COLL - Processing page {self._page}, size {len(entities)}")
        
        # Process each entity
        for entity in entities:
            if True == self._incremental_data_ingest:
                # Create a timestamp from the devices fetch_time field
                entity_fetch_time = datetime.datetime.strptime(entity[fetch_time_field_name], "%a, %d %b %Y %H:%M:%S %Z").timestamp()
                
                # Remove the fetch_time field if it was not part of the saved query's query_field definition
                if True == self._remove_fetch_time_field:
                    entity.pop(fetch_time_field_name)
                
                # Create event
                event = self._helper.new_event(source=self._source, host=self._host, index=self._index, sourcetype=self._sourcetype, data=json.dumps(entity))
                
                # Add event if no checkpoint is defined yet, or if fetch time is greater than the checkpoint time
                if checkpoint is None:
                    self._event_writer.write_event(event)
                    self._events_written += 1
                elif entity_fetch_time > checkpoint:
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
        else:
            raise ValueError(f"Critical Error: {ex}")
    
    pass

def collect_events(helper, ew):
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
    
    helper.log_info(f"VARS - Axonius Host: {opt_page_size}")
    helper.log_info(f"VARS - Entity type: {opt_entity_type}")
    helper.log_info(f"VARS - Saved query: {opt_saved_query}")
    helper.log_info(f"VARS - Page size: {opt_page_size}")
    helper.log_info(f"VARS - Shorten field names: {opt_shorten_field_names}")
    helper.log_info(f"VARS - Incremental data ingest: {opt_incremental_data_ingest}")
    helper.log_info(f"VARS - API standoff (ms): {opt_standoff_ms}")
    helper.log_info(f"VARS - Field Mapping: {opt_field_mapping}")
    helper.log_info(f"VARS - Enforce SSL validation: {opt_enforce_ssl_validation}")
    helper.log_info(f"VARS - CA bundle path: {opt_ssl_certificate_path}")
    
    def log_message(msg):
        helper.log_info(msg)
    
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
    
    # Create an API object for REST calls
    api = API(opt_api_host, opt_api_key, opt_api_secret, verify)

    # Create EntitySearch object with entity type and page size
    search = EntitySearch(api, opt_entity_type, opt_page_size, log_message)

    # Load the input's checkpoint data
    checkpoint = helper.get_check_point(checkpoint_name)

    if checkpoint is not None:
        # Log the checkpoint name
        helper.log_info(f"COLL - Check point: {checkpoint_name}")

    try:
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
        max_retries = 5
        retry_sleep_time = [0, 5, 10, 15, 30, 60]
        entity_count = 0
        retries = 0
        
        # Set the fetch_time field name, take into account the use of shorten field name
        fetch_time_field_name = "fetch_time" if True == opt_shorten_field_names else "specific_data.data.fetch_time"
        
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
        
        while retries < max_retries + 1 and entity_count == 0:
            # Create EventWriter instance to process batches
            event_writer = EventWriter(incremental_data_ingest=opt_incremental_data_ingest, remove_fetch_time_field=remove_fetch_time_field, checkpoint=checkpoint, host=host, source=opt_saved_query, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), helper=helper, event_writer=ew) 
            
            try:
                # Grab entity from the saved search
                search.execute_saved_query(opt_saved_query, int(opt_standoff_ms)/1000, opt_shorten_field_names, dynamic_field_names, incremental_ingest=opt_incremental_data_ingest, batch_callback=event_writer.process_batch)
                
                # Get Stats
                entity_count = event_writer.get_entity_count()
                events_written = event_writer.get_events_written()
                    
                # Log stats
                helper.log_info(f"COLL - Total entities returned: {entity_count}")
                helper.log_info(f"COLL - Total events written: {events_written}")
            except Exception as ex:
                helper.log_error(f"ERR - Error '{ex}', attempting to recover")
            
            # Log retry
            if retries > 0 and entity_count == 0:
                helper.log_info(f"COLL - Retry: {retries}")
            
            # Increment retry counter
            retries += 1
            
            if entity_count > 0:
                helper.save_check_point(checkpoint_name, datetime.datetime.now().timestamp())
            else:
                if retries < max_retries + 1:
                    # Log length of retry sleep time
                    helper.log_info(f"COLL - Sleeping for {retry_sleep_time[retries]} seconds, then retrying")
                    
                    # Sleep the process and then retry
                    time.sleep(retry_sleep_time[retries])
                else:
                    # Log no devices after max retries
                    helper.log_info(f"COLL - No entities returned afetr max retries ({max_retries}), check the saved query '{opt_saved_query}' in the Axonius web console to validate entity count.")

    except Exception as e:
        helper.log_critical(f"Critical Error: {e}")
