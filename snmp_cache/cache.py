'''
Class used to query SNMP from devices using v2 or v3 and maintain data in a cache (based on provided timeout)
Cache data format:
{
    "[[mib]]": {
        "[[object]]": {
            "max_age": [[max age in minutes]]
            "query_time": [[timestamp when data queried]]
            "data": [[data for the MIB]]
        }
    }
}

'''
import asyncio
import os
import json
from time import time
from threading import Lock
import puresnmp
from logging_handler import create_logger, INFO, DEBUG
from datetime import datetime, timedelta
from .helpers import *
from .creds import SnmpCredV2, SnmpCredV3


class SnmpCache:
    ''' Class used to query SNMP from devices using v2 or v3 and maintain data in a cache (based on provided timeout) '''
    def __init__(self, host:str, cred:SnmpCredV2|SnmpCredV3, port=161, v6=False, mib_paths=None, cache_enabled=True, max_cache_age=10, log_level=INFO, debug_return_data=False):
        self._lock = Lock()
        self._logger = create_logger(log_level, name=self.__class__.__name__)
        self.debug_return_data = debug_return_data
        self.host = host
        self.port = port
        self.v6 = v6
        self._cache = {}
        self.max_cache_age = max_cache_age
        self.cache_enabled = cache_enabled
        # verify credentials
        if isinstance(cred, SnmpCredV3):
            self.cred = cred
        elif isinstance(cred, SnmpCredV2):
            self.cred = cred
        else:
            raise ValueError('Expecting SnmpCredV2 or SnmpCredV3 object')
        # open MIB files
        self.mibs = {}
        if mib_paths is not None:
            self.load_mibs(mib_paths)

    def __del__(self):
        pass

    def load_mibs(self, mib_dirs:list|str):
        ''' Loads all json mib files in the listed dir(s) '''
        self.mibs = {}
        mib_dir_list = [mib_dirs] if isinstance(mib_dirs, str) else mib_dirs if isinstance(mib_dirs, list) else []
        with self._lock:
            for mib_dir in mib_dir_list:
                if os.path.isdir(mib_dir):
                    for file_name in os.listdir(mib_dir):
                        if file_name.endswith('.json'):
                            self._logger.debug(f'{self.info_str}: Loading MIB {file_name}...')
                            with open(os.path.join(mib_dir, file_name), 'r', encoding='utf-8') as input_file:
                                self.mibs[str(file_name.split('.')[0])] = json.load(input_file)

            # loop through the mibs and resolve and constraints from across MIB files
            for mib_name, mib_content in self.mibs.items():
                for key, item in mib_content.items():
                    if isinstance(item, dict) and item.get('class', None) == 'objecttype' and item.get('syntax', {}).get('class', None) == 'type':
                        # search for objects that have a syntax with a class of type
                        # Then loop through imports to look for a matching type
                        for import_key, import_item in mib_content.get('imports', {}).items():
                            # exclude generic SNMP references
                            if import_key != 'class' and not str(import_key).startswith('SNMP'):
                                if item['syntax'].get('type', None) in import_item and 'type' in self.mibs[import_key].get(item['syntax']['type'], {}):
                                    # if the SNMP field is of a type imported from another MIB copy 'type' from source MIB into 'syntax'
                                    self._logger.debug(f"{self.info_str}: {mib_name}: {key}: matched type '{item['syntax']['type']}' from MIB {import_key}")
                                    item['syntax'] = self.mibs[import_key][item['syntax']['type']]['type']

        self._logger.info(f'{self.info_str}: Loaded {len(self.mibs.keys())} MIBS ({self.mibs.keys()})')

    @property
    def info_str(self):
        ''' Returns the info string for the class (used in logging commands) '''
        return f"{self.host}:{self.port}{' V6' if self.v6 else ''}"

    def get_table(self, mib:str, table:str, allow_cached=True, query_cache_max_age=10):
        ''' Get a specific object from the MIB.  Allow_cached can be disabled to force a live pull.  A max age of the cached data can be specified '''
        # get from cache
        with self._lock:
            if self.cache_enabled and allow_cached:
                if mib in self._cache.keys() and table in self._cache[mib]:
                    # compare the query time against the lower of the cache_max_age or the saved query max age
                    if self._cache[mib][table].get('query_time',0) > time() - min(self.max_cache_age, self._cache[mib][table].get('max_age',self.max_cache_age))*60:
                        self._logger.debug(f"{self.info_str}: {mib}: {table}: Loaded from cache. Cache age: {time() - self._cache[mib][table].get('query_time',0)} seconds, max age {query_cache_max_age*60} seconds")
                        if self._cache[mib][table].get('data', None) is not None:
                            return self._cache[mib][table]['data']

            self._logger.debug(f"{self.info_str}: {mib}: {table}: Polling from device...")
            # get from device
            snmp_server = puresnmp.PyWrapper(puresnmp.Client(self.host, self.cred.creds))

            if mib not in self.mibs.keys():
                raise ValueError(f"MIB {mib} not loaded.  Loaded MIB's: {self.mibs.keys()}")
            if table not in self.mibs[mib].keys():
                raise ValueError(f"Object {table} not in MIB {mib}.")
            table_data = []
            self._logger.debug(f"{self.info_str}: Table {mib}::{table} Querying Table...")
            raw_rows = asyncio.run(snmp_server.table(self.mibs[mib][table]['oid']))
            query_time = time()
            self._logger.debug(f"{self.info_str}: Table {mib}::{table} returned {len(raw_rows)} records")
            for raw_row in raw_rows:
                # start a new row record
                table_row = {'_query_time': query_time}
                # loop through the keys and look for the oid in the MIB table
                for key, value in raw_row.items():
                    mib_resolved = False
                    for mib_key, mib_value in self.mibs[mib].items():
                        if self.mibs[mib][table]['oid'] + '.' + str(key) == mib_value.get('oid'):
                            # normalize content
                            mib_resolved = True
                            table_row[mib_key] = self.__format_snmp_field(value, mib_value['syntax']) if 'syntax' in mib_value else value # type: ignore
                            break
                    if not mib_resolved:
                        if str(key) == '0':
                            self._mib_table_index(value, mib, table, table_row)
                        else:
                            self._logger.warning(f"{self.info_str}: Table {mib}::{table} Returned OID {self.mibs[mib][table]['oid'] + '.' + str(key)} which could not be found in MIB {mib}")
                            table_row[key] = value
                table_data.append(table_row)
            if len(table_data) != len(raw_rows):
                raise ValueError(f"Parsed rows does not match returned rows! {len(table_data)} / {len(raw_rows)}")

            # update the cache
            if self.cache_enabled:
                if mib not in self._cache:
                    self._cache[mib] = {table:{}}
                self._cache[mib][table] = {
                    'max_age': query_cache_max_age,
                    'query_time': query_time,
                    'data': table_data
                }

        return table_data

    def walk(self):
        pass

    def get(self):
        pass

    def get_cache_table_age(self, mib, table) -> timedelta|None:
        ''' Get the cache age of an object and return it '''
        refresh_time = self.get_cache_table_refresh_time(mib, table)
        return (datetime.now() - refresh_time) if refresh_time is not None else None
    
    def get_cache_table_refresh_time(self, mib, table) -> datetime|None:
        ''' Get the cache age of an object and return it '''
        with self._lock:
            if mib in self._cache and table in self._cache[mib] and 'query_time' in self._cache[mib][table]:
                return datetime.fromtimestamp(self._cache[mib][table]['query_time'])
        return None

    def _mib_table_index(self, value, mib:str, mib_table:str, return_value:dict):
        ''' Parse the table index and update the return_value dict with the relevant fields '''
        if self.mibs[mib][mib_table].get('nodetype') != 'row' or 'indices' not in self.mibs[mib][mib_table]:
            return
        # loop through the index values - there may be multiple combined (and cross MIB's)!
        index_pos = 0
        for table_index in self.mibs[mib][mib_table]['indices']:
            # get the index variable
            if table_index.get('module', None) in self.mibs and table_index.get('object') in self.mibs[table_index['module']]:
                if self.mibs[table_index['module']][table_index['object']]['syntax']['class'] == 'type' \
                    and self.mibs[table_index['module']][table_index['object']]['syntax']['type'].lower() == 'macaddress':
                    # If a MAC, grab 6 octets and convert
                    try:
                        return_value[table_index['object']] = mac_decimal_to_hex('.'.join(value.split('.')[index_pos:index_pos+6]))
                        index_pos += 6
                    except Exception as e:
                        self._logger.error(f"{self.info_str}: Error parsing {mib_table} index. Value: {value}, Index: {[table_index['object']]}, Index specification: {self.mibs[mib][mib_table]['indices']},, Error: {e}")
                        return
                elif self.mibs[table_index['module']][table_index['object']]['syntax']['class'] == 'type' \
                    and self.mibs[table_index['module']][table_index['object']]['syntax']['type'].lower() == 'inetaddress':
                    # If an IP, grab 4 octets
                    try:
                        return_value[table_index['object']] = '.'.join(value.split('.')[index_pos:index_pos+4])
                        index_pos += 4
                    except Exception as e:
                        self._logger.error(f"{self.info_str}: Error parsing {mib_table} index. Value: {value}, Index: {[table_index['object']]}, Index specification: {self.mibs[mib][mib_table]['indices']},, Error: {e}")
                        return
                else:
                    # grab one octet and set it
                    try:
                        return_value[table_index['object']] = int(''.join(value.split('.')[index_pos:index_pos+1]))
                        index_pos += 1
                    except Exception as e:
                        self._logger.error(f"{self.info_str}: Error parsing {mib_table} index. Value: {value}, Index: {[table_index['object']]}, Index specification: {self.mibs[mib]['mib_table']['indices']},, Error: {e}")
                        return

    def __format_snmp_field(self, value, mib_syntax):
        ''' Take a value returned by SNMP and format based on the information in the MIB '''
        if mib_syntax.get('class', None) is None or mib_syntax.get('type', None) is None:
            # no syntax info, return as is
            return value
        if mib_syntax['class'].lower() != 'type':
            # wrong class, return as is
            return value

        # run fixups on the type
        return_value = value
        if mib_syntax['type'].lower() == 'macaddress':
            return_value = mac_binary_to_hex(value)
        elif mib_syntax['type'].lower() == 'inetaddress' or mib_syntax['type'].lower() == 'ipaddress':
            return_value = ip_binary_to_str(value)
        elif mib_syntax['type'].lower() == 'truthvalue':
            return_value = True if value == 1 else False
        elif mib_syntax['type'].lower() == 'bits':
            # return bits field as after checking for bits info
            for x,y in mib_syntax.get('bits', {}).items():
                if y == int.from_bytes(value, 'big'):
                    return {'value': value, 'enumeration': x}
            # no need to continue on to check constraints with bits
            return value
        elif isinstance(value, int) or isinstance(value, timedelta):
            pass
        else:
            # if we haven't identified the type, try converting it to a string
            try:
                return_value = value.decode('utf-8')
            except Exception as e:
                self._logger.warning(f"{self.info_str}: Error decoding {value}: {e}")

        # check against constraints
        if isinstance(mib_syntax.get('constraints', None), dict):
            if 'enumeration' in mib_syntax['constraints']:
                # loop through and add the translated value
                for key, item in mib_syntax['constraints']['enumeration'].items():
                    if item == return_value:
                        return {'value': return_value, 'enumeration': key}

        return return_value


