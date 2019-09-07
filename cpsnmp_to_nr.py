#!/usr/bin/python

# *******************************************************************************
# Name: cpsnmp_to_nr.py
# Description: An automation script for Check Point Security Gateways to gather 
#  metrics via SNMP and send an aggregated payload to New Relic Insights
#
# Copywrite 2019, Check Point Software
# www.checkpoint.com
# *******************************************************************************

import json
import time
import os
import sys
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError
from pysnmp import hlapi
import argparse
from argparse import RawTextHelpFormatter
from datetime import datetime

#SNMP Auth Examples
#SNMP v2
#hlapi.CommunityData(snmp_community))

#SNMP v3
# hlapi.UsmUserData('testuser', authKey='authenticationkey', privKey='encryptionkey', authProtocol=hlapi.usmHMACSHAAuthProtocol, privProtocol=hlapi.usmAesCfb128Protocol)

def get_snmp(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler = hlapi.getCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port)),
        context,
        *construct_object_types(oids)
    )
    return fetch(handler, 1)[0]
 
def construct_object_types(list_of_oids):
    object_types = []
    for oid in list_of_oids:
        object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
    return object_types
 
 
def fetch(handler, count):
    result = []
    for i in range(count):
        try:
            error_indication, error_status, error_index, var_binds = next(handler)
            if not error_indication and not error_status:
                items = {}
                for var_bind in var_binds:
                    items[str(var_bind[0])] = cast(var_bind[1])
                result.append(items)
            else:
                raise RuntimeError('Got SNMP error: {0}'.format(error_indication))
        except StopIteration:
            break
    return result

    
def cast(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        try:
            return float(value)
        except (ValueError, TypeError):
            try:
                return str(value)
            except (ValueError, TypeError):
                pass
    return value

def get_bulk(target, oids, credentials, count, start_from=0, port=161,
             engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler = hlapi.bulkCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port)),
        context,
        start_from, count,
        *construct_object_types(oids)
    )
    return fetch(handler, count)

def send_to_nr(events):
    nr_url = 'https://insights-collector.newrelic.com/v1/accounts/%s/events' % OPTIONS.nr_account_num
 
    if OPTIONS.verbose:
        print('\n' + json.dumps(events, indent=2))
  
    headers = {'Content-Type': 'application/json', 'X-Insert-Key': OPTIONS.nr_key, 'Content-Encoding': 'gzip'} #this is the NewRelic insert key, which is specific to the end user and must be configurable.    
    resp = ''
    try:
        resp = requests.post(nr_url, json=events, headers=headers) 
        resp.raise_for_status()
        #print('')
    except HTTPError as http_err:
        print('HTTP error occurred: %s' % http_err) 
    except Exception as err:
        print('Other error occurred: %s' % err) 
    else:
        if OPTIONS.verbose:
            print('Success!')

def main(argv=None):

    global OPTIONS

    if argv is None:
        argv = sys.argv[1:]

    # define argparse helper meta 
    example_text = example_text = 'Example: \n %s --community public --account 1234567 --key 12345678Z-2jAnRQlUHgjjKE12345678 --verbose' % sys.argv[0]

    parser = argparse.ArgumentParser(
     epilog=example_text,
     formatter_class=RawTextHelpFormatter)
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    # Add arguments to argparse
    required.add_argument('--community', dest='snmp_community', help='Name of SNMP v1/v2 community Id (e.g. "public")', required=True)  
    required.add_argument('--account', dest='nr_account_num', help='New Relic account number (e.g. "1234567")', required=True)
    required.add_argument('--key', dest='nr_key', help='New Relic Insights Insert Key', required=True) 
    optional.add_argument('--ip', dest='snmp_agent_ip', default='127.0.0.1', help='IP Address of SNMP Agent to poll. Default: 127.0.0.1')
    optional.add_argument('--verbose', dest='verbose', default=False, help='Verbose output', action='store_true')

    if len(sys.argv) == 1:
        parser.print_help()
        os._exit(1) 

    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        parser.print_help()
        os._exit(1)
    
    OPTIONS = parser.parse_args(argv)
    if OPTIONS.nr_account_num and OPTIONS.nr_key and OPTIONS.snmp_community and OPTIONS.snmp_agent_ip:
        print('\n:: Check Point Security Gateway Metrics to New Relic :: \nExecution time: %s \n' % str(datetime.now()))
    else:
        parser.print_help()
        os._exit(1)
    
    # Pre-processing of OIDs
    #cp_proc_usage_oids = get_cp_proc_usage_oids() # Get CPU Count to generate Proc Usage OIDs
    
    # read metrics_list.json file
    #with open('metrics_list.json', 'r') as jsonfile:
    #    filedata = jsonfile.read()

    #load metrics_list from file data
    #metrics_list = json.loads(filedata)
    metrics_list = [
      {'metric_name': 'cpvIpsecEspEncPkts', 'metric_oid': '1.3.6.1.4.1.2620.1.2.5.4.5'},
      {'metric_name': 'cpvIpsecEspDecPkts', 'metric_oid': '1.3.6.1.4.1.2620.1.2.5.4.6'},
      {'metric_name': 'memTotalReal64', 'metric_oid': '1.3.6.1.4.1.2620.1.6.7.4.3.0'},
      {'metric_name': 'memActiveReal64', 'metric_oid': '1.3.6.1.4.1.2620.1.6.7.4.4.0'},
      {'metric_name': 'memFreeReal64', 'metric_oid': '1.3.6.1.4.1.2620.1.6.7.4.5.0'}, 
      {'metric_name': 'multiProcUsage', 'metric_oid': '1.3.6.1.4.1.2620.1.6.7.5.1.5.%.0', 'index_oid': '1.3.6.1.4.1.2620.1.6.7.2.7.0', 'labels': [{'label_name': 'multiProcIndex', 'label_oid': '1.3.6.1.4.1.2620.1.6.7.5.1.1.%.0'}]},
      {'metric_name': 'ifInOctets', 'metric_oid': '1.3.6.1.2.1.2.2.1.10.%', 'index_oid': '1.3.6.1.2.1.2.1.0', 'labels': [{'label_name': 'ifDescr', 'label_oid': '1.3.6.1.2.1.2.2.1.2.%'}]}
     ]
    
    nr_payload = []
    # Query SNMP and build events payload

    for item in metrics_list:
        elements = ''
        labels = {}
        if 'index_oid' in item:
            elements = get_snmp(OPTIONS.snmp_agent_ip, [item['index_oid']], hlapi.CommunityData(OPTIONS.snmp_community))
            print('Element count: %s' % elements[item['index_oid']])
        
        if elements:
            for i in range(1, (elements[elements.keys()[0]] + 1)): #elements[item['index_oid']]
                current_metric_oid = item['metric_oid'].replace('%', str(i))
                metric_data = get_snmp(OPTIONS.snmp_agent_ip, [current_metric_oid], hlapi.CommunityData(OPTIONS.snmp_community))
                print(metric_data)
                if metric_data[metric_data.keys()[0]]:
                    if 'labels' in item.keys():
                        for label in item['labels']:
                            label_oid = label['label_oid'].replace('%', str(i))
                            label_data = get_snmp(OPTIONS.snmp_agent_ip, [label_oid], hlapi.CommunityData(OPTIONS.snmp_community))
                            labels = {label['label_name']: label_data[label_data.keys()[0]]} 
                            #print(labels)
                    nr_payload.append({'eventType': 'CheckPointPerformance', 'metricType': 'Performance', item['metric_name']: metric_data[metric_data.keys()[0]], 'labels': labels})
        else:
            current_metric_oid = item['metric_oid']
            metric_data = get_snmp(OPTIONS.snmp_agent_ip, [current_metric_oid], hlapi.CommunityData(OPTIONS.snmp_community))
            print(metric_data)
            if metric_data[metric_data.keys()[0]]:
                nr_payload.append({'eventType': 'CheckPointPerformance', 'metricType': 'Performance', item['metric_name']: metric_data[metric_data.keys()[0]], 'labels': labels})
            else:
                print('\tOID data is null: %s' % (current_metric_oid))
    
    # Send all events to New Relic
    if nr_payload:
        send_to_nr(nr_payload)
    else:
        print('Error: Payload is null')
        os._exit(1)

if __name__ == '__main__': main()