#!/usr/bin/python

# *******************************************************************************
# Name: snmp_to_nr.py
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

def get_cp_proc_usage_oids():
    proc_num_oid = '1.3.6.1.4.1.2620.1.6.7.2.7.0' # OID: iso.org.dod.internet.private.enterprises.checkpoint.products.svn.svnPerf.svnProc.procNum.0
    proc_num = get_snmp(OPTIONS.snmp_agent_ip, [proc_num_oid], hlapi.CommunityData(OPTIONS.snmp_community)) 
    print('\nNumber of CPUs on SNMP Agent: ' + str(proc_num[proc_num_oid]))

    proc_usage_oids = []
    for i in range(1, (proc_num[proc_num_oid] + 1)):
        proc_usage_oids.append('1.3.6.1.4.1.2620.1.6.7.5.1.5.' + str(i) + '.0') # OID: .iso.org.dod.internet.private.enterprises.checkpoint.products.svn.svnPerf.multiProcTable.multiProcEntry.multiProcUsage.1.0

    return proc_usage_oids

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

def get_bulk_auto(target, oids, credentials, count_oid, start_from=0, port=161,
                  engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    count = get_snmp(target, [count_oid], credentials, port, engine, context)[count_oid]
    return get_bulk(target, oids, credentials, count, start_from, port, engine, context)

def send_to_nr(events):
    nr_url = 'https://insights-collector.newrelic.com/v1/accounts/%s/events' % OPTIONS.nr_account_num
 
    if OPTIONS.verbose:
        print(json.dumps(events, indent=2))
  
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
    example_text = 'Example: \n %s --community public --nrkey ABC123 --snmpip 10.3.2.1' % sys.argv[0]

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
    optional.add_argument("--interval", dest="ins_interval", default=300, help="Time to wait between New Relic inserts (in seconds). Default: 300")    
    optional.add_argument('--ip', dest='snmp_agent_ip', default='127.0.0.1', help='IP Address of SNMP Agent to poll. Default: 127.0.0.1')
    optional.add_argument('--verbose', dest='verbose', default=False, help='Verbose output', action='store_true')

    if len(sys.argv) == 1:
        parser.print_help()
        os._exit(1) 

    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        parser.print_help()
        os._exit(1)
    
    OPTIONS = parser.parse_args(argv)
    if OPTIONS.snmp_community and OPTIONS.nr_key and OPTIONS.snmp_agent_ip and OPTIONS.ins_interval:
        print('\n:: Check Point Security Gateway Metrics to New Relic :: \nExecution time: %s \n' % str(datetime.now()))
    else:
        parser.print_help()
        os._exit(1)
    
    # Pre-processing of OIDs
    cp_proc_usage_oids = get_cp_proc_usage_oids() # Get CPU Count to generate Proc Usage OIDs
    
    # Simple OID list
    metrics_list = [
      {'metric_name': 'Throughput', 'datapoint_name': 'pps', 'oid': '1.3.6.1.2.1.1.5.0'} # JUST AN EXAMPLE! -- iso.org.dod.internet.mgmt.mib-2.system.sysName.0
     ]
    
    try:
        print('\nPress Ctrl-C to break\n')
        while True:
            nr_payload = []
            # Query SNMP and build events payload
            ## Get CPU Usage metrics
            for idx, proc_usage_oid in enumerate(cp_proc_usage_oids): 
                data = get_snmp(OPTIONS.snmp_agent_ip, [proc_usage_oid], hlapi.CommunityData(OPTIONS.snmp_community))
                nr_payload.append({'eventType': 'CheckPointPerformance', 'metricType': 'Performance', 'metricName': 'CPU Usage', 'proc%s_usage' % (idx + 1): data[data.keys()[0]]})
            ## OID List
            for item in metrics_list:
                data = get_snmp(OPTIONS.snmp_agent_ip, [item['oid']], hlapi.CommunityData(OPTIONS.snmp_community))
                nr_payload.append({'eventType': 'CheckPointPerformance', 'metricType': 'Performance', 'metricName': item['metric_name'], item['datapoint_name']: data[data.keys()[0]]})
            
            # Send all events to New Relic
            send_to_nr(nr_payload)
            time.sleep(int(OPTIONS.ins_interval))

    except KeyboardInterrupt:
        print('Ctrl-C was pressed. Exiting...')
        os._exit(1)
    
    ## FUTURE USE ##
    #its = get_bulk_auto(OPTIONS.snmp_agent_ip, [
    #    '1.3.6.1.2.1.2.2.1.2',
    #    '1.3.6.1.2.1.31.1.1.1.18',
    #    '1.3.6.1.2.1.1.1.0'
    #    ], hlapi.CommunityData(snmp_community), '1.3.6.1.2.1.2.1.0')
    # We print the results in format OID=value

    #for it in its:
    #    for k, v in it.items():
    #        print("{0}={1}".format(k, v))
    #    print('') # We leave a blank line between the output of each interface

if __name__ == '__main__': main()