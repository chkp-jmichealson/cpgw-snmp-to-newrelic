# Check Point Security Gateway Metrics to New Relic Insights Integration
An automation script for Check Point Security Gateways to gather metrics via SNMP and send an aggregated payload to New Relic Insights.

## **Process Summary** 
The following explains what this tool does in sequence at a high level:
1. Build a list of OIDs and respective metadata. Process special cases first until OID list is completed.
2. Query SNMP Agent for OID datapoints.
3. Build a single New Relic payload with all metrics and datapoints.
4. Send the payload to New Relic Insights via API.
5. Clear the payload and repeat the SNMP Agent query in X seconds.

## Requirements
* Python v2.7.x 

## Operation
To run the script, review the arguments of the script and the syntax.

### Arguments 
Below are the global and mode-specific arguments.

| Argument       | Description                                               | Default value |
|----------------|-----------------------------------------------------------|---------------|
| `--community`  | Name of source SNMP v1/v2 community Id                    | |
| `--account`    | New Relic account number                                  | `12345678`    |
| `--key`        | New Relic Insights insert key                             | |
| `--ip`         | IP Address of SNMP Agent to poll                          | `127.0.0.1`   |	
| `--interval`   | Time to wait between New Relic inserts (in seconds)       | `300`         |	
| `--verbose`    | Verbose output                                            | `False`       |	

### How to run:
```bash
# Syntax
python snmp_to_nr.py --community public --account 1234567 --key 12345678Z-2jAnRQlUHgjjKE12345678 --ip 127.0.0.1 --interval 300 --verbose
```