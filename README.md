# Check Point Security Gateway Metrics to New Relic Insights Integration
An automation script for Check Point Security Gateways to gather metrics via SNMP and send an aggregated payload to New Relic Insights.

## **Process Summary** 
The following explains what this tool does in sequence at a high level:
1. Load a metrics list JSON file for processing.
2. Query target SNMP Agent for OIDs in metrics list. 
A. If metrics list item specifies an index OID, make multiple queries to child OIDs based on current index.
B. If metrics list item specifies an index OID, the `labels` array in metrics list item will processed based on the current index. **In the absence of an index OID, all labels will be ignored.**
4. Build a single New Relic payload with all metrics (and labels).
5. Send the payload to New Relic Insights via API.
6. Script exits after single execution.

## Requirements
* Admin/expert-mode access to Check Point appliance (Gaia)
* Staging environment with Python v2.7.x 

## Setup
#### Check Point Appliance Setup
1. Login to Check Point appliance CLI as admin and set the shell to bash:
`set user admin shell /bin/bash`
>  Note: Required for SCP to function properly.
2. Setup the appliance expert password and enter expert mode:
  ```bash
  set expert-password
  save config
  expert
```
3. You will return to the Check Point appliance in later steps.

#### Prepare python virtual environment for export
1. Create a RHEL/CentOS instance to stage a virutal environment
2. Install python2, pip and virtualenv.
* `yum install python2 python2-pip python2-virtualenv -y`
3. Setup python virtual environment and dependencies
```bash
python2path=/usr/bin/python2.7 # Set to real python2 path if different
virtualenv -p $python2path cpgaia-pythonenv
source cpgaia-pythonenv/bin/activate
pip install requests pysnmp
deactivate
tar -czvf cpgaia-pythonenv.tar.gz ./cpgaia-pythonenv
# Deployment to Appliance: SCP the file to the appliance (SFTP not supported)
scp -i ~/mykey.pem ./cpgaia-pythonenv.tar.gz admin@<appliance-ip>:/home/admin # Verify key path, tar path, and destination path
```
### Import/deploy on Check Point Appliance 
1. Login to Check Point appliance CLI as admin in expert-mode.
1. Untar python environment: `tar -xvf cpgaia-pythonenv.tar.gz`
2. All files decompress to a `cpgaia-pythonenv` subdirectory. You will be creating symbolic links to this directory in the following step. Ensure that this directory location is satisfactory, otherwise move it now.
3. Python PIP is not installed on Check Point appliances. Create symbolic links to the required Python libraries loaded in the previous step.
```bash
ln -s ./cpgaia-pythonenv/lib/python2.7/site-packages/requests $FWDIR/Python/lib/python2.7/site-packages/requests
ln -s ./cpgaia-pythonenv/lib/python2.7/site-packages/pysnmp $FWDIR/Python/lib/python2.7/site-packages/pysnmp
ln -s ./cpgaia-pythonenv/lib/python2.7/site-packages/pyasn1 $FWDIR/Python/lib/python2.7/site-packages/pyasn1
ln -s ./cpgaia-pythonenv/lib/python2.7/site-packages/urllib3 $FWDIR/Python/lib/python2.7/site-packages/urllib3
ln -s ./cpgaia-pythonenv/lib/python2.7/site-packages/chardet $FWDIR/Python/lib/python2.7/site-packages/chardet
ln -s ./cpgaia-pythonenv/lib/python2.7/site-packages/certifi $FWDIR/Python/lib/python2.7/site-packages/certifi
ln -s ./cpgaia-pythonenv/lib/python2.7/site-packages/idna $FWDIR/Python/lib/python2.7/site-packages/idna
```
#### Upload the GitHub project files to Check Point appliance
1. Using SCP, transfer `cpsnmp-to-nr.py` and `metrics_list.json` to the appliance.

#### Customizing the Metrics List JSON file
The `metrics_list.json` file as been preloaded with common SNMP metrics. If you would to customize this list please review the following to understand the data model:
##### Example metrics_list.json:
```json
[ 
   {
      "metric_name":"memoryMetric",
      "metric_oid":"1.6.7.8",
   },
   {
      "metric_name":"firewallMetric",
      "metric_oid":"1.9.8.%.0",
      "index_oid":"1.2.3.0", 
      "labels":[
         {
            "label_name":"interface_id",
            "label_oid":"1.3.4.%.0"
         }
      ]
   }, ...
]
```
##### JSON Properties descriptions:
| Property  | Required                                  | Notes             |
|---------------|-------------------------------------------|---------------|
| `"metric_name":"value"` | Yes                                       | Name of metric to be sent to New Replic |
| `"metric_oid":"value"`  | Yes                                       | Simple OID to query SNMP to get metric. If `index_oid` is specified you must use `%` as a wildcard in the OID which is replaced with the current index during a "for" loop.     |
| `"index_oid":"value"`   | No                                        | This OID returns an integer for length of "for" loops|
| `labels: [{label_name:"value", label_oid="value.%"}, ...]`    | No          | Labels are ignored if an index_oid is not specified. You must use `%` as a wildcard in the OID which is replaced with the current index during a "for" loop.  |	


## Operation
To run the script, review the arguments of the script and the syntax.

### Arguments 
Below are the global and mode-specific arguments.

| Argument       | Description                                               | Default value |
|----------------|-----------------------------------------------------------|---------------|
| `--community`  | Name of source SNMP v1/v2 community Id                    | |
| `--account`    | New Relic account number                                  | |
| `--key`        | New Relic Insights insert key                             | |
| `--ip`         | IP Address of SNMP Agent to poll                          | `127.0.0.1`   |	
| `--verbose`    | Verbose output                                            | `False`       |	

### How to run:
```bash
# Syntax
python cpsnmp_to_nr.py --community public --account 1234567 --key 12345678Z-2jAnRQlUHgjjKE12345678 --verbose
```