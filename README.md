# Sigma2Splunk
Bulk searching Splunk with Sigma Rules

This tool can be used to convert individual or many Sigma Rules in to Splunk format and search a splunk instance for any matching alerts. 


```
➜ python3 sigma2splunk.py -h
usage: sigma2splunk.py [-h] [-c CONFIG] [-sh SPLUNK_HOST] [-si SPLUNK_INDEX] [-u USER] [-p PASS] [-vp] splunkip sigmafile

Searching Splunk with Sigma Rules

positional arguments:
  splunkip              IP address for the target Splunk instance
  sigmafile             The path to a sigma file

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Set Custom Config file for Sigma Conversion
  -sh SPLUNK_HOST, --splunk_host SPLUNK_HOST
                        Set Specific Host to search against
  -si SPLUNK_INDEX, --splunk_index SPLUNK_INDEX
                        Set specific index to search against
  -u USER, --user USER  Username for the target Splunk instance
  -p PASS, --pass PASS  Password for the target Splunk instance
  -vp, --verbose_print  Print all the results

```
