
# Sigma2Splunk
# Copyright (C) 2021 Kevin Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/Sigma2Splunk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import json
import pprint
import time
from pathlib import Path
from xml.dom import minidom

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import sigma.backends.discovery as backends
from sigma.config.collection import SigmaConfigurationManager
from sigma.configuration import SigmaConfigurationChain
from sigma.parser.collection import SigmaCollectionParser

# Disable TLS warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def convert_sigma(sigma_rule_file, sigma_config):
    scm = SigmaConfigurationManager()
    sigma_target = 'splunk'

    if sigma_config:
        target_config = sigma_config
    else:
        target_config = 'splunk-windows'
    rules = []

    with open(sigma_rule_file, 'r') as infile:
        rule_content = infile.read()

    rulefilter = None
    backend_class = backends.getBackend(sigma_target)

    sigmaconfigs = SigmaConfigurationChain()
    sigmaconfig = scm.get(target_config)
    sigmaconfigs.append(sigmaconfig)

    backend = backend_class(sigmaconfigs)

    parser = SigmaCollectionParser(rule_content, sigmaconfigs, rulefilter)
    results = parser.generate(backend)
    for res in results:
        rules.append({
            'sigma_target': sigma_target,
            'rule_string': res})

    return rules


class SplunkSearch():

    def __init__(self, splunk_ip):
        self.base_url = f'https://{splunk_ip}:8089'
        self.username = 'admin'
        self.password = ''
        self.verify_tls = False

        self.session_key = None
        self.splunk_auth()

    def splunk_auth(self):
        auth_url = f'{self.base_url}/servicesNS/admin/search/auth/login'
        auth_payload = {'username': self.username, 'password': self.password}

        auth_request = requests.get(
            auth_url,
            data=auth_payload,
            verify=self.verify_tls,
            )

        status_code = auth_request.status_code

        if status_code == 200:
            self.session_key = minidom.parseString(
                auth_request.text).getElementsByTagName(
                    'sessionKey')[0].firstChild.nodeValue
        else:
            print(f'[!] Splunk failed to auth: {status_code}')  # noqa: T001

    def splunk_search(self, search_query, splunk_index, search_host):
        sid = None
        if not self.session_key:
            print('Session not authenticated')  # noqa: T001
            return

        extra_params = ''

        if splunk_index:
            extra_params += f'index={splunk_index} '

        if search_host:
            extra_params += f'host="{search_host}" '

        search_url = f'{self.base_url}/services/search/jobs/'
        auth_headers = {'Authorization': f'Splunk {self.session_key}'}
        search_query = f'search=search {extra_params}{search_query}'.encode('utf-8')

        search_request = requests.post(
            search_url,
            headers=auth_headers,
            data=search_query,
            verify=self.verify_tls,
        )

        status_code = search_request.status_code

        if status_code == 201:
            sid = minidom.parseString(
                search_request.text).getElementsByTagName(
                    'sid')[0].firstChild.nodeValue
        else:
            sid = None
            print(f'Splunk returned status code: {status_code}')  # noqa: T001

        return sid

    def splunk_results(self, sid, wait=False):
        if not self.session_key:
            print('Session not authenticated')  # noqa: T001
            return

        results_url = f'{self.base_url}/services/search/jobs/{sid}/results/'
        auth_headers = {'Authorization': f'Splunk {self.session_key}'}

        results_request = requests.get(
            results_url,
            headers=auth_headers,
            data={'output_mode': 'json'},
            verify=self.verify_tls,
        )

        results = None
        if results_request.status_code == 200:
            results = json.loads(results_request.text)
        elif results_request.status_code == 204:
            results = None
        else:
            print(f'  [!] Status Code: {results_request.status_code} returned')

        return results


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Searching Splunk with Sigma Rules')
    parser.add_argument(
        'splunkip',
        help='IP address for the target Splunk instance',
        )
    parser.add_argument(
        'sigmafile',
        help='The path to a sigma file',
        )

    parser.add_argument(
        '-c',
        '--config',
        help='Set Custom Config file for Sigma Conversion',
        default=None,
        )

    parser.add_argument(
        '-sh',
        '--splunk_host',
        help='Set Specific Host to search against',
        default=None,
        )
    parser.add_argument(
        '-si',
        '--splunk_index',
        help='Set specific index to search against',
        default=None,
        )

    parser.add_argument(
        '-u',
        '--user',
        help='Username for the target Splunk instance',
        default='admin',
        )
    parser.add_argument(
        '-p',
        '--pass',
        help='Password for the target Splunk instance',
        default='',
        )

    parser.add_argument(
        '-vp',
        '--verbose_print',
        action='store_true',
        help='Print all the results',
    )

    args = parser.parse_args()

    print(f'[+] Connecting to Splunk Instance: {args.splunkip}')  # noqa: T001
    splunk_handler = SplunkSearch(args.splunkip)

    if args.splunk_index:
        print(f'Limiting all searches to Index: {args.splunk_index}')

    if args.splunk_host:
        print(f'Limiting all searches to Host: {args.splunk_host}')

    all_sigma_files = []

    rule_path = Path(args.sigmafile)

    if rule_path.is_file():
        all_sigma_files.append(args.sigmafile)

    if rule_path.is_dir():
        all_sigma_files = list(rule_path.glob('**/*.yml'))

    for sigma_rule in all_sigma_files:
        print(f'[+] Running Search for {sigma_rule}')  # noqa: T001

        try:
            search_strings = convert_sigma(sigma_rule, args.config)
        except Exception as err:
            print(f'  [!] Failed to convert sigma rule {sigma_rule}: {err}')
            search_strings = []

        for search in search_strings:

            raw_search_string = search['rule_string']

            sid = splunk_handler.splunk_search(
                raw_search_string,
                args.splunk_index,
                args.splunk_host,
                )

            print(f'  [-] Search running with SID: {sid}')  # noqa: T001

            if sid:
                waiting = True
                while waiting:
                    time.sleep(5)
                    print(f'  [-] Checking for completed search with SID: {sid}')  # noqa: T001
                    results = splunk_handler.splunk_results(sid)
                    if results:
                        print(f'[+] Found {len(results["results"])} results from the query')  # noqa: T001
                        waiting = False
                        if args.verbose_print:
                            pprint.pprint(results['results'])  # noqa: T001
