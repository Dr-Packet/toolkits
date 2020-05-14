#!/usr/bin/env python

import requests
import os
import sys
import json
from datetime import datetime
from pprint import pprint
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # disable security warning for SSL certificate
# import logging
# logging.captureWarnings(True)

__version__ = "0.1.0"


class FGT(object):
    """
    Class to send GET/POST/PUT/DELETE and backup requests to FGT
    
    Parameters:
    host (string): IP Address of firewall
    key (string): API Key of firewall
    hostname (string): Hostname of firewall. Only used for config backup filename
    """

    def __init__(self, host, key, hostname=None):
        self.host = host
        self.key = key
        self.url_prefix = "https://" + self.host + '/api/v2/'
        self.token = {'Authorization': f'Bearer {key}'}
        self.hostname = hostname

    def get(self, url, **params):
        '''
        Send a GET request to the firewall.

        Parameters:
        url (string): URL of request NOT including /api/v2/
            i.e., for monitor api call, pass 'monitor/<rest-of-url>'
            and for configuration call, pass 'cmdb/<rest-of-url>'
        params (dict): Optional parameters to pass

        Returns:
        string: JSON response of GET request
        '''
        url = self.url_prefix + url
        res = None
        try:
            res = requests.get(
                url,
                headers=self.token,
                params=params,
                verify=False)
        except requests.exceptions.RequestException as e:
            print(e)
            exit()

        return res.text

    def post(self, url, **params):
        '''
        Send a POST request to the firewall.

        Parameters:
        url (string): URL of request NOT including /api/v2/
            i.e., for monitor api call, pass 'monitor/<rest-of-url>'
            and for configuration call, pass 'cmdb/<rest-of-url>'
        params (dict): Parameters to pass
            Currently only passing JSON. Must pass dictionary containing
            {'json':{
                'key':'value',
                'key':'value'
            }}

        Returns:
        bool: Returns True if successful, else False
        '''
        url = self.url_prefix + url
        json = params.get("json") if params.get("json") else None
        try:
            res = requests.post(
                url,
                headers=self.token,
                json=json,
                verify=False)
        except requests.exceptions.RequestException as e:
            print(e)
            exit()
        return check_response(res, False)

    def put(self, url, **params):
        '''
        Send a PUT request to the firewall.

        Parameters:
        url (string): URL of request NOT including /api/v2/
            i.e., for monitor api call, pass 'monitor/<rest-of-url>'
            and for configuration call, pass 'cmdb/<rest-of-url>'
        params (dict): Parameters to pass
            Currently only passing JSON. Must pass dictionary containing
            {'json':{
                'key':'value',
                'key':'value'
            }}

        Returns:
        bool: Returns True if successful, else False
        '''
        url = self.url_prefix + url
        json = params.get("json") if params.get("json") else None
        try:
            res = requests.put(
                url,
                headers=self.token,
                json=json,
                verify=False)
        except requests.exceptions.RequestException as e:
            print(e)
            exit()
        return check_response(res, False)

    def delete(self, url, **params):
        '''
        Send a DELETE request to the firewall.

        Parameters:
        url (string): URL of request NOT including /api/v2/
            i.e., for monitor api call, pass 'monitor/<rest-of-url>'
            and for configuration call, pass 'cmdb/<rest-of-url>'
        params (dict): Parameters to pass
            Currently only passing JSON. Must pass dictionary containing
            {'json':{
                'key':'value',
                'key':'value'
            }}

        Returns:
        bool: Returns True if successful, else False
        '''
        url = self.url_prefix + url
        json = params.get("json") if params.get("json") else None
        try:
            res = requests.delete(
                url,
                headers=self.token,
                json=json,
                verify=False)
        except requests.exceptions.RequestException as e:
            print(e)
            exit()
        return check_response(res, False)

    def backup(self):
        '''
        Create a backup of firewall.

        Returns:
        bool: Returns True if successful, else False
        '''
        now = datetime.now()
        filename = self.hostname + "_" + str(now.year) + str(now.month).zfill(2) + str(now.day).zfill(2) + "_" + str(
            now.hour).zfill(2) + str(now.minute).zfill(2) + ".conf"
        if os.path.exists(filename):
            filename = self.hostname + "_" + str(now.year) + str(now.month).zfill(2) + str(now.day).zfill(
                2) + "_" + str(now.hour).zfill(2) + str(now.minute).zfill(2) + "_POST.conf"

        params = {'scope': 'global'}
        url = self.url_prefix + 'monitor/system/config/backup/'
        res = None
        try:
            res = requests.get(
                url,
                headers=self.token,
                params=params,
                verify=False)
        except requests.exceptions.RequestException as e:
            print(e)
            exit()

        if res.status_code != 200:
            print(f'Error when taking backup. status_code: {res.status_code}')
            return False

        print(res.status_code)
        with open(filename, 'w+') as f:
            f.write(res.text)
            return True

        return False


##########################################################

# This has been replaced by a method fnt_connector()

class fnt_tools(object):
    """
    Class to connect to FortiGate devices

    Depends on FGT class

    Parameters:
    host: Firewall IP address and Port
    key: Firewall API Key
    """

    def __init__(self, host, key):
        self.host = host
        self.key = key
        self.current_firewall = FGT(host, key)
        #PLEASE TEST ME!
        self.hostname = self.current_firewall.get(f'cmdb/system/global/hostname') # THIS MAY NOT WORK

    def backup_pre_changes(self):
        if (self.current_firewall.backup()):
            print(f'Pre-Operation Config Backup for {self.hostname} successful.')
        else:  # If pre-operation backup fails, do not make change
            print(f'Error taking Pre-Operation Config for {self.hostname} backup. No operations performed.')



    def routes_show(self):
        # Self.Routes here because I don't want to call information I don't need
        self.static_routes = self.current_firewall.get('cmdb/router/static/')
        self.policy_routes = self.current_firewall.get('cmdb/router/policy/')
        self.ospf_routes = self.current_firewall.get('cmdb/router/ospf/')

    def routes_remove_non_default(self):
        res = self.current_firewall.get('cmdb/router/static/')
        res_dict = json.loads(
            res)  # get returns a JSON string--must convert to a python dictionary--perhaps a good idea to change acutools to return a dictionary instead of the response in the future?
        # res_dict = {
        #     "results":[
        #         {
        #         "seq-num":1,
        #         "dst":"0.0.0.0 0.0.0.0",
        #         "device":"wan1"
        #         },
        #         {
        #         "seq-num":2,
        #         "dst":"10.0.0.0 255.0.0.0",
        #         "device":"VPN_OmniPeak10"
        #         },
        #         {
        #         "seq-num":3,
        #         "dst":"10.0.0.0 255.0.0.0",
        #         "device":"test2"
        #         },
        #         {
        #         "seq-num":4,
        #         "dst":"10.0.0.0 255.0.0.0",
        #         "device":"test3"
        #         }
        #     ]
        # }
        routes_to_delete = []
        for route in res_dict["results"]:
            if route["dst"] != "0.0.0.0 0.0.0.0":
                routes_to_delete.append(route)

        routes_to_delete.sort(reverse=True, key=returnSeqNum)  # need to sort items in reverse order. When deleting
        # removing item 2 will likely cause the further routes to "shift up"
        # in the array, causing their seq-num to change. This would lead to
        # out-of-bounds errors, potentially deleting the wrong route, etc.

        for route in routes_to_delete:
            self.current_firewall.delete(f'cmdb/router/static/{route["seq-num"]}')
            print(f'cmdb/router/static/{route["seq-num"]}')
            print(route["device"])




##########################################################

"""
class info_gather(object):
   
    Class to make repeatable changes against firewalls

    Parameters:
    



    def __init__(self):
        self.current_firewall = fnt_connector.connector(host, key)

    # Print out static routing table to console
    def routes(self):
        print(self.current_firewall)
        static_routes = self.current_firewall.get('cmdb/router/static/')
        policy_routes = self.current_firewall.get('cmdb/router/policy/')
        ospf_routes = self.current_firewall.get('cmdb/router/ospf/')

        return static_routes, ospf_routes, policy_routes
"""

##########################################################

# function to retrieve json data from HTTP response (return False if fails)
def get_json(response):
    try:
        rjson = response.json()
    except UnicodeDecodeError as e:
        print("Cannot decode json data in HTTP response")
        return False
    except:
        e = sys.exc_info()[0]
        print(e)
        return False
    else:
        return rjson


# function to check response
def check_response(res, verbose):
    rjson = get_json(res)
    if verbose: pprint(rjson)
    if not rjson:
        print("Failed to retrieve JSON response")
    else:
        status = rjson["http_status"]
        if status == 200:
            if verbose: print("200 successful request")
            return True
        elif status == 400:
            print("400 Invalid request format")
        elif status == 403:
            print("403 Permission denied")
        elif status == 404:
            print("404 None existing resource")
        elif status == 405:
            print("405 Unsupported method")
        elif status == 424:
            print("424 Dependency error")
        elif status == 500:
            print("500 Internal server error")
        else:
            print(status, "Unknown error")
        return False

def returnSeqNum(e):
    return e["seq-num"]