#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
from requests.auth import HTTPBasicAuth
import time
import re
from datetime import datetime, timedelta

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):

    JSON_field_mappings = {
            'FileName': 'file_name',
            'PathName': 'file_path',
            'LastSeen': 'timestamp',
            'GroupId': 'group_id'
    }

    def read_input_file(self, filename):
        with open(filename) as file:
            data = file.readlines()
        file.close()
        return json.loads(data[0])


    def cleanhtml(self, raw_html):
        cleanr = re.compile('<.*?>')
        cleantext = re.sub(cleanr, '', raw_html)
        return cleantext

    def get_auth_token(self, ssl_verify=True, proxies=None):
        url = self.url + '/auth/token'
        self.ds.log('INFO', "Attempting to connect to url: " + url)
    
        #headers = {'X-Auth-Token': "{0}/{1}".format(api_key, connector_id)}

        headers = {
                'Content-Type':'application/x-www-form-urlencoded'
                }

        data = {
                'username': self.username,
                'password': self.password,
                'grant_type':'password',
                'scope':'Console.GSM'
               }
        try:
            response = requests.post(url, auth = HTTPBasicAuth(self.client_id, self.client_secret), headers=headers, data = data, timeout=15, verify=ssl_verify, proxies=proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return False
        else:
            self.auth_info = response.json()
            return True

    def threathistory_request(self, ssl_verify= True, proxies = None, siteId = None, groupId = None, pageNr = 1):

        url = self.url + '/service/api/console/gsm/' + self.gsm_key + '/sites/' + siteId + '/groups/' + groupId + '/threathistory'

        headers = {
                'Authorization':'Bearer '+ self.auth_info['access_token']
                }

        data = {
                'endDate': self.current_run,
                'startDate': self.last_run,
                'PageNr': pageNr
               }
        self.ds.log('INFO', "Attempting to connect to url: " + url + ' ,data: ' + str(data))
        try:
            response = requests.get(url, headers=headers, timeout=15, params=data, verify=ssl_verify, proxies = proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return False

        if not response or response.status_code != 200:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Cb Defense Server {0}.".format(
                    url))
            return None
        json_response = json.loads(response.content)

        self.ds.log('INFO', "Results for url: " + url + ' ,record count: ' + str(len(json_response['ThreatRecords'])))
        return json_response

    def get_threathistory(self, siteId = None, groupId = None):
        threat_records = []
        json_response = self.threathistory_request(siteId=siteId, groupId=groupId)
        threat_records += json_response['ThreatRecords']
        PageNr = 0
        while json_response['MoreAvailable'] == True:
            PageNr = json_response['PageNr'] + 1
            json_response = self.threathistory_request(siteId = siteId, groupId = groupId, pageNr = PageNr)
            threat_records += json_response['ThreatRecords']
        return json_response['ThreatRecords']


    def grouplist_request(self, ssl_verify= True, proxies = None, siteId = None):
        url = self.url + '/service/api/console/gsm/' + self.gsm_key + '/sites/' + siteId + '/groups'

        headers = {
                'Authorization':'Bearer '+ self.auth_info['access_token']
                }
        try:
            response = requests.get(url, headers=headers, timeout=15, verify=ssl_verify, proxies = proxies)
        except Exception as e:

            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return False
        if not response or response.status_code != 200:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Webroot Server {0}.".format(
                    url))
            return None
        json_response = json.loads(response.content)
        return json_response['Groups']

    def sitelist_request(self, ssl_verify = True, proxies = None):
        url = self.url + '/service/api/console/gsm/' + self.gsm_key + '/sites'

        headers = {
                'Authorization':'Bearer '+ self.auth_info['access_token']
                }
        try:
            response = requests.get(url, headers=headers, timeout=15, verify=ssl_verify, proxies = proxies)
        except Exception as e:

            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return False
        if not response or response.status_code != 200:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Webroot Server {0}.".format(
                    url))
            return None
        json_response = json.loads(response.content)
        return json_response['Sites']

    def webroot_main(self): 

        self.url = self.ds.config_get('webroot', 'server_url')
        self.client_id = self.ds.config_get('webroot', 'client_id')
        self.client_secret = self.ds.config_get('webroot', 'client_secret')

        self.username = self.ds.config_get('webroot', 'username')
        self.password = self.ds.config_get('webroot', 'password')
        self.site_name = self.ds.config_get('webroot', 'site_name')
        self.gsm_key = self.ds.config_get('webroot', 'gsm_key')

        self.state_dir = self.ds.config_get('webroot', 'state_dir')
        self.last_run = self.ds.get_state(self.state_dir)
        self.time_format = "%Y-%m-%dT%H:%M:%S"
        current_time = datetime.now()
        self.current_run = current_time.strftime(self.time_format)

        if self.last_run == None:
            #last_run = current_time - timedelta(minutes = 15)
            last_run = current_time - timedelta(days = 30)
            self.last_run = last_run.strftime(self.time_format)

        if not self.get_auth_token():
            self.ds.log('ERROR', 
                    "Failed Authentication from Webroot API {0}.".format(
                    self.ds.config_get('webroot', 'server_url')))
            return

        sites = self.sitelist_request()
        threat_list = []
        for site in sites:
            groups = self.grouplist_request(siteId = site['SiteId'])
            for group in groups:
                threats = self.get_threathistory(siteId = site['SiteId'], groupId = group['GroupId'])
                for threat in threats:
                    threat['SiteId'] = site['SiteId']
                    threat['GroupId'] = group['GroupId']
                    threat_list.append(threat)

        for threat in threat_list:
            threat['category'] = 'threat'
            threat['message'] = 'Threat Detected - ' + threat['MalwareGroup']
            self.ds.writeJSONEvent(threat, JSON_field_mappings = self.JSON_field_mappings)

        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('webroot', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of cb defense syslog connector is already running")
                # another instance is running
                sys.exit(0)
            self.webroot_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('webrootEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
