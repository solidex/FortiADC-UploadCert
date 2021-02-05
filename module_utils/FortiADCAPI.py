import sys
import os
import datetime
import json
import requests

import logging

try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 0

# You must initialize logging, otherwise you'll not see debug output.
logging.basicConfig()
logging.getLogger().setLevel(logging.WARNING)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.WARNING)
requests_log.propagate = True

formatter = logging.Formatter(
    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fortiadcapi')
hdlr = logging.FileHandler('/var/tmp/ansible-fortiadcapi.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

MONITOR_ACTIONS_TO_API_DICT = {
    'system ha status': 'api/system_ha/status',
    'slb all_vs_info': 'api/all_vs_info/vs_list',
    'platform info': 'api/platform/info'
}


class FortiADCAPI:


    MONITOR_ACTIONS = [
        'system ha status',
        'slb all_vs_info',
        'platform info',
        'logs'
    ]

    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        self.session = requests.Session()
        self.session.verify = False

    def login(self, data):

        payload = { 'username': data['username'], 'password': data['password'] }
        self.host = data['host']
        response = self.session.post('https://%s/api/user/login' % self.host, json = payload )

        if response.status_code == requests.codes.ok:
            json_data = json.loads(response.text)
            self.session.headers.update({'Authorization': 'Bearer ' + json_data['token']})
        else:
            sys.exit('ERROR: Could not login to FortiADC')

    def _extend_login(self, url):
        response = self.session.post('https://%s/%s' % (self.host, url), data = [])

        if not response.status_code == requests.codes.ok:
            sys.exit('ERROR: Could not extend login')

    def monitor(self, data):
        action = data['action']
        vdom = data['vdom']
        if action in self.MONITOR_ACTIONS:
            if action == 'logs':
                return self._logs(data)
            else:
                response = self.session.get('https://%s/%s?vdom=%s' % (self.host, MONITOR_ACTIONS_TO_API_DICT[action], vdom))
                return response.status_code, response.text
        else:
            sys.exit('ERROR: Unknown action')

    def get_obj(self, api_endpoint, data):
        mkey = data['mkey']
        vdom = data['vdom']

        url = 'https://%s/%s?mkey=%s&vdom=%s' % (self.host, api_endpoint, mkey, vdom)

        logger.debug("%s %s" % ('get', url))

        response = self.session.get(url)
        logger.debug("%s - %s" % (response.status_code, response.content))
        return response.status_code, response.content

    def get_obj_by_pkey(self, api_endpoint, data):
        pkey = data['pkey']
        vdom = data['vdom']

        url = 'https://%s/%s?pkey=%s&vdom=%s' % (self.host, api_endpoint, pkey, vdom)

        logger.debug("%s %s" % ('get', url))

        response = self.session.get(url)
        logger.debug("%s - %s" % (response.status_code, response.content))
        return response.status_code, response.content

    def add_obj(self, api_endpoint, data, payload):
        if 'pkey' in data:
            pkey = data['pkey']
        else:
            pkey = ""
        if 'vdom' in data:
            vdom = data['vdom']
        else:
            vdom = ""
        if pkey:
            url = 'https://%s/%s?pkey=%s&vdom=%s' % (self.host, api_endpoint, pkey, vdom)
        else:
            url = 'https://%s/%s?vdom=%s' % (self.host, api_endpoint, vdom)

        logger.debug("post - %s" % url)
        logger.debug(payload)

        response = self.session.post(url, json = payload)
        logger.debug("%s - %s" % (response.status_code, response.content))
        return response.status_code, response.content

    def update_obj(self, api_endpoint, data, payload):
        if 'mkey' in data:
            mkey = data['mkey']
        else:
            mkey = ""
        if 'vdom' in data:
            vdom = data['vdom']
        else:
            vdom = ""
        url = 'https://%s/%s?mkey=%s&vdom=%s' % (self.host, api_endpoint, mkey, vdom)

        logger.debug("%s %s" % ('put', url))
        logger.debug(payload)

        response = self.session.put(url, json = payload)
        logger.debug("%s - %s" % (response.status_code, response.content))
        return response.status_code, response.content


    def upload_cert(self, data):
        vdom = data['vdom']
        url = 'api/upload/certificate_local?entire=enable&vdom=%s' % vdom

        key_file = open(os.path.join(data['path'], data['name'] + '.key'), 'rb')
        cert_file = open(os.path.join(data['path'], data['name'] + '.cert'), 'rb')

        payload = { 'mkey': data['name'], 'vdom': data['vdom'], 'type': 'CertKey' }
        logger.debug(payload)
        files = { 'cert': cert_file, 'key': key_file }

        response = self.session.post('https://%s/%s' % (self.host, url), data = payload, files = files)
        logger.debug(response)
        return response.status_code, response.content

    def delete_obj(self, api_endpoint, data, pkey = None):
        mkey = data['mkey']
        if 'vdom' in data:
            vdom = data['vdom']
        else:
            vdom = ""

        if pkey:
            url = 'https://%s/%s?pkey=%s&mkey=%s&vdom=%s' % (self.host, api_endpoint, pkey, mkey, vdom)
        else:
            url = 'https://%s/%s?mkey=%s&vdom=%s' % (self.host, api_endpoint, mkey, vdom)
        logger.debug('delete - %s' % url)

        response = self.session.delete(url)
        logger.debug(response)
        return response.status_code, response.content

    def _logs(self, data):
        vdom = data['vdom']
        search_filter = data['log_search_filter']
        if data['log_type']:
            log_type = data['log_type']
        else:
            log_type = "attack"
        if data['log_subtype']:
            log_subtype = data['log_subtype']
        else:
            log_subtype = "ip_reputation"

        try:
            search_filter_json = json.loads(search_filter)
        except:
            search_filter = data['log_search_filter'].replace('\'', '"')
            search_filter_json = json.loads(search_filter)

        self._extend_login('api/log_report/logs?type=attack&subType=%s&vdom=data&refresh=1&action=add&filename=1.%s.alog' % (log_subtype, log_subtype))

        payload = {'draw':1,'columns':[],'order':[],'start':0,'length':100,'search':search_filter_json}

        url = 'https://%s/api/log_report/logs?action=server&type=%s&subType=%s&filename=1.%s.alog&vdom=%s&refresh=1' % (self.host, log_type, log_subtype, log_subtype, vdom)

        response = self.session.post(url, json=payload)
        return response.status_code, response.content

    def logout(self):
        response = self.session.get('https://%s/api/user/logout' % self.host)

    def get_err_msg(self, err_id):
        url = 'https://%s/api/platform/errMsg' % (self.host)

        response = self.session.get(url)
        if str(err_id) in json.loads(response.content)['payload']:
            err_msg = json.loads(response.content)['payload'][str(err_id)]
        else:
            err_msg = 'err code: ' + str(err_id)
        return err_msg
