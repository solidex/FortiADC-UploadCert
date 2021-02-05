from ansible.module_utils.basic import *
from ansible.module_utils.FortiADCAPI import FortiADCAPI
import json
from argparse import Namespace
import logging
import difflib
import re

api = FortiADCAPI()

def add_cert(data):
    api.login(data)

    data['mkey'] = data['name']
    status_code, output = api.get_obj('api/system_certificate_local', data)

    changed = False
    if status_code == 200:
        # cert already exists, identified by name
        if json.loads(output)['payload']:
            meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
        # cert doesn't exist, identified by name
        else:
            status_code, output = api.upload_cert(data)

            meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
            if 'payload' in json.loads(output):
                if json.loads(output)['payload'] == 0:
                    changed = True
                else:
                    meta['status'] = json.loads(output)['payload']
                    meta['err_msg'] = api.get_err_msg(meta['status'])
    else:
        meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
        if 'payload' in json.loads(output):
            meta['status'] = json.loads(output)['payload']
            meta['err_msg'] = api.get_err_msg(meta['status'])

    api.logout()

    if meta['status'] in [0, 200]:
        if changed:
            return False, True, meta
        else:
            return False, False, meta
    else:
        return True, False, meta

def delete_cert(data):
    api.login(data)

    data['mkey'] = data['name']
    status_code, output = api.get_obj('api/system_certificate_local', data)

    changed = False
    if status_code == 200:
        # cert already exists, identified by name
        if json.loads(output)['payload']:
            status_code, output = api.delete_obj('api/system_certificate_local', data=data)

            meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
            if 'payload' in json.loads(output):
                if json.loads(output)['payload'] == 0:
                    changed = True
                else:
                    meta['status'] = json.loads(output)['payload']
                    meta['err_msg'] = api.get_err_msg(meta['status'])
        # cert doesn't exist, identified by name
        else:
            meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
    else:
        meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
        if 'payload' in json.loads(output):
            meta['status'] = json.loads(output)['payload']
            meta['err_msg'] = api.get_err_msg(meta['status'])

    api.logout()

    if meta['status'] in [0, 200]:
        if changed:
            return False, True, meta
        else:
            return False, False, meta
    else:
        return True, False, meta



def param_check(module):
    res = True
    state = module.params['state']
    err_msg = []

    if (state == 'absent') and not module.params['mkey']:
        err_msg.append('Parameter mkey must be set')
        res = False

    return res, err_msg


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "username": {"required": True, "type": "str"},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": False, "type": "str", "type": "str"},
        "https": {"required": False, "type": "bool", "default": "True"},
        "ssl_verify": {"required": False, "type": "bool", "default": "True"},
        "commands": {"required": False, "type": "str"},
        "name": {"required": False, "type": "str"},
        "path": {"required": False, "type": "str"},
        "mkey": {"required": False, "type": "str"}
    }

    choice_map = {
        "present": add_cert,
        "absent": delete_cert
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    module.params['diff'] = False
    try:
        module.params['diff'] = module._diff
    except:
        logger.warning("Diff mode is only available on Ansible 2.1 and later versions")
        pass

    result = {}
    param_pass, param_err = param_check(module)

    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    else:

        is_error, has_changed, result = choice_map.get(module.params['state'])(module.params)

    if not is_error:
        if module.params['diff']:
            module.exit_json(changed=has_changed, meta=result, diff={'prepared': result['diff']})
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error", meta=result)


if __name__ == '__main__':
    main()
