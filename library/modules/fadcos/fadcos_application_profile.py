from ansible.module_utils.basic import *
from ansible.module_utils.FortiADCAPI import FortiADCAPI
import json
from argparse import Namespace
import logging
import difflib
import re

api = FortiADCAPI()

def needs_update(data, new_data):
    params = [
        'type',
        'client_address',
        'http_x_forwarded_for',
        'http_x_forwarded_for_header',
        'starttls_active_mode',
        'smtp_domain_name'
    ]

    res = False
    diff_data = {}

    for param in params:
        if param in new_data and data[param] != new_data[param]:
            diff_data[param] = new_data[param]
            res = True
    return res, diff_data

def add_profile(data):
    api.login(data)

    name = data['name']

    data['mkey'] = data['name']
    status_code, output = api.get_obj('api/load_balance_profile', data)

    changed = False
    if status_code == 200:
        # profile already exists, identified by name
        if json.loads(output)['payload']:
            res, payload = needs_update(json.loads(output)['payload'], data)
            if res:
                status_code, output = api.update_obj('api/load_balance_profile', data, payload)

                meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
                if 'payload' in json.loads(output):
                    if json.loads(output)['payload'] == 0:
                        changed = True
                    else:
                        meta['status'] = json.loads(output)['payload']
                        meta['err_msg'] = api.get_err_msg(meta['status'])
            else:
                meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}

        # profile doesn't exist, identified by name
        else:

            payload = {
                'mkey': name,
                'type': data['type'],
                'client_address': data['client_address'],
                'http_x_forwarded_for': data['x_forwarded_for'],
                'http_x_forwarded_for_header': data['x_forwarded_for_header'],
                'starttls_active_mode': data['starttls_active_mode'],
                'smtp_domain_name': data['smtp_domain_name']
            }
            status_code, output = api.add_obj('api/load_balance_profile', data, payload)

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


def param_check(module):
    res = True
    state = module.params['state']
    err_msg = []

    if not module.params['name']:
        err_msg.append('Parameter name must be set')
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
        "name": {"required": True, "type": "str"},
        "type": {"required": True, "type": "str"},
        "client_address": {"required": False, "type": "str", "default": "disable"},
        "x_forwarded_for": {"required": False, "type": "str", "default": "disable"},
        "x_forwarded_for_header": {"required": False, "type": "str", "default": "X-Forwarded-For"},
        "starttls_active_mode": {"required": False, "type": "str", "default": "allow"},
        "smtp_domain_name": {"required": False, "type": "str", "default": "example.com"}
    }

    choice_map = {
        "present": add_profile
        # "absent": delete_group
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
