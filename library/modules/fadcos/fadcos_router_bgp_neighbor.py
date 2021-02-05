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
        "ip",
        "remote-as"
    ]

    res = False
    diff_data = {}

    for param in params:
        if param in new_data and data[param].strip() != new_data[param].strip():
            diff_data[param] = new_data[param]
            res = True
    return res, diff_data


def update(status_code, output, data, neighbor):
    changed = False
    res, payload = needs_update(neighbor, data)
    if res:
        status_code, output = api.update_obj('api/router_bgp_child_neighbor', data, payload)

        meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
        if 'payload' in json.loads(output):
            if json.loads(output)['payload'] == 0:
                changed = True
            else:
                meta['status'] = json.loads(output)['payload']
                meta['err_msg'] = api.get_err_msg(meta['status'])
    else:
        meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
    return changed, meta

def create(data):

    changed = False

    payload = {
        "ip": data["ip"],
        "remote-as": data["remote-as"]
    }
    status_code, output = api.add_obj('api/router_bgp_child_neighbor', data, payload)

    meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
    if 'payload' in json.loads(output):
        if json.loads(output)['payload'] == 0:
            changed = True
        else:
            meta['status'] = json.loads(output)['payload']
            meta['err_msg'] = api.get_err_msg(meta['status'])

    return changed, meta

def config_router(data):
    api.login(data)

    data['mkey'] = ""
    status_code, output = api.get_obj('api/router_bgp_child_neighbor', data)

    changed = False
    if status_code == 200:

        exists = False

        for nei in json.loads(output)['payload']:
            if nei['ip'] == data['ip']:
                exists = True
                neighbor = nei
                break
        if exists:
            changed, meta = update(status_code, output, data, neighbor)

        else:
            changed, meta = create(data)
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

    if not module.params['ip']:
        err_msg.append('Parameter `router-id` must be set')
        res = False
    if not module.params['remote-as']:
        err_msg.append('Parameter `as` must be set')
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
        "ip": {"required": True, "type": "str"},
        "remote-as": {"required": True, "type": "str"}
    }

    choice_map = {
        "present": config_router
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
