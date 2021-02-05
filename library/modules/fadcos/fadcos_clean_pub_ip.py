from ansible.module_utils.basic import *
from ansible.module_utils.FortiADCAPI import FortiADCAPI
import json
from argparse import Namespace
import logging
import difflib
import re

api = FortiADCAPI()


def delete_vs(data, mkey):
    changed = False

    payload = { 'vdom': data['vdom'], 'mkey': mkey }
    status_code, output = api.delete_obj('api/load_balance_virtual_server', payload)

    meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
    if 'payload' in json.loads(output):
        if json.loads(output)['payload'] == 0:
            changed = True
        else:
            meta['status'] = json.loads(output)['payload']
            meta['err_msg'] = api.get_err_msg(meta['status'])

    return changed, meta

def delete_all_vs(data):
    api.login(data)

    data['mkey'] = ""
    status_code, output = api.get_obj('api/load_balance_virtual_server', data)
    meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
    global_changed = False

    if status_code == 200:
        for vs in json.loads(output)['payload']:
            if vs['address'] == data['pub_ip']:
                changed, meta = delete_vs(data, vs['mkey'])
                if changed:
                    global_changed = True
    else:
        if 'payload' in json.loads(output):
            meta['status'] = json.loads(output)['payload']
            meta['err_msg'] = api.get_err_msg(meta['status'])

    api.logout()

    if meta['status'] in [0, 200]:
        if global_changed:
            return False, True, meta
        else:
            return False, False, meta
    else:
        return True, False, meta


def param_check(module):

    res = True
    err_msg = []

    if not module.params['pub_ip']:
        err_msg.append('Parameter `pub_ip` must be set')
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
        "pub_ip": {"required": True, "type": "str"}
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

        is_error, has_changed, result = delete_all_vs(module.params)

    if not is_error:
        if module.params['diff']:
            module.exit_json(changed=has_changed, meta=result, diff={'prepared': result['diff']})
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error", meta=result)


if __name__ == '__main__':
    main()
