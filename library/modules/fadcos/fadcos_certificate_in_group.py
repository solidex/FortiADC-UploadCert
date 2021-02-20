from ansible.module_utils.basic import *
from ansible.module_utils.FortiADCAPI import FortiADCAPI
import json
from argparse import Namespace
from ansible.module_utils.mylogging import logger
import difflib
import re

api = FortiADCAPI()

def add_cert_to_group(data):
    api.login(data)

    data['pkey'] = data['group_name']
    status_code, output = api.get_obj_by_pkey('api/system_certificate_local_cert_group_child_group_member', data)

    if status_code == 200:
        group_details = json.loads(output)['payload']
    else:
        meta = {'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
        meta['status'] = json.loads(output)['payload']
        meta['err_msg'] = api.get_err_msg(meta['status'])
        return True, False, meta

    logger.debug(group_details)

    for cert_obj in group_details:
        # check if cert in group

        if cert_obj[u'local_cert'].encode('utf-8') == data['certificate_name'] or cert_obj['local_cert'] == data['certificate_name']:
            meta = {'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
            meta['status'] = json.loads(output)['payload']
            return False, False, meta

    changed = False
    payload = { 'OCSP_stapling': '', 'default': 'disable', 'extra_local_cert': '', 'intermediate_cag': '', 'local_cert': data['certificate_name'] }

    status_code, output = api.add_obj('api/system_certificate_local_cert_group_child_group_member', data, payload)

    meta = {"status": status_code, 'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
    if 'payload' in json.loads(output):
        if json.loads(output)['payload'] == 0:
            changed = True
        else:
            meta['status'] = json.loads(output)['payload']
            meta['err_msg'] = api.get_err_msg(meta['status'])

    api.logout()

    if meta['status'] in [0, -154, 200]:
        if changed:
            return False, True, meta
        else:
            return False, False, meta
    else:
        return True, False, meta

def delete_cert_from_group(data):
    api.login(data)

    data['pkey'] = data['group_name']
    status_code, output = api.get_obj_by_pkey('api/system_certificate_local_cert_group_child_group_member', data)

    if status_code == 200:
        group_details = json.loads(output)['payload']
    else:
        meta = {'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
        meta['status'] = json.loads(output)['payload']
        meta['err_msg'] = api.get_err_msg(meta['status'])
        return True, False, meta

    mkey = -1
    for cert_obj in group_details:
        # check if cert in group
        if cert_obj[u'local_cert'].encode('utf-8') == data['certificate_name']:
            mkey = cert_obj['mkey']
            break

    if mkey == -1:
        meta = {'http_status': 200 if status_code == 200 else 500, 'output': json.loads(output)}
        meta['status'] = json.loads(output)['payload']
        return False, False, meta

    data['mkey'] = mkey
    status_code, output = api.delete_obj('api/system_certificate_local_cert_group_child_group_member', data, data['pkey'])

    changed = False

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

    if not module.params['certificate_name']:
        err_msg.append('Parameter certificate_name must be set')
        res = False
    if not module.params['group_name']:
        err_msg.append('Parameter group_name must be set')
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
        "certificate_name": {"required": False, "type": "str"},
        "group_name": {"required": False, "type": "str"}
    }

    choice_map = {
        "present": add_cert_to_group,
        "absent": delete_cert_from_group
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
