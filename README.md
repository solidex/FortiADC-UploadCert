### About
These ansible scripts can be used to:
- upload certificates into FortiADC
- add uploaded certifcate to FortiADC local certificate group

#### Requirements
Ansible version: 2.8.11

#### How to use
1/ Create a local_certificate_group on FortiADC

2/ Place certificates `*.cert` and corresponding keys `*.key` in a local directory


```cert/<FortiADC inventory_hostname>/<local certifcate group name>/```

  Example:

```
$ tree cert/
cert/
└── dc1-adc1.1
    ├── whm_202-1
    │   ├── server1.cert
    │   ├── server1.key
    │   ├── server2.cert
    │   ├── server2.key
    │   ├── server3.cert
    │   └── server3.key
    └── whm_202-2
        ├── server4.cert
        ├── server4.key
        ├── server4.cert
        └── server4.key

```  

3/ Run ansible playbook:

```ansible-playbook upload_cert.yml```
