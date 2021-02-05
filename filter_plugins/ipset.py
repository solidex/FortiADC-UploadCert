#!/usr/bin/python
from netaddr import *

class FilterModule(object):
    def filters(self):
        return {'ipset': self.get_ip_set}

    def get_ip_set(self, network):
        iplist = set()
        for i in IPSet([ '192.168.1.0/30' ]):
            iplist.add(str(i))
        return list(sorted(iplist))
