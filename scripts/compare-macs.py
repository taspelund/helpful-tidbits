#!/usr/bin/python3

import subprocess
from sys import exit

kern_macs_raw = subprocess.Popen('/sbin/bridge fdb show | grep dst | grep -v perm',
                                 shell=True, stdout=subprocess.PIPE).stdout.read().decode('utf-8')

hw_macs_raw = subprocess.Popen('/usr/bin/fdb_dump_new.py | grep TUN_ID',
                                shell=True, stdout=subprocess.PIPE).stdout.read().decode('utf-8')

kern_macs = {}
for kmac in kern_macs_raw.splitlines():
    current_kmac = []
    kmac = kmac.split()
    kaddr = kmac[0]
    ktun = kmac[4]
    kern_macs[kaddr] = ktun

hw_macs = {}
for hmac in hw_macs_raw.splitlines():
    current_hmac = []
    hmac = hmac.split()
    haddr = hmac[4][:-1]
    htun = hmac[5].split('_')[-1][:-1]
    hw_macs[haddr] = htun

for mac in kern_macs:
    k = kern_macs.get(mac)
    h = hw_macs.get(mac)
    if k != h:
        print('discrepancy found for mac %s! kernel tun %s does not match hw tun %s' % (mac,k,h))
    else:
        print('kernel tun %s and hw tun %s match for mac %s' % (k,h,mac))
