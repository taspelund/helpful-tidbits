#!/usr/bin/python3

from sys import exit, argv
import subprocess

"""
punt_everything.py will add a new TCAM entry that will punt all traffic to CPU indiscriminately.
The logic is to find the highest group_id in Lookup stage and use it, then create a new entry
in the group using the highest entry number + 1 as the new entry_id.
Only works on BCM, and must be run as root.
"""

if len(argv) > 1:
    if len(argv) != 3:
        print("invalid syntax. either run script without arguments, or with 'remove [entry_id]'")
        exit(1)
    if argv[1] == 'remove':
        current_eid = argv[2]
        print('removing entry %s ...' % current_eid)
        subprocess.call("/usr/lib/cumulus/bcmcmd fp entry destroy " + current_eid, shell=True)
        exit(0)
    if argv[1] == 'show':
        current_eid = argv[2]
        print('displaying entry %s ...' % current_eid)
        subprocess.call("/usr/lib/cumulus/bcmcmd fp show entry " + current_eid, shell=True)
        exit(0)

######################
# group processing
#
gids_lines = subprocess.getoutput("/usr/lib/cumulus/bcmcmd fp show | grep GID | grep stage=Lookup").splitlines()
gids = []
for i in gids_lines:
    i = i.split()
    gids.append(i[1][:-1])
gids.sort()
entry_gid = gids[-1]


######################
# entry processing
#
eids_lines = subprocess.getoutput("/usr/lib/cumulus/bcmcmd fp show | grep EID").splitlines()
eids = []
for i in eids_lines:
    i = i.split()
    eid_int = int(i[1][:-1], 16)
    # add 1 to all ints so I don't have to convert int -> str -> int -> str
    eids.append(eid_int + 1)

eids.sort()
current_eid = hex(eids[-1])

entry_gid = '2'
print('creating entry %s ...' % current_eid)
subprocess.call("/usr/lib/cumulus/bcmcmd fp entry create " + entry_gid + " " + current_eid, shell=True)
subprocess.call("/usr/lib/cumulus/bcmcmd fp action add " + current_eid + " CopyToCpu 0 0", shell=True)

print('installing entry %s ...' % current_eid)
subprocess.call("/usr/lib/cumulus/bcmcmd fp entry install " + current_eid, shell=True)

print('new entry:')
print(subprocess.getoutput("/usr/lib/cumulus/bcmcmd fp show entry " + current_eid))
