#!/usr/bin/python3
"""
This script parses the kernel & evpn mac tables of multiple cl-support bundles.
If multiple vtep addresses are seen for the same mac/vlan/table (kernel v evpn),
the script informs the user which macs have inconsistent entries and which vtep
address is seen by each bundle for those macs.
"""

import sys
import os
import glob
import pprint
import argparse

SUPPORT_PREFIX = "/Support/"
DEVTYPE_GLOB = "/sys/class/net/*/uevent"
KERNEL_FDB_FILE = "bridge.fdb"
KERNEL_VLAN_FILE = "bridge.vlan"
ZEBRA_FDB_FILE = "evpn.mac.vni"
ZEBRA_VNI_FILE = "evpn.vni.detail"

ARGPARSE_DESCRIPTION="""\
This script will search multiple cl-support files for inconsistencies regarding
location (vtep address) of kernel/zebra macs. Optionally run with -m/-v to
filter for a specific mac/vni. Parses/compares all macs by default.
"""

# Allow for optional mac/vni arguments, but still 
# retrieve the list of bundles from a shell glob
parser = argparse.ArgumentParser(allow_abbrev=False,
                                 description=ARGPARSE_DESCRIPTION)
parser.add_argument("-m", "--mac",
                    help="search for specific mac. format must match output of \
                    'bridge fdb show'. must be used with -v/--vni")
parser.add_argument("-v", "--vni",
                    help="search for mac within this vni. supply vni in numeric\
                    format. must be used with -m/--mac")
parser.add_argument("bundles", nargs=argparse.REMAINDER)
args = parser.parse_args()

if (args.mac or args.vni) and not (args.mac and args.vni):
    print("--mac and --vni must be used together.")
    exit(1)

if len(args.bundles) < 2:
    print("Not enough cl-support directories provided. At least 2 required.")
    exit(1)


# Macs are significant by address & broadcast domain. Since vlan id is locally
# significant, we have to use vxlan id to identify the broadcast domain.
class Mac(object):
    def __init__(self, addr, vni):
        self.addr = addr
        self.vni = vni
    
    def __eq__(self, other):
        return(self.addr == other.addr and self.vni == other.vni)

    def __hash__(self):
        return(hash((self.addr, self.vni)))

    def __str__(self):
        return('{} VXLAN ID# {}'.format(self.addr, self.vni))


# final structure for kmacs/zmacs: {Mac: {vtep: [support_file]}}
kmacs = {}
zmacs = {}
num_support_dir = 0

# open files & read in list of macs
for support_file in args.bundles:
    if not os.path.isdir(support_file):
        print("%s is not a cl-support directory.. Skipping" % support_file)
        continue
    num_support_dir += 1
    try:
        with open(support_file + '/Support/' + ZEBRA_FDB_FILE, "r") as z_f:
            # per vni delimiter here is the string 'VNI'
            z_fdb = z_f.read().split('VNI')
        with open(support_file + '/Support/' + KERNEL_VLAN_FILE, "r") as k_v:
            # per bridge-port delimiter is an empty line
            k_vlan = k_v.read().split('\n\n')
        with open(support_file + '/Support/' + KERNEL_FDB_FILE, "r") as k_f:
            # there are no per mac delimiters, so we'll have to settle for
            # splitting into individual lines and disambiguating by vlan/vxlan
            k_fdb = k_f.read().splitlines()
        with open(support_file + '/Support/' + ZEBRA_VNI_FILE, "r") as z_v:
            # per vni delimiter in this file is an empty line
            z_vni = z_v.read().split('\n\n')
    except Exception as e:
        print("Failed to open %s: %s" % (e.filename, e.strerror))
        exit(1)

    vxlan_devs = []
    # iterate over all /sys/class/net/*/uevent files looking for DEVTYPE=vxlan
    for devtype_file in glob.glob(support_file + DEVTYPE_GLOB):
        vdev = devtype_file.split('/')[-2]
        try:
            with open(devtype_file, "r") as dtf:
                dt = dtf.readlines()
        except:
            print("Failed to open %s: %s" % (e.filename, e.strerror))
            exit(2)
        for dtl in dt:
            if 'DEVTYPE=vxlan' in dtl:
                vxlan_devs.append(vdev)

    vlan_to_vxlan = {}
    bports = []
    for k_bport in k_vlan:
        bport = None
        vlan = None
        # ignore comments, header and lines without the bridge-port
        if k_bport[0] == '#' or k_bport[0] == ' ' or 'vlan ids' in k_bport:
            continue
        bport = k_bport.split()[0]
        bports.append(bport)
        if bport not in vxlan_devs:
            continue
        else:
            vlan = k_bport.split()[1]
            vlan_to_vxlan[vlan] = bport

    vdev_to_vnid = {}
    vdev_to_local_vtep = {}
    vni_to_local_vtep = {}
    for z_vni_chunk in z_vni:
        z_vni_lines = z_vni_chunk.splitlines()
        # ignore final chunk containing only 'Completed' comment
        if len(z_vni_lines) < 2:
            continue
        vn_id = None
        vn_if = None
        l_vtep = None
        for line in z_vni_lines:
            if line.startswith('VNI:'):
                vn_id = line.split()[-1]
            # L2VNI iface string
            elif line.startswith(' VxLAN interface:'):
                vn_if = line.split()[-1]
            # L3VNI iface string
            elif line.startswith('  Vxlan-Intf:'):
                vn_if = line.split()[-1]
            # L2VNI local vtep string
            elif line.startswith(' Local VTEP IP:'):
                l_vtep = line.split()[-1]
            # L3VNI local vtep string
            elif line.startswith('  Local Vtep Ip:'):
                l_vtep = line.split()[-1]
        vdev_to_vnid[vn_if] = vn_id
        vdev_to_local_vtep[vn_if] = l_vtep
        vni_to_local_vtep[vn_id] = l_vtep

    k_vxlan_vlan= {}
    for k_e in k_fdb:
        mac = None
        dev = None
        vlan = None
        vtep = None
        vni_num = None
        loc_rem = None
        # skip comments, self macs, and flood entries
        if k_e[0] == '#' or 'perm' in k_e or '00:00:00:00:00:00' in k_e:
            continue
        mac = k_e.split()[0]
        dev = k_e.split()[2]
        if 'vlan' in k_e:
            vlan = k_e.split()[4]
            # if this vlan entry is for a vni, update the dict so the dst entry
            # can determine its vlan and update its vtep accordingly
            if dev in vxlan_devs:
                k_vxlan_vlan[dev] = vlan
                vni_num = vdev_to_vnid[dev]
            else: 
                # lookup vxlan dev for this vlan
                lookup_dev = vlan_to_vxlan.get(vlan)
                loc_rem = 'local'
                if lookup_dev:
                    # lookup local vtep addr for this vni
                    vtep = vdev_to_local_vtep.get(lookup_dev)
                    vni_num = vdev_to_vnid[lookup_dev]
        if 'dst' in k_e:
            vtep = k_e.split()[4]
            vlan = k_vxlan_vlan[dev]
            vni_num = vdev_to_vnid[dev]
            loc_rem = 'remote'
        km = Mac(mac, vni_num)
        existing_km = kmacs.get(km)
        if vtep:
            if not existing_km:
                kmacs[km] = {vtep: [[support_file, loc_rem]]}
            elif existing_km.get(vtep):
                existing_km[vtep].append([support_file, loc_rem])
            else:
                existing_km[vtep] = [[support_file, loc_rem]]

    for z_mac_chunk in z_fdb:
        vni = None
        mac = None
        location = None
        dev = None
        vtep = None
        # skip first commented chunk
        if z_mac_chunk[0] == '#':
            continue
        for z_mac_line in z_mac_chunk.splitlines():
            # skip anything that isn't a mac or the header with the VNI number
            # (empty lines, headers and final comment)
            if z_mac_line and 'Intf' not in z_mac_line and z_mac_line[0] != '#':
                z_mac_spl = z_mac_line.split()
                if '#MACs (local and remote)' in z_mac_line:
                    vni = z_mac_spl[0]
                else:
                    mac = z_mac_spl[0]
                    location = z_mac_spl[1]
                    if location == 'local':
                        dev = z_mac_spl[2]
                        if dev not in bports:
                            continue
                        vtep = vni_to_local_vtep[vni]
                    if location == 'remote':
                        vtep = z_mac_spl[2]
                zm = Mac(mac, vni)
                existing_zm = zmacs.get(zm)
                if not existing_zm:
                    zmacs[zm] = {vtep: [[support_file, location]]}
                else:
                    if existing_zm.get(vtep):
                        existing_zm[vtep].append([support_file, location])
                    else:
                        existing_zm[vtep] = [[support_file, location]]


# don't bother printing if we don't have more than 1 valid support bundle
if num_support_dir > 1:

    # if user is searching for one individual mac, grab results
    if args.mac and args.vni:
        search_mac = Mac(args.mac, args.vni)
        kresult = kmacs.get(search_mac)
        zresult = zmacs.get(search_mac)

    print("Kernel FDB Results:")
    print("===================")
    print("")
    if kresult and len(kresult) > 1:
        print("%s:" % (search_mac.__str__()))
        pprint.pprint(kresult)
        print('\n')
    else:
        for mac, vtep_to_bundle in kmacs.items():
            # if mac has multiple vteps
            if len(kmacs[mac]) > 1:
                print("%s:" % (mac.__str__()))
                pprint.pprint(vtep_to_bundle)
                print('\n')

    print("")
    print("Zebra MAC DB Results:")
    print("=====================")
    print("")
    if zresult and len(zresult) > 1:
        print("%s:" % (search_mac.__str__()))
        pprint.pprint(zresult)
        print('\n')
    else:
        for mac, vtep_to_bundle in zmacs.items():
            # if mac has multiple vteps
            if len(zmacs[mac]) > 1:
                print("%s:" % (mac.__str__()))
                pprint.pprint(vtep_to_bundle)
                print('\n')

else:
    print("Not enough cl-support directories provided. At least 2 required.")
    exit(1)
