#!/usr/bin/python3

import os.path
from sys import exit
import subprocess
import ipaddress
import re


def setup_parser(args):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("-a", "--asic",
        help="specify ASIC manufacturer. supported inputs: ['bcm'|'mlx']",
        choices=['bcm', 'mlx'],
        )
    parser.add_argument("-d", "--directory",
        help="base directory is searched for input files, e.g.\
	'base_dir/Support' or 'base_dir/support'", default="./",
        )
    parser.add_argument("-l", "--live",
        help="capture output from shell commands instead of cl-support",
        action="store_true",
        )
    parser.add_argument("-t", "--search_type",
        help="override detection of search type. \
        supported types: ['4'|'6'|'iface'|'mac']",
        choices=['4', '6', 'iface', 'mac'],
        )
    parser.add_argument("match", help="specify search string")
    return vars(parser.parse_args(args))


def get_k_neigh_file(is_live=False, base_dir='./'):
    if is_live:
        k_neigh_output = subprocess.run(
            "/bin/ip neigh show".split(),
            stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
    else:
        if os.path.exists(base_dir + "/Support/"):
            support_dir = base_dir + "/Support/"
        elif os.path.exists(base_dir + "/support/"):
            support_dir = base_dir + "/support/"
        else:
            print("Can't find {0}/Support/ or {0}/support/".format(base_dir))
            #############################
            # find better way to return an error and gracefully end the program
            #############################
            exit(2)
        with open(support_dir + "ip.neigh") as f:
            k_neigh_output = f.read().splitlines()
    return k_neigh_output


def get_k_neigh_entries(k_neigh_lines):
    k_neigh_entries = []
    for line in k_neigh_lines:
        if line[0] == '#':
            continue
        k_neigh_entry = {}
        k_neigh_ip = line.split()[0]
        k_neigh_dev = line.split()[2]
        k_neigh_status = line.split()[-1]
        if k_neigh_status == "FAILED" or k_neigh_status == "INCOMPLETE":
            k_neigh_mac = None
        else:
            k_neigh_mac = line.split()[4]
        k_neigh_entry.update({
            'ip': k_neigh_ip,
            'mac': k_neigh_mac,
            'iface': k_neigh_dev,
            'status': k_neigh_status,
            })
        k_neigh_entries.append(k_neigh_entry)
    return k_neigh_entries


def get_bcm_neigh_files(s_type, is_live, base_dir='./'):
    if is_live:
        if s_type == '4':
            bcm_neigh_output = subprocess.run(
                "/usr/lib/cumulus/bcmcmd l3 l3table show".split(),
                stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()

        elif s_type == '6':
            bcm_neigh_output = subprocess.run(
                "/usr/lib/cumulus/bcmcmd l3 ip6host show".split(),
                stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()

        else:
            bcm_l3_l3table_output = subprocess.run(
                "/usr/lib/cumulus/bcmcmd l3 l3table show".split(),
                stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
            bcm_l3_ip6host_output = subprocess.run(
                "/usr/lib/cumulus/bcmcmd l3 ip6host show".split(),
                stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
            bcm_neigh_output = bcm_l3_l3table_output + bcm_l3_ip6host_output

        bcm_l3_egress_output = subprocess.run(
            "/usr/lib/cumulus/bcmcmd l3 egress show".split(),
            stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
        portmap_output = subprocess.run(
            "/usr/lib/cumulus/portmap".split(),
            stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
        portstat_output = subprocess.run(
            "/usr/lib/cumulus/bcmcmd portstat".split(),
            stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
        ip_link_output = subprocess.run(
            "/bin/ip link show".split(),
            stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()

        # enable switchd debug to collect kernel/hw mapping
        subprocess.run("echo 1 > /cumulus/switchd/ctrl/debug", shell=True)
        bcm_switchd_l3_intf_output = subprocess.run(
            "cat /cumulus/switchd/debug/l3_intf/info".split(),
            stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
        # disable switchd debug after collecting kernel/hw mapping
        subprocess.run("echo 0 > /cumulus/switchd/ctrl/debug", shell=True)

    else:
        if os.path.exists(base_dir + "/Support/"):
            support_dir = base_dir + "/Support/"

        elif os.path.exists(base_dir + "/support/"):
            support_dir = base_dir + "/support/"

        else:
            print("Can't find {0}Support/ or {0}support/".format(base_dir))
            #############################
            # find better way to return an error and gracefully end the program
            #############################
            exit(2)

        if s_type == '4':
            with open(support_dir + "l3.l3table.show") as l3_l3table:
                bcm_neigh_output = l3_l3table.read().splitlines()

        elif s_type == '6':
            with open(support_dir + "l3.ip6host.show") as l3_ip6host:
                bcm_neigh_output = l3_ip6host.read().splitlines()

        else:
            with open(support_dir + "l3.l3table.show") as l3_l3table:
                bcm_l3_l3table_output = l3_l3table.read().splitlines()
            with open(support_dir + "l3.ip6host.show") as l3_ip6host:
                bcm_l3_ip6host_output = l3_ip6host.read().splitlines()
            bcm_neigh_output = bcm_l3_l3table_output + bcm_l3_ip6host_output

        with open(support_dir + "l3.egress.show") as l3_egress:
            bcm_l3_egress_output = l3_egress.read().splitlines()
        with open(base_dir + "/cumulus/switchd/debug/l3_intf/info") as port:
            bcm_switchd_l3_intf_output = port.read().splitlines()
        with open(support_dir + "portmap") as pm:
            portmap_output = pm.read().splitlines()
        with open(support_dir + "portstat") as ps:
            portstat_output = ps.read().splitlines()
        with open(support_dir + "ip.link") as ipl:
            ip_link_output = ipl.read().splitlines()

    return [
    bcm_neigh_output,
    bcm_l3_egress_output,
    bcm_switchd_l3_intf_output,
    portstat_output,
    portmap_output,
    ip_link_output,
    ]


def get_bcm_neigh_entries(bcm_return):
    bcm_neigh_lines = bcm_return[0]
    bcm_l3_egress_lines = bcm_return[1]
    bcm_switchd_l3_intf_lines = bcm_return[2]
    portstat_lines = bcm_return[3]
    portmap_lines = bcm_return[4]
    ip_link_lines = bcm_return[5]

    bcm_neigh_table = []
    for i in bcm_neigh_lines:
        if i and i[0].isnumeric():
            i = i.split()
            bcm_neigh_ip = i[2]
            bcm_neigh_egr_id = i[4]
            bcm_neigh_status = i[8]
            bcm_neigh_entry = {
                'ip': bcm_neigh_ip,
                'egress_id': bcm_neigh_egr_id,
                'status': bcm_neigh_status,
            }
            bcm_neigh_table.append(bcm_neigh_entry)

    bcm_egress = {}
    for i in bcm_l3_egress_lines:
        if i[0].isnumeric():
            i = i.split()
            egress_id, dmac, vlan, l3_intf, port = i[:5]
            egress_details = {
                'dmac': dmac,
                'vlan': vlan,
                'l3_intf': l3_intf,
                # port may be used in the future to get neigh gport
                'port': port, }
            bcm_egress[egress_id] = egress_details

    bcm_switchd_l3_intf = {}
    for i in bcm_switchd_l3_intf_lines:
        if '======' in i or 'IF key' in i:
            continue
        else:
            # sometimes an 'i' or '*' will appear before the IF Key.
            # remove this so we can consistently index values from the line
            i = i[3:].split()
            l3_id = i[-6]
            gport = i[-7]
            intf_type = i[0][:-1]

            if intf_type == 'PORT':
                port = i[2][:-1]
                ovid = i[4].split('.')[0]
                ivid = i[4].split('.')[1]
                vlan = None
                brid = None
            elif intf_type == 'SVI':
                port = None
                ovid = None
                ivid = None
                vlan = i[1]
                brid = i[-8]
            elif intf_type == 'BRIDGE':
                port = None
                ovid = None
                ivid = None
                vlan = None
                brid = i[-8]
            elif intf_type == 'BOND':
                port = None
                ovid = i[4].split('.')[0]
                ivid = i[4].split('.')[1]
                vlan = None
                brid = i[-8]

            bcm_switchd_l3_intf_entry = {
                'l3_id': l3_id,
                'gport': gport,
                'type': intf_type,
                'port': port,
                'ovid': ovid,
                'ivid': ivid,
                'vlan': vlan,
                'br_id': brid,
            }

            bcm_switchd_l3_intf[l3_id] = bcm_switchd_l3_intf_entry

    bcm_portstat = {}
    for i in portstat_lines:
        if i[0] == '#' or 'speed/ link' in i or 'duplex scan neg?' in i:
            continue
        else:
            i = i.split()
            bcm_port = i[0][:-1]
            bcm_log_port = i[1][:-1]
            bcm_portstat[bcm_log_port] = bcm_port

    bcm_portmap = {}
    for i in portmap_lines:
        if i and i[0] != '#':
            i = i.split()
            linux_intf = i[0]
            sdk_intf = i[1]
            bcm_portmap[sdk_intf] = linux_intf

    ip_link = {}
    for i in ip_link_lines:
        if i[0].isnumeric():
            i = i.split()
            ifindex = i[0][:-1]
            kern_if = i[1][:-1]
            ip_link[ifindex] = kern_if


    bcm_neigh_entries = [] 
    for neigh_details in bcm_neigh_table:
        bcm_neigh_entry = {}
        egress_entry = bcm_egress[neigh_details['egress_id']]

        if egress_entry['dmac'] == '00:00:00:00:00:00':
            hw_specific_dict = {
                'l3_intf': egress_entry['l3_intf'],
            }
            bcm_neigh_entry.update({
                'ip': neigh_details['ip'],
                'mac': egress_entry['dmac'],
                'kernel_iface': None,
                'status': 'Punt',
                'hw_specific': hw_specific_dict
            })
        else:
            intf_info = bcm_switchd_l3_intf[egress_entry['l3_intf']]
            if intf_info['type'] == 'PORT':
                bcm_lport = intf_info['port']
                bcm_phy_port = bcm_portstat[bcm_lport]
                k_if = '"' + bcm_portmap[bcm_phy_port] + '"'
                hw_specific_dict = {
                    'l3_intf_type': intf_info['type'],
                    'l3_intf': egress_entry['l3_intf'],
                    'logical_port': bcm_lport,
                    'phy_port': bcm_phy_port,
                },
            elif intf_info['type'] == 'SVI':
                bridge = ip_link[intf_info['br_id']]
                vlan = intf_info['vlan']
                k_if = '"%s" -- vlan %s' % (bridge, vlan)
                hw_specific_dict = {
                    'l3_intf_type': intf_info['type'],
                    'l3_intf': egress_entry['l3_intf'],
                    'l3_intf_vlan': vlan,
                    'l3_intf_br_id': intf_info['br_id'],
                }
            elif intf_info['type'] == 'BRIDGE':
                bridge = ip_link[intf_info['br_id']]
                k_if = '"' + bridge + '"'
                hw_specific_dict = {
                    'l3_intf_type': intf_info['type'],
                    'l3_intf': egress_entry['l3_intf'],
                    'l3_intf_br_id': intf_info['br_id'],
                }

            bcm_neigh_entry.update({
                'ip': neigh_details['ip'],
                'mac': egress_entry['dmac'],
                'kernel_iface': k_if,
                'status': neigh_details['status'],
                'hw_specific': hw_specific_dict
            })
        bcm_neigh_entries.append(bcm_neigh_entry)
    return bcm_neigh_entries


def get_mlx_neigh_files(parse_type, live, base_dir='./'):
    if live:
        if parse_type == '4':
            mlx_neigh_output = subprocess.run(
                "/usr/lib/cumulus/mlxcmd l3 neighbor".split(),
                stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()

        elif parse_type == '6':
            mlx_neigh_output = subprocess.run(
                "/usr/lib/cumulus/mlxcmd l3 neighbor6".split(),
                stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()

        else:
            mlx_v4_neigh_output = subprocess.run(
                "/usr/lib/cumulus/mlxcmd l3 neighbor".split(),
                stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
            mlx_v6_neigh_output = subprocess.run(
                "/usr/lib/cumulus/mlxcmd l3 neighbor6".split(),
                stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
            mlx_neigh_output = mlx_v4_neigh_output + mlx_v6_neigh_output

        mlx_l3_intf_output = subprocess.run(
            "/usr/lib/cumulus/mlxcmd l3 interface".split(),
            stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()

        # enable switchd debug to collect vport info
        subprocess.run("echo 1 > /cumulus/switchd/ctrl/debug", shell=True)
        mlx_switchd_l3_intf_output = subprocess.run(
            "cat /cumulus/switchd/debug/l3_intf/info".split(),
            stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
        # disable switchd debug after collecting vport info
        subprocess.run("echo 0 > /cumulus/switchd/ctrl/debug", shell=True)

    else:
        if os.path.exists(base_dir + "/Support/"):
            support_dir = base_dir + "/Support/"

        elif os.path.exists(base_dir + "/support/"):
            support_dir = base_dir + "/support/"

        else:
            print("Can't find {0}Support/ or {0}support/".format(base_dir))
            #############################
            # find better way to return an error and gracefully end the program
            #############################
            exit(2)

        if parse_type == '4':
            with open(support_dir + "l3.neigh.show") as mlx_v4:
                mlx_neigh_output = mlx_v4.read().splitlines()

        elif parse_type == '6':
            with open(support_dir + "l3.neigh6.show") as mlx_v6:
                mlx_neigh_output = mlx_v6.read().splitlines()

        else:
            with open(support_dir + "l3.neigh.show") as mlx_v4:
                mlx_v4_neigh_output = mlx_v4.read().splitlines()
            with open(support_dir + "l3.neigh6.show") as mlx_v6:
                mlx_v6_neigh_output = mlx_v6.read().splitlines()
            mlx_neigh_output = mlx_v4_neigh_output + mlx_v6_neigh_output

        with open(support_dir + "l3.interface.show") as l3_intf:
            mlx_l3_intf_output = l3_intf.read().splitlines()
        with open(base_dir + "/cumulus/switchd/debug/l3_intf/info") as intf:
            mlx_switchd_l3_intf_output = intf.read().splitlines()

    return [
        mlx_neigh_output,
        mlx_l3_intf_output,
        mlx_switchd_l3_intf_output,
        ]


def get_mlx_neigh_entries(mlx_return):
    mlx_neigh_lines = mlx_return[0]
    mlx_l3_intf_lines = mlx_return[1]
    mlx_switchd_l3_intf_lines = mlx_return[2]

    mlx_neigh_entries = []

    mlx_neigh_table = []
    for i in mlx_neigh_lines:
        if i and i[0].isnumeric():
            i = i.split()
            mlx_neigh_ip = i[1]
            mlx_neigh_dmac = i[2]
            mlx_neigh_status = i[3]
            mlx_neigh_rif = i[5]
            mlx_neigh_entry = {
                'ip': mlx_neigh_ip,
                'dmac': mlx_neigh_dmac,
                'status': mlx_neigh_status,
                'rif': mlx_neigh_rif,
            }
            mlx_neigh_table.append(mlx_neigh_entry)

    mlx_l3_interface = {}
    for i in mlx_l3_intf_lines:
        if i and i[0].isnumeric():
            i = i.split()
            intf_rif = i[0]
            intf_type = i[1]
            intf_vport = i[7]
            intf_bridge_id = i[8]
            mlx_l3_intf_entry = {
                'rif': intf_rif,
                'type': intf_type,
                'vport': intf_vport,
                'bridge_id': intf_bridge_id,
            }
            mlx_l3_interface[intf_rif] = mlx_l3_intf_entry

    mlx_switchd_l3_intf = {}
    for i in mlx_switchd_l3_intf_lines:
        if i and i[0].isnumeric():
            i = i.split()
            switchd_rif = i[0]
            switchd_vrid = i[1]
            switchd_table_id = i[2]
            switchd_rif_type = i[3]

            if switchd_rif_type == 'vlan':
                switchd_vid = i[4]
                switchd_vport_hex = None
                switchd_kernel_iface = '"' + 'vlan' + switchd_vid + '"'
            elif switchd_rif_type == 'vport':
                switchd_vid = None
                switchd_vport_hex = i[4]
                switchd_kernel_iface = '"' + i[5][1:-1] + '"'

            mlx_switchd_l3_intf_entry = {
                'rif': switchd_rif,
                'vrid': switchd_vrid,
                'table_id': switchd_table_id,
                'type': switchd_rif_type,
                'vid': switchd_vid,
                'kernel_iface': switchd_kernel_iface,
                'vport_hex': switchd_vport_hex,
            }
            mlx_switchd_l3_intf[switchd_rif] = mlx_switchd_l3_intf_entry

    for neigh_details in mlx_neigh_table:
        mlx_neigh_entry = {}
        l3_intf_details = mlx_switchd_l3_intf[neigh_details['rif']]
        mlx_neigh_entry.update({
            'ip': neigh_details['ip'],
            'mac': neigh_details['dmac'],
            'kernel_iface': l3_intf_details['kernel_iface'],
            'status': neigh_details['status'],
            'hw_specific': {
                'RIF': neigh_details['rif'],
                'RIF_type': l3_intf_details['type'],
                'table_id': l3_intf_details['table_id'],
            }
        })
        mlx_neigh_entries.append(mlx_neigh_entry)
    return mlx_neigh_entries


def detect_type(search):
    MAC_REGEX = "[0-9a-fA-F]{2}([-:]?)[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}$"
    try:
        # returns int [4|6] if ip is valid, otherwise raises a ValueError
        search_t = str(ipaddress.ip_address(search).version)
    except ValueError:
        if re.match(MAC_REGEX, search):
            search_t = 'mac'
        else:
            search_t = 'iface'
    return(search_t)


def parse_k_neighs(match, k_neighs, match_type):
    k_matches = []
    k_count = 0
    for i in k_neighs:
        if match_type.isnumeric():
            if match_type == '4':
                if match == i['ip']:
                    k_matches.append(i)
                    k_count += 1
            elif match_type == '6':
                if match == i['ip']:
                    k_matches.append(i)
                    k_count += 1
        elif match_type == 'mac':
            if match == i['mac']:
                k_matches.append(i)
                k_count += 1
        elif match_type == 'iface':
            if match == i['iface']:
                k_matches.append(i)
                k_count += 1

    print("Found %s kernel entries matching search '%s':" % (k_count, match))
    print("================================================")
    for i in k_matches:
        print('Kernel neigh entry:')
        print('IP: %s' % (i['ip']))
        print('  MAC: %s' % (i['mac']))
        print('  Dev: "%s"' % (i['iface']))
        print('  Status: %s\n' % (i['status']))


def parse_hw_neighs(match, hw_neighs, match_type, asic):
    hw_matches = []
    hw_match_count = 0
    for i in hw_neighs:
        if match_type.isnumeric():
            if match_type == '4':
                if match == i['ip']:
                    hw_matches.append(i)
                    hw_match_count += 1
            if match_type == '6':
                try:
                    search = ipaddress.ip_address(match).exploded
                    if i['ip'] == search:
                        hw_matches.append(i)
                        hw_match_count += 1
                except ValueError as e:
                    print('')
                    print(e + '\n======================')
                    print(match + " doesn't appear to be an IPv6 address")
                    ###############################
                    # TODO: find better way to exit
                    ###############################
                    exit(4)
        elif match_type == 'mac':
            if match == i['mac']:
                hw_matches.append(i)
                hw_match_count += 1
        elif match_type is 'iface':
            if match == i['kernel_iface']:
                hw_matches.append(i)
                hw_match_count += 1

    if hw_matches:
        print("\nFound %s %s hardware entries matching search '%s':" % (
            hw_match_count,
            asic.upper(),
            match)
        )
        print("================================================")
        for i in hw_matches:
            print('%s neigh entry:' % (asic.upper()))
            print('IP: %s' % (i['ip']))
            print('  MAC: %s' % (i['mac']))
            print('  Dev: %s' % (i['kernel_iface']))
            print('  Status: %s' % (i['status']))
            print('  hw_specific: %s\n' % (i['hw_specific']))
    else:
        print("No matches for %s found in hardware." % (match))


def main(args):
    kwargs = setup_parser(args)
    if not kwargs['search_type']:
        kwargs['search_type'] = detect_type(kwargs['match'])

    kern_file = get_k_neigh_file(
        kwargs['live'],
        kwargs['directory'],
        )
    kern_neighs = get_k_neigh_entries(kern_file)
    parse_k_neighs(
        kwargs['match'],
        kern_neighs,
        kwargs['search_type'],
	)

    if kwargs['asic']:
        if kwargs['asic'] != 'bcm' and kwargs['asic'] !='mlx':
            print("Unsupported ASIC type.")
            exit(5)
        if kwargs['asic'] == 'bcm':
            bcm_neigh_files = get_bcm_neigh_files(
                kwargs['search_type'],
                kwargs['live'],
                kwargs['directory'],
                )
            hw_neighs = get_bcm_neigh_entries(bcm_neigh_files)
        elif kwargs['asic'] == 'mlx':
            mlx_neigh_files = get_mlx_neigh_files(
                kwargs['search_type'],
                kwargs['live'],
                kwargs['directory'],
                )
            hw_neighs = get_mlx_neigh_entries(mlx_neigh_files)
        parse_hw_neighs(
        kwargs['match'],
        hw_neighs,
        kwargs['search_type'],
        kwargs['asic'],
	)


if __name__ == '__main__':
    import argparse
    from sys import argv
    try:
        main(argv[1:])
    except KeyboardInterrupt:
        exit(1)
