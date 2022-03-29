#!/usr/bin/env python
"""
This script updates the Underlay SIP of the SDK
tunnel construct used for VXLAN encap.
"""

ERR_FILE_LOCATION = "/tmp/python_err_log.txt"

import errno
import os
import sys

sys.path.insert(1, "/usr/bin")

from python_sdk_api.sx_api import *
from test_infra_common import *
import argparse

parser = argparse.ArgumentParser(
    description="Update tunnel SIP using sx_api_tunnel_set"
)
parser.add_argument(
    "-t", dest="tunnel_id", default="0x8c00000", help="SDK Tunnel ID (hex)"
)
parser.add_argument("-s", dest="new_sip", default=None, help="New Tunnel SIP")
args = parser.parse_args()

tunnel_id = int(args.tunnel_id, 16)  # convert hex string -> int
new_sip = args.new_sip

file_exist = os.path.isfile(ERR_FILE_LOCATION)
sys.stderr = open(ERR_FILE_LOCATION, "w")
if not file_exist:
    os.chmod(ERR_FILE_LOCATION, 0o777)

old_stdout = redirect_stdout()
rc, handle = sx_api_open(None)
sys.stdout = os.fdopen(old_stdout, "w")
if rc != SX_STATUS_SUCCESS:
    print("Failed to open api handle.\nPlease check that SDK is running.")
    sys.exit(rc)

# return sx_tunnel_attribute_t*
tunnel_attr_p = new_sx_tunnel_attribute_t_p()

# sx_api_tunnel_get(const sx_api_handle_t handle,
#                   const sx_tunnel_id_t tunnel_id,
#                   sx_tunnel_attribute_t *tunnel_attr_p)
rc1 = sx_api_tunnel_get(handle, tunnel_id, tunnel_attr_p)
if rc1 != SX_STATUS_SUCCESS:
    print("####################################")
    print("# Failed to lookup tunnel Info rc(:%d)" % (rc))
    print("####################################")
    sys.exit(1)

# extract value from sx_tunnel_attribute_t*
tunnel_attr = sx_tunnel_attribute_t_p_value(tunnel_attr_p)

print("old sip: %s" % (ip_addr_to_str(tunnel_attr.attributes.vxlan.encap.underlay_sip)))
tunnel_attr.attributes.vxlan.encap.underlay_sip = make_sx_ip_addr_v4(new_sip)
print(
    "setting new sip: %s"
    % (ip_addr_to_str(tunnel_attr.attributes.vxlan.encap.underlay_sip))
)

# *tunnel_attr_p = tunnel_attr
sx_tunnel_attribute_t_p_assign(tunnel_attr_p, tunnel_attr)

# create and assign a pointer to the tunnel_id, because the 'set' method wants
# you to spend hours wondering why you're getting a TypeError while passing in
# the int instead of a pointer to the int :|
tunnel_id_p = new_sx_tunnel_id_t_p()

# *tunnel_id_p = tunnel_id
sx_tunnel_id_t_p_assign(tunnel_id_p, tunnel_id)

# sx_api_tunnel_set(const sx_api_handle_t handle,
#                   const sx_access_cmd_t cmd,
#                   const sx_tunnel_attribute_t *tunnel_attr_p,
#                   sx_tunnel_id_t *tunnel_id_p)
rc2 = sx_api_tunnel_set(handle, SX_ACCESS_CMD_EDIT, tunnel_attr, tunnel_id_p)
if rc2 != SX_STATUS_SUCCESS:
    print("#######################################")
    print("# Failed to update tunnel attrs rc(:%d)" % (rc2))
    print("#######################################")
    sys.exit(1)
print("done!")

sx_api_close(handle)
