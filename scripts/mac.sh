#!/bin/bash

ACTION="$1"
BRPORT="$2"
VLAN="$3"
MACFILE="$4"

for MAC in $(/bin/cat $MACFILE); do
     /sbin/bridge fdb $ACTION $MAC dev $BRPORT vlan $VLAN master static
done
