#!/bin/bash

ACTION="$1"
BRPORT="$2"
VLAN="$3"
STICKY_FLAG="$4"
MACFILE="$5"

for MAC in $(/bin/cat $MACFILE); do
     /sbin/bridge fdb $ACTION $MAC dev $BRPORT vlan $VLAN master $STICKY_FLAG
done
date -u
