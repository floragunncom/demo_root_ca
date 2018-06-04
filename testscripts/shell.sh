#!/bin/bash
set -e
#set -x

host=$(head -n 1 hosts)
echo "connect to $host"

ssh  "ubuntu@$host"


#pssh -h hosts -i -x -T --user ubuntu -I < update_conf.sh