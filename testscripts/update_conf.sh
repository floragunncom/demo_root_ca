#!/bin/bash
set -e
#set -x

sudo systemctl stop elasticsearch
#sudo sed -i '/searchguard.audit.type/d' /etc/elasticsearch/elasticsearch.yml
sudo sed -i '/searchguard.disabled/d' /etc/elasticsearch/elasticsearch.yml
#echo "searchguard.audit.type: noop" | sudo tee --append /etc/elasticsearch/elasticsearch.yml
echo "searchguard.disabled: true" | sudo tee --append /etc/elasticsearch/elasticsearch.yml
cat /etc/elasticsearch/elasticsearch.yml
sudo systemctl start elasticsearch
sudo journalctl -r -u elasticsearch
#sudo tail -n 200 /var/log/elasticsearch/default.log

#pssh -h hosts -i -x -T --user ubuntu -I < update_conf.sh