#!/bin/bash
set -e
#set -x
sudo systemctl stop elasticsearch
sudo /usr/share/elasticsearch/bin/elasticsearch-plugin remove search-guard-6
sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install -b com.floragunn:search-guard-6:6.2.4-22.1
sudo systemctl start elasticsearch
#sudo journalctl -r -u elasticsearch
#sudo tail -n 200 /var/log/elasticsearch/default.log