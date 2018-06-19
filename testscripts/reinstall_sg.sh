#!/bin/bash
set -e
#set -x
sudo systemctl stop elasticsearch
sudo /usr/share/elasticsearch/bin/elasticsearch-plugin remove search-guard-6
#sudo sed -i '/searchguard/d' /etc/elasticsearch/elasticsearch.yml
#sudo sed -i '/.*sgadmin.*/d' /etc/elasticsearch/elasticsearch.yml

sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install -b https://oss.sonatype.org/content/repositories/snapshots/com/floragunn/search-guard-6/6.x-HEAD-SNAPSHOT/search-guard-6-6.x-HEAD-20180606.214512-1580.zip

#sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install -b com.floragunn:search-guard-6:6.2.4-22.1
sudo systemctl start elasticsearch
sudo journalctl -r -u elasticsearch
sudo tail -n 200 /var/log/elasticsearch/default.log

#pssh -h hosts -i -x -T --user ubuntu -I < reinstall_sg.sh