#!/bin/bash

host=$(head -n 1 hosts)

curl -Ssk "http://$host:9200"/_cat/health?v -u admin:admin
curl -Ssk "http://$host:9200"/_cat/nodes?v -u admin:admin
curl -Ssk "http://$host:9200"/_cat/indices?v -u admin:admin
curl -Ssk "http://$host:9200"/_cluster/allocation/explain?pretty -u admin:admin
curl -Ssk "http://$host:9200"/_cluster/health?pretty -u admin:admin
curl -Ssk "http://$host:9200/_nodes/hot_threads?human=true" -u admin:admin


curl -Ssk "https://$host:9200"/_cat/health?v -u admin:admin
curl -Ssk "https://$host:9200"/_cat/nodes?v -u admin:admin
curl -Ssk "https://$host:9200"/_cat/indices?v -u admin:admin
curl -Ssk "https://$host:9200"/_cluster/allocation/explain?pretty -u admin:admin
curl -Ssk "https://$host:9200"/_cluster/health?pretty -u admin:admin
curl -Ssk "https://$host:9200/_nodes/hot_threads?human=true" -u admin:admin




#pssh -h hosts -i -x -T --user ubuntu -I < update_conf.sh
