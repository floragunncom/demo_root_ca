#!/bin/bash

export host=$(head -n 1 hosts)

curl -Ssk "http://$host:9200"/_cat/health?v -u admin:admin
curl -Ssk "http://$host:9200"/_cat/nodes?v -u admin:admin
curl -Ssk "http://$host:9200"/_cat/indices?v -u admin:admin
curl -Ssk "http://$host:9200"/_cluster/allocation/explain?pretty -u admin:admin
curl -Ssk "http://$host:9200"/_cluster/health?pretty -u admin:admin
curl -Ssk "http://$host:9200/_nodes/hot_threads?human=true" -u admin:admin
curl -Ssk "http://$host:9200/_cat/segments?v" -u admin:admin
curl -Ssk "http://$host:9200/_cat/fielddata?v" -u admin:admin

curl -Ssk "https://$host:9200"/_cat/health?v -u admin:admin
curl -Ssk "https://$host:9200"/_cat/nodes?v -u admin:admin
curl -Ssk "https://$host:9200"/_cat/indices?v -u admin:admin
curl -Ssk "https://$host:9200"/_cluster/allocation/explain?pretty -u admin:admin
curl -Ssk "https://$host:9200"/_cluster/health?pretty -u admin:admin
curl -Ssk "https://$host:9200/_nodes/hot_threads?human=true" -u admin:admin
curl -Ssk "https://$host:9200/_searchguard/license?pretty" -u admin:admin
curl -Ssk "https://$host:9200/_searchguard/kibanainfo?pretty" -u admin:admin
curl -Ssk "https://$host:9200/_cat/segments?v" -u admin:admin
curl -Ssk "https://$host:9200/_cat/fielddata?v" -u admin:admin

_cat/nodes?v&h=id,queryCacheMemory,queryCacheEvictions,requestCacheMemory,requestCacheHitCount,requestCacheMissCount,flushTotal,flushTotalTime


#pssh -h hosts -i -x -T --user ubuntu -I < update_conf.sh
