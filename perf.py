import time
import json
import ssl
from elasticsearch import Elasticsearch

#Needs Python3 and elasticsearch

INDEX_NAME = "temp_index"
TYPE = "type1"

es = Elasticsearch(
    ['admin:admin@localhost:9200'],
    #connection_class=RequestsHttpConnection,
    use_ssl=True,
    verify_certs=False,
    #ca_certs='/usr/share/elasticsearch/config/chain-ca.pem',
    ssl_version=ssl.PROTOCOL_TLSv1_2,
    ssl_assert_hostname=False
    #client_key='/usr/share/elasticsearch/config/CN=picard,OU=client,O=client,L=Test,C=DE.key.pem'
    #client_cert='/usr/share/elasticsearch/config/CN=picard,OU=client,O=client,L=Test,C=DE.crtfull.pem',
    )

def generate_large_json():
    data = {i: i for i in range(0, 300000)}
    return json.dumps({"data": data})


def create_index_with_temp_data():
    large_json = generate_large_json()


    mapping = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },
        "mappings": {
            TYPE: {
                "properties": {
                    "data": {"type": "object",
                             "enabled": False}
                }
            }
        }
    }
    try:
        es.indices.delete(INDEX_NAME)
    except:
        print("No index to delete")
    es.indices.create(INDEX_NAME, body=mapping)
    es.index(INDEX_NAME, TYPE, large_json, id="data1")

create_index_with_temp_data()
start = time.time()
for i in range(10):
    es.get(INDEX_NAME, TYPE, "data1")
end = time.time()

total_time_ms = (end-start)*1000
print("total time = {}ms".format(total_time_ms))