#!/bin/bash
#set -x

post_slack() {
   curl -X POST --data-urlencode 'payload={"channel": "#aws_notify", "username": "awsbot", "text": "'"$1"'", "icon_emoji": ":cyclone:"}' $SLACKURL > /dev/null 2>&1
}

do_install() {

  mkfs -t ext4 -V /dev/xvdb
  mount /dev/xvdb /mnt -o defaults,noatime,nodiratime,discard
  #echo noop | tee /sys/block/xvdb/queue/scheduler
  
  export REGION=$(wget -qO- http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//' | tr -d '"')
  export STACKNAME=$(aws ec2 describe-instances --filters "Name=ip-address,Values=$(ec2metadata --public-ipv4)" --region $REGION | jq '.Reservations[0].Instances[0].Tags | map(select (.Key == "aws:cloudformation:stack-name" )) ' | jq .[0].Value | tr -d '"')
  export SG_PUBHOST=$(curl -s http://169.254.169.254/latest/meta-data/public-hostname)
  export SG_PRIVHOST=$(curl -s http://169.254.169.254/latest/meta-data/hostname)
  dolog "Will bootstrap $STACKNAME in $REGION on $SG_PUBHOST ($DIST) no SG"
  
  #GITHUB_URL="$(aws cloudformation describe-stacks --stack-name $STACKNAME  --region $REGION | jq '.Stacks[0].Parameters | map(select (.ParameterKey == "GithubUrl" ))[0].ParameterValue' | tr -d '"' )"
  
  echo "Stopping services"
  
  systemctl stop kibana.service > /dev/null 2>&1
  systemctl stop metricbeat.service > /dev/null 2>&1
  systemctl stop elasticsearch.service > /dev/null 2>&1
  
  dolog "Install packages"
  
  apt install -yqq python3-pip
  pip3 install esrally
  pip3 install requests ndg-httpsclient --upgrade
  #pip3 install elasticsearch requests cryptography pyopenssl ndg-httpsclient pyasn1
  #esrally --track=logging --pipeline=benchmark-only --target-hosts=10.0.0.6:9200,10.0.0.7:9200,10.0.0.8:9200 --client-options "use_ssl:true,verify_certs:False,basic_auth_user:'admin',basic_auth_password:'admin'"

  #ssl_openssl_supports_key_manager_factory":false,"ssl_openssl_supports_hostname_validation":false

  ES_VERSION=5.5.1
  
  if [ ! -f "elasticsearch-$ES_VERSION.deb" ]; then
    wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ES_VERSION.deb > /dev/null 2>&1
    check_ret "Downloading ES"
  fi
  
  dpkg --force-all -i elasticsearch-$ES_VERSION.deb > /dev/null 2>&1
  check_ret "Installing ES"
  
  wget https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-$ES_VERSION-amd64.deb > /dev/null 2>&1
  check_ret "Downloading Metricbeat"
  
  dpkg --force-all -i metricbeat-$ES_VERSION-amd64.deb > /dev/null 2>&1
  check_ret "Installing Metricbeat"
  
  wget https://artifacts.elastic.co/downloads/kibana/kibana-$ES_VERSION-amd64.deb > /dev/null 2>&1
  check_ret "Downloading Kibana"
  
  dpkg --force-all -i kibana-$ES_VERSION-amd64.deb > /dev/null 2>&1
  check_ret "Installing Kibana"
  
  sed -i -e 's/-Xmx2g/-Xmx30g/g' /etc/elasticsearch/jvm.options
  sed -i -e 's/-Xms2g/-Xms30g/g' /etc/elasticsearch/jvm.options
  check_ret "xmx sed"
  
  export ES_BIN=/usr/share/elasticsearch/bin
  export ES_CONF=/etc/elasticsearch
  export ES_LOG=/var/log/elasticsearch
  export ES_PLUGINS=/usr/share/elasticsearch/plugins
  
  echo "SG_PUBHOST: $SG_PUBHOST"
  echo "SG_PRIVHOST: $SG_PRIVHOST"
  
  $ES_BIN/elasticsearch-plugin remove discovery-ec2 > /dev/null 2>&1
  $ES_BIN/elasticsearch-plugin remove x-pack > /dev/null 2>&1
  
  $ES_BIN/elasticsearch-plugin install -b discovery-ec2 > /dev/null 
  check_ret "Installing discovery-ec2 plugin"
  $ES_BIN/elasticsearch-plugin install -b x-pack > /dev/null 
  check_ret "Installing xpack plugin"
  
  cd /demo_root_ca
  git pull > /dev/null 2>&1
  
  #chown -R elasticsearch:elasticsearch $ES_CONF
  chown -R elasticsearch:elasticsearch $ES_CONF
  
  chmod -R 755 $ES_CONF
  
  cd - > /dev/null 2>&1

  #dns seems to be broken on aws currently, so we need to disable hostname verification
  echo "cluster.name: $STACKNAME" > $ES_CONF/elasticsearch.yml
  echo "discovery.zen.hosts_provider: ec2" >> $ES_CONF/elasticsearch.yml
  echo "discovery.type: ec2" >> $ES_CONF/elasticsearch.yml
  echo "discovery.ec2.host_type: private_dns" >> $ES_CONF/elasticsearch.yml
  echo "cloud.aws.protocol: http" >> $ES_CONF/elasticsearch.yml
  #echo 'network.host: ["_ec2:publicDns_"]' >> $ES_CONF/elasticsearch.yml
  echo "network.host: _ec2:privateDns_" >> $ES_CONF/elasticsearch.yml
  echo "transport.host: _ec2:privateDns_" >> $ES_CONF/elasticsearch.yml
  echo "transport.tcp.port: 9300" >> $ES_CONF/elasticsearch.yml
  
  echo "http.host: _ec2:publicDns_" >> $ES_CONF/elasticsearch.yml
  echo "http.port: 9200" >> $ES_CONF/elasticsearch.yml
  echo "http.cors.enabled: true" >> $ES_CONF/elasticsearch.yml
  echo 'http.cors.allow-origin: "*"' >> $ES_CONF/elasticsearch.yml
  echo "cloud.aws.region: $REGION" >> $ES_CONF/elasticsearch.yml
  
  echo "cluster.routing.allocation.disk.watermark.high: 10mb" >> $ES_CONF/elasticsearch.yml
  echo "cluster.routing.allocation.disk.watermark.low: 10mb" >> $ES_CONF/elasticsearch.yml
  echo "node.name: $SG_PUBHOST" >> $ES_CONF/elasticsearch.yml
  echo "bootstrap.memory_lock: true" >> $ES_CONF/elasticsearch.yml
  echo "xpack.security.enabled: false" >> $ES_CONF/elasticsearch.yml
  echo "xpack.watcher.enabled: false" >> $ES_CONF/elasticsearch.yml
  echo "xpack.monitoring.enabled: true" >> $ES_CONF/elasticsearch.yml
  echo "xpack.ml.enabled: false" >> $ES_CONF/elasticsearch.yml
  echo "" >> $ES_CONF/elasticsearch.yml
  echo "" >> $ES_CONF/elasticsearch.yml
  echo "" >> $ES_CONF/elasticsearch.yml
  echo "" >> $ES_CONF/elasticsearch.yml
  
  echo "path.data: /mnt/esdata">> $ES_CONF/elasticsearch.yml
  
  mkdir -p /mnt/esdata
  chown -R elasticsearch:elasticsearch /mnt/esdata

  echo "vm.max_map_count=262144" >> /etc/sysctl.conf
  echo 262144 > /proc/sys/vm/max_map_count 
  
  mkdir -p /etc/systemd/system/elasticsearch.service.d
  echo "[Service]" > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf
  echo "LimitMEMLOCK=infinity" >> /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf
  echo "LimitNOFILE=1000000" >> /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf
  
  echo "MAX_LOCKED_MEMORY=unlimited" >> /etc/default/elasticsearch
  echo "MAX_OPEN_FILES=1000000" >> /etc/default/elasticsearch
  echo "MAX_MAP_COUNT=262144"  >> /etc/default/elasticsearch
  
  echo "elasticsearch  -  nofile  1000000" >> /etc/security/limits.conf
    
  /bin/systemctl daemon-reload
  check_ret "daemon-reload"
  /bin/systemctl enable elasticsearch.service
  check_ret "enable elasticsearch.service"
  systemctl start elasticsearch.service
  check_ret "start elasticsearch.service"
  
  while ! nc -z $SG_PUBHOST 9200 > /dev/null 2>&1; do
    dolog "Wait for elasticsearch ..."
    sleep 5
  done
  
  echo "elasticsearch up"
  sleep 5
    
  curl -XPUT -k "http://$SG_PUBHOST:9200/twitter/tweet/1?pretty" -d'
  {
    "user" : "searchguard",
    "post_date" : "2013-11-15T14:12:12",
    "message" : "rockn roll"
  }'

  curl -XPUT -k "http://$SG_PUBHOST:9200/twitter1/tweet/1?pretty" -d'
  {
    "user" : "searchguard1",
    "post_date" : "2015-11-15T14:12:12",
    "message" : "rockn roll"
  }'
  
  dolog "Install Kibana"
  
  
  echo "server.host: RPLC_HOST" > /demo_root_ca/kibana/kibana.yml
  echo "elasticsearch.url: http://RPLC_HOST:9200"  >> /demo_root_ca/kibana/kibana.yml
  echo "xpack.security.enabled: false"  >> /demo_root_ca/kibana/kibana.yml
  echo "xpack.graph.enabled: false"  >> /demo_root_ca/kibana/kibana.yml
  echo "xpack.ml.enabled: false"  >> /demo_root_ca/kibana/kibana.yml
  echo "xpack.reporting.enabled: false"  >> /demo_root_ca/kibana/kibana.yml
  echo "xpack.monitoring.enabled: true"  >> /demo_root_ca/kibana/kibana.yml

  cat /demo_root_ca/kibana/kibana.yml | sed -e "s/RPLC_HOST/$SG_PUBHOST/g" > /etc/kibana/kibana.yml 
  /usr/share/kibana/bin/kibana-plugin install x-pack


  /bin/systemctl enable kibana.service
  check_ret
  systemctl start kibana.service  
  check_ret
  
cat >/demo_root_ca/metricbeat/metricbeat.yml <<EOL  
output.elasticsearch:
  hosts: ["RPLC_HOST"]

metricbeat.modules:
- module: system
  metricsets:
    - cpu
    - load
    - memory
    - process
  enabled: true
  period: 10s
  processes: ['.*']
EOL

  cat /demo_root_ca/metricbeat/metricbeat.yml | sed -e "s/RPLC_HOST/$SG_PUBHOST/g" > /etc/metricbeat/metricbeat.yml

  /bin/systemctl enable metricbeat.service
  check_ret
  systemctl start metricbeat.service
  check_ret
  
  dolog "Kibana $SG_VERSION running on http://$SG_PUBHOST:5601"
    
  curl -ksS "http://$SG_PUBHOST:9200/_cluster/health?pretty" > health
  check_ret "final curl 1"

  dolog "Cluster Health: $(cat health)"
  
}


show_info() {
  do_log "This script will bootstrap Search Guard $SG_VERSION"
  do_log "It is supposed to be run on an Ubuntu AWS instance"
  do_log "Detect OS: $DIST"
  do_log ""
}

do_log() {
  echo "$1" 1>&2
}

do_error_exit() {
  echo "ERR: $1" 1>&2
  post_slack "ERR: $1"
  exit 1
}

check_prerequisites() {

  if ! check_cmd apt-get; then
    do_error_exit "apt-get is not installed (not ubuntu?)"
  fi
  
  
  ########## start Oracle 8 Java 
  apt-get -yqq update > /dev/null 2>&1
  echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections > /dev/null 2>&1
  apt-get -yqq install software-properties-common > /dev/null 2>&1
  add-apt-repository -y ppa:webupd8team/java > /dev/null 2>&1
  apt-get -yqq update > /dev/null 2>&1
  apt-get -yqq install oracle-java8-installer oracle-java8-unlimited-jce-policy > /dev/null 2>&1
  ########## end Oracle 8 Java

  apt-get -yqq install ntp ntpdate haveged libssl-dev autoconf libtool build-essential libffi6 libffi-dev git curl wget openssl libapr1 iputils-ping dnsutils host netcat telnet > /dev/null 2>&1
  apt-get -yqq install unzip awscli docker.io curl git jq ansible apt-transport-https

  if ! check_cmd docker; then
    do_error_exit "docker is not installed"
  fi
  
  if ! check_cmd curl; then
    do_error_exit "curl is not installed"
  fi
  
  if ! check_cmd git; then
    do_error_exit "git is not installed"
  fi
  
  if ! check_cmd unzip; then
    do_error_exit "unzip is not installed"
  fi
  
  if ! check_cmd ansible; then
    do_error_exit "ansible is not installed"
  fi
  
  if ! check_cmd aws; then
    do_error_exit "aws is not installed"
  fi
  
  if ! check_cmd jq; then
    do_error_exit "jq is not installed"
  fi
  
  if ! check_cmd java; then
    do_error_exit "java is not installed"
  fi
  
  if ! check_cmd openssl; then
    do_error_exit "openssl is not installed"
  fi
  
  echo "- prerequisites ok"
}

check_root() {
  if [ "$(id -u)" != "0" ]; then
   do_error_exit "This script must be run as root"
  fi
}

check_cmd() {
  if command -v $1 >/dev/null 2>&1
  then
    return 0
  else
    return 1
  fi
}

check_aws() {
   #http://stackoverflow.com/questions/6475374/how-do-i-make-cloud-init-startup-scripts-run-every-time-my-ec2-instance-boots
   #curl http://169.254.169.254/latest/user-data
  INSTANCE_ID_OK=$(curl --max-time 5 -s -o /dev/null -I -w "%{http_code}" http://169.254.169.254/latest/meta-data/instance-id)
  if [ "$INSTANCE_ID_OK" != "200" ]; then
   do_error_exit "This script must be run within AWS ($INSTANCE_ID_OK)"
  fi
}

check_ret() {
    local status=$?
    if [ $status -ne 0 ]; then
         echo "ERR - The last command $1 failed with status $status" 1>&2
         post_slack "ERR - The last command $1 failed with status $status on $SG_PRIVHOST"
         exit $status
    fi
}

dolog() {
	 echo "$1" 1>&2
	 post_slack "$SG_PRIVHOST : $1"
}

cd /

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DIST=`grep DISTRIB_ID /etc/*-release | awk -F '=' '{print $2}'`
echo $(date) >> /root/runs

check_root
check_aws
show_info
check_prerequisites
do_install
