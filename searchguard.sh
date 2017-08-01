#!/bin/bash
#set -x

post_slack() {
   curl -X POST --data-urlencode 'payload={"channel": "#aws_notify", "username": "awsbot", "text": "'"$1"'", "icon_emoji": ":cyclone:"}' $SLACKURL > /dev/null 2>&1
}

do_install() {
  
  export REGION=$(wget -qO- http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//' | tr -d '"')
  export STACKNAME=$(aws ec2 describe-instances --filters "Name=ip-address,Values=$(ec2metadata --public-ipv4)" --region $REGION | jq '.Reservations[0].Instances[0].Tags | map(select (.Key == "aws:cloudformation:stack-name" )) ' | jq .[0].Value | tr -d '"')
  export SG_PUBHOST=$(curl -s http://169.254.169.254/latest/meta-data/public-hostname)
  export SG_PRIVHOST=$(curl -s http://169.254.169.254/latest/meta-data/hostname)
  dolog "Will bootstrap $STACKNAME in $REGION on $SG_PUBHOST ($DIST)"
  
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
  #esrally --track=geopoint --pipeline=benchmark-only --target-hosts=10.0.0.6:9200,10.0.0.7:9200,10.0.0.8:9200 --client-options "use_ssl:true,verify_certs:False,basic_auth_user:'admin',basic_auth_password:'admin'"

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
  
  sed -i -e 's/-Xmx2g/-Xmx32g/g' /etc/elasticsearch/jvm.options
  sed -i -e 's/-Xms2g/-Xms32g/g' /etc/elasticsearch/jvm.options
  check_ret "xmx sed"
  
  NETTY_NATIVE_VERSION=2.0.5.Final
  NETTY_NATIVE_CLASSIFIER=linux-x86_64
  export ES_BIN=/usr/share/elasticsearch/bin
  export ES_CONF=/etc/elasticsearch
  export ES_LOG=/var/log/elasticsearch
  export ES_PLUGINS=/usr/share/elasticsearch/plugins
  SG_VERSION=$ES_VERSION-14
  ORG_NAME="Example DSG Inc. 1.0"
  
  echo "SG_PUBHOST: $SG_PUBHOST"
  echo "SG_PRIVHOST: $SG_PRIVHOST"
  
  $ES_BIN/elasticsearch-plugin remove discovery-ec2 > /dev/null 2>&1
  $ES_BIN/elasticsearch-plugin remove search-guard-5 > /dev/null 2>&1
  $ES_BIN/elasticsearch-plugin remove x-pack > /dev/null 2>&1
  
  $ES_BIN/elasticsearch-plugin install -b discovery-ec2 > /dev/null 
  check_ret "Installing discovery-ec2 plugin"
  $ES_BIN/elasticsearch-plugin install -b com.floragunn:search-guard-5:$SG_VERSION > /dev/null 
  check_ret "Installing SG plugin"
  $ES_BIN/elasticsearch-plugin install -b x-pack > /dev/null 
  check_ret "Installing xpack plugin"
  
  cd /demo_root_ca
  git pull > /dev/null 2>&1
  
  dolog "Generate certificates"
  cp truststore.jks truststore.jks.orig
  rm -rf *.jks *.p12 *.pem *.csr *.key
  
  ./gen_node_cert.sh "$ORG_NAME" "CN=$SG_PUBHOST" "$SG_PUBHOST" changeit "ca pass" > /dev/null 2>&1
  check_ret "generate certificate"
  ./gen_node_cert.sh "$ORG_NAME" "CN=$SG_PRIVHOST" "$SG_PRIVHOST" changeit "ca pass" > /dev/null 2>&1
  check_ret "generate certificate"
  ./gen_client_node_cert.sh "$ORG_NAME" "CN=user" changeit "ca pass" > /dev/null 2>&1
  check_ret "generate certificate"
  ./gen_client_node_cert.sh "$ORG_NAME" "CN=sgadmin" changeit "ca pass" > /dev/null 2>&1
  check_ret "generate certificate"
  ./gen_nonsgserver_certificate.sh "$ORG_NAME" "/C=DE/ST=Berlin/L=City/O=floragunn/OU=IT Department/CN=topbeat" $SG_PUBHOST topbeat "ca pass"  > /dev/null 2>&1
  check_ret "generate certificate"
  ./gen_nonsgserver_certificate.sh "$ORG_NAME" "/C=DE/ST=Berlin/L=City/O=floragunn/OU=IT Department/CN=kibana" $SG_PUBHOST kibana "ca pass"  > /dev/null 2>&1
  check_ret "generate certificate"

  cp truststore.jks.orig truststore.jks

  cp *.jks $ES_CONF/
  cp *.p12 $ES_CONF/
  cp *.pem $ES_CONF/
  cp *.key $ES_CONF/
  cp ca/*.pem $ES_CONF/

  #chown -R elasticsearch:elasticsearch $ES_CONF
  chown -R elasticsearch:elasticsearch $ES_CONF
  
  chmod -R 755 $ES_CONF
  
  if [ ! -f "netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar" ]; then
    wget -O $ES_PLUGINS/search-guard-5/netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar https://search.maven.org/remotecontent?filepath=io/netty/netty-tcnative/$NETTY_NATIVE_VERSION/netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar > /dev/null 2>&1
    check_ret "Downloading netty native"
  fi
  
  cd - > /dev/null 2>&1
  
  cd $ES_PLUGINS/search-guard-5

  dolog "Download modules"

  wget "http://oss.sonatype.org/service/local/artifact/maven/content?c=jar-with-dependencies&r=releases&g=com.floragunn&a=dlic-search-guard-authbackend-ldap&v=5.0-7" --content-disposition  > /dev/null 2>&1
  check_ret "ldap module"
  wget "http://oss.sonatype.org/service/local/artifact/maven/content?c=jar-with-dependencies&r=releases&g=com.floragunn&a=dlic-search-guard-module-auditlog&v=5.3-5" --content-disposition  > /dev/null 2>&1
  check_ret "auditlog module"
  wget "http://oss.sonatype.org/service/local/artifact/maven/content?c=jar-with-dependencies&r=releases&g=com.floragunn&a=dlic-search-guard-rest-api&v=5.3-5" --content-disposition  > /dev/null 2>&1
  check_ret "rest api module"
  wget "http://oss.sonatype.org/service/local/artifact/maven/content?c=jar-with-dependencies&r=releases&g=com.floragunn&a=dlic-search-guard-auth-http-kerberos&v=5.0-4" --content-disposition  > /dev/null 2>&1
  check_ret "kerberos module"
  wget "http://oss.sonatype.org/service/local/artifact/maven/content?c=jar-with-dependencies&r=releases&g=com.floragunn&a=dlic-search-guard-auth-http-jwt&v=5.0-5" --content-disposition  > /dev/null 2>&1
  check_ret "jwt module"
  wget "http://oss.sonatype.org/service/local/artifact/maven/content?c=jar-with-dependencies&r=releases&g=com.floragunn&a=dlic-search-guard-module-dlsfls&v=5.3-6" --content-disposition  > /dev/null 2>&1
  check_ret "dls module"
  wget "http://oss.sonatype.org/service/local/artifact/maven/content?c=jar-with-dependencies&r=releases&g=com.floragunn&a=dlic-search-guard-module-kibana-multitenancy&v=5.4-4" --content-disposition  > /dev/null 2>&1
  check_ret "multitenancy module"
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
  echo "##################################################" >> $ES_CONF/elasticsearch.yml
  echo "#          Search Guard 5 configuration          " >> $ES_CONF/elasticsearch.yml
  echo "#                                                " >> $ES_CONF/elasticsearch.yml
  echo "#Host: $SG_PUBHOST    $SG_PRIVHOST               " >> $ES_CONF/elasticsearch.yml
  echo "#Generated: $(date)                              " >> $ES_CONF/elasticsearch.yml
  echo "#ES-Version: $ES_VERSION                         " >> $ES_CONF/elasticsearch.yml
  echo "#SG-Version: $SG_VERSION                         " >> $ES_CONF/elasticsearch.yml
  echo "#NettyNative-Version: $NETTY_NATIVE_VERSION      " >> $ES_CONF/elasticsearch.yml
  echo "#                                                " >> $ES_CONF/elasticsearch.yml
  echo "##################################################" >> $ES_CONF/elasticsearch.yml	
  echo "searchguard.ssl.transport.enabled: true" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.transport.keystore_filepath: CN=$SG_PRIVHOST-keystore.jks" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.transport.keystore_password: $KS_PASS" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.transport.truststore_filepath: truststore.jks" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.transport.truststore_password: $TS_PASS" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.transport.enforce_hostname_verification: false" >> $ES_CONF/elasticsearch.yml

  echo "searchguard.ssl.http.enabled: true" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.keystore_filepath: CN=$SG_PUBHOST-keystore.jks" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.http.keystore_password: $KS_PASS" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.truststore_filepath: truststore.jks" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.http.truststore_password: $TS_PASS" >> $ES_CONF/elasticsearch.yml

  #echo "searchguard.kerberos.krb5_filepath: /Users/temp/kerberos_ldap_environment/krb5.conf" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.kerberos.acceptor_keytab_filepath: http_srv.keytab" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.audit.type: internal_elasticsearch" >> $ES_CONF/elasticsearch.yml

  echo "searchguard.authcz.admin_dn:">> $ES_CONF/elasticsearch.yml
  echo "  - CN=sgadmin" >> $ES_CONF/elasticsearch.yml

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
  
  dolog "run sgadmin $SG_PUBHOST $SG_PRIVHOST"
  
  chmod +x $ES_PLUGINS/search-guard-5/tools/sgadmin.sh
  $ES_PLUGINS/search-guard-5/tools/sgadmin.sh -cd /demo_root_ca/sgconfig -h $SG_PRIVHOST -icl -ts $ES_CONF/truststore.jks -ks $ES_CONF/CN=sgadmin-keystore.jks -nhnv
  check_ret "running sgadmin"
  post_slack "SG $SG_VERSION initialized on https://$SG_PUBHOST:9200"
  
  curl -XPUT -k -u admin:admin "https://$SG_PUBHOST:9200/twitter/tweet/1?pretty" -d'
  {
    "user" : "searchguard",
    "post_date" : "2013-11-15T14:12:12",
    "message" : "rockn roll"
  }'

  curl -XPUT -k -u admin:admin "https://$SG_PUBHOST:9200/twitter1/tweet/1?pretty" -d'
  {
    "user" : "searchguard1",
    "post_date" : "2015-11-15T14:12:12",
    "message" : "rockn roll"
  }'
  
  dolog "Install Kibana"

  cat /demo_root_ca/kibana/kibana.yml | sed -e "s/RPLC_HOST/$SG_PUBHOST/g" > /etc/kibana/kibana.yml 
  echo 'searchguard.cookie.password: "a12345678912345678912345678912345678987654c"' >> /etc/kibana/kibana.yml 
  /usr/share/kibana/bin/kibana-plugin install https://github.com/floragunncom/search-guard-kibana-plugin/releases/download/v5.5.1-3/searchguard-kibana-5.5.1-3.zip
  /usr/share/kibana/bin/kibana-plugin install x-pack


  /bin/systemctl enable kibana.service
  check_ret
  systemctl start kibana.service  
  check_ret
  
  cat /demo_root_ca/metricbeat/metricbeat.yml | sed -e "s/RPLC_HOST/$SG_PUBHOST/g" > /etc/metricbeat/metricbeat.yml

  /bin/systemctl enable metricbeat.service
  check_ret
  systemctl start metricbeat.service
  check_ret
  
  dolog "Kibana $SG_VERSION running on https://$SG_PUBHOST:5601"
    
  curl -ksS -u admin:admin "https://$SG_PUBHOST:9200/_cluster/health?pretty" > health 2>&1
  check_ret "final curl 1"
  curl -ksS -u admin:admin "https://$SG_PUBHOST:9200/_searchguard/authinfo?pretty" > authinfo 2>&1
  check_ret "final curl 2"
  curl -ksS -u admin:admin "https://$SG_PUBHOST:9200/_searchguard/sslinfo?pretty" > sslinfo 2>&1
  check_ret "final curl 3"
  
  cat authinfo
  cat sslinfo
  cat health
  
  dolog "Authinfo: $(cat authinfo)"
  dolog "SSL Info: $(cat sslinfo)"
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
