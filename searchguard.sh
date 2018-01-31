#!/bin/bash
set -x
ES_VERSION=6.1.1
SG_VERSION=$ES_VERSION-20.1
#SG_KIBANA_VERSION=8
SGSSL_VERSION=$ES_VERSION-25.0
NETTY_NATIVE_VERSION=2.0.5.Final
OPENSSL_VERSION=1.0.2l
SG_DISABLED="false"
SG_SSLONLY="false"
#MYML="metricbeat.yml"
#FYML="filebeat.yml"
#KYML="kibana.yml"

post_slack() {
   curl -X POST --data-urlencode 'payload={"channel": "#aws_notify", "username": "awsbot", "text": "'"$1"'", "icon_emoji": ":cyclone:"}' $SLACKURL > /dev/null 2>&1
}

do_install() {

  mkfs -t ext4 -V /dev/xvdb
  mount -a
  
  export REGION=$(wget -qO- http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//' | tr -d '"')
  export STACKNAME="sgaws" #$(aws ec2 describe-instances --filters "Name=ip-address,Values=$(ec2metadata --public-ipv4)" --region $REGION | jq '.Reservations[0].Instances[0].Tags | map(select (.Key == "aws:cloudformation:stack-name" )) ' | jq .[0].Value | tr -d '"')
  export SG_PUBHOST=$(curl -s http://169.254.169.254/latest/meta-data/public-hostname)
  export SG_PRIVHOST=$(curl -s http://169.254.169.254/latest/meta-data/hostname)
  dolog "Will bootstrap $STACKNAME in $REGION on $SG_PUBHOST ($DIST)"
  
  echo "Stopping services"
  
  systemctl stop kibana.service > /dev/null 2>&1
  systemctl stop metricbeat.service > /dev/null 2>&1
  systemctl stop elasticsearch.service > /dev/null 2>&1
  systemctl stop filebeat.service > /dev/null 2>&1
  
  
  #Make sure we have enough entropie
  cat /proc/sys/kernel/random/entropy_avail
  dolog "Entropie on $SG_PUBHOST is $(cat /proc/sys/kernel/random/entropy_avail)"
  #rngd -r /dev/urandom -o /dev/random -t 1
  
  #Use ECDSA
  
  #openssl ecparam -name prime256v1 -genkey -param_enc explicit -out private-key.pem 
  #openssl req -new -x509 -key private-key.pem -out server.pem -days 730 -sha256
  
  cat /proc/sys/net/core/somaxconn
  dolog "somaxconn on $SG_PUBHOST is $(cat /proc/sys/net/core/somaxconn)"
  
  #Netty version
  #replace netty in sg plugin folder
  #also replace tcnative to match 2.0.7
  #wget http://central.maven.org/maven2/io/netty/netty-handler/4.1.16.Final/netty-handler-4.1.16.Final.jar
  #wget http://central.maven.org/maven2/io/netty/netty-buffer/4.1.16.Final/netty-buffer-4.1.16.Final.jar
  #wget http://central.maven.org/maven2/io/netty/netty-codec/4.1.16.Final/netty-codec-4.1.16.Final.jar
  #wget http://central.maven.org/maven2/io/netty/netty-codec-http/4.1.16.Final/netty-codec-http-4.1.16.Final.jar
  #wget http://central.maven.org/maven2/io/netty/netty-common/4.1.16.Final/netty-common-4.1.16.Final.jar
  #wget http://central.maven.org/maven2/io/netty/netty-resolver/4.1.16.Final/netty-resolver-4.1.16.Final.jar
  #wget http://central.maven.org/maven2/io/netty/netty-transport/4.1.16.Final/netty-transport-4.1.16.Final.jar
  
  #python perf script
  #https://github.com/floragunncom/search-guard/issues/310
  
  #dolog "Install packages"
  
  #apt install -yqq python3-pip
  #pip3 install esrally
  #pip3 install requests ndg-httpsclient --upgrade
  #pip3 install elasticsearch requests cryptography pyopenssl ndg-httpsclient pyasn1
  #esrally --track=logging --report-file="~/report-$(date).md" --report-format=csv --pipeline=benchmark-only --target-hosts=https://ec2-34-253-194-30.eu-west-1.compute.amazonaws.com:9200,https://ec2-54-154-99-160.eu-west-1.compute.amazonaws.com:9200 --client-options "use_ssl:true,verify_certs:False,basic_auth_user:'admin',basic_auth_password:'admin'"
  #esrally --track=logging --pipeline=benchmark-only --target-hosts=$(hostname -f):9200 --client-options "use_ssl:true,verify_certs:False,basic_auth_user:'admin',basic_auth_password:'admin'"
  #nyc_taxis
  #percolator
  #--report-file=/path/to/your/report.md
  #--report-format=csv
  #--test-mode
  #nohup esrally --track=logging --report-file="~/report-$(date).md" --report-format=csv --pipeline=benchmark-only --target-hosts=https://ec2-34-253-234-70.eu-west-1.compute.amazonaws.com:9200,https://ec2-54-154-62-50.eu-west-1.compute.amazonaws.com:9200 --client-options "use_ssl:true,verify_certs:False,basic_auth_user:'admin',basic_auth_password:'admin'" &
  
  if [ ! -f "elasticsearch-$ES_VERSION.deb" ]; then
    wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ES_VERSION.deb > /dev/null 2>&1
    check_ret "Downloading ES"
  fi
  
  dpkg --force-all -i elasticsearch-$ES_VERSION.deb > /dev/null 2>&1
  check_ret "Installing ES"
  
  #wget https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-$ES_VERSION-amd64.deb > /dev/null 2>&1
  #check_ret "Downloading Metricbeat"
  
  #dpkg --force-all -i metricbeat-$ES_VERSION-amd64.deb > /dev/null 2>&1
  #check_ret "Installing Metricbeat"
  
  #wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-$ES_VERSION-amd64.deb > /dev/null 2>&1
  #check_ret "Downloading filebeat"
  
  #dpkg --force-all -i filebeat-$ES_VERSION-amd64.deb > /dev/null 2>&1
  #check_ret "Installing filebeat"
  
  #wget https://artifacts.elastic.co/downloads/kibana/kibana-$ES_VERSION-amd64.deb > /dev/null 2>&1
  #check_ret "Downloading Kibana"
  
  #dpkg --force-all -i kibana-$ES_VERSION-amd64.deb > /dev/null 2>&1
  #check_ret "Installing Kibana"
  
  # Total memory in KB
  totalMemKB=$(awk '/MemTotal:/ { print $2 }' /proc/meminfo)

  # Percentage of memory to use for Java heap
  usagePercent=50

  # heap size in KB
  let heapKB=$totalMemKB*$usagePercent/100

  # heap size in MB
  let heapMB=$heapKB/1024
  
  #dolog "Half Ram: ${heapMB}m"
  
  sed -i -e "s/-Xmx1g/-Xmx${heapMB}m/g" /etc/elasticsearch/jvm.options
  sed -i -e "s/-Xms1g/-Xms${heapMB}m/g" /etc/elasticsearch/jvm.options
  
  #dolog "$(cat /etc/elasticsearch/jvm.options)"

  export ES_BIN=/usr/share/elasticsearch/bin
  export ES_CONF=/etc/elasticsearch
  export ES_LOG=/var/log/elasticsearch
  export ES_PLUGINS=/usr/share/elasticsearch/plugins
  
  ORG_NAME="Example Inc."
  
  echo "SG_PUBHOST: $SG_PUBHOST"
  echo "SG_PRIVHOST: $SG_PRIVHOST"
  
  $ES_BIN/elasticsearch-plugin remove discovery-ec2 > /dev/null 2>&1
  $ES_BIN/elasticsearch-plugin remove search-guard-6 > /dev/null 2>&1
  $ES_BIN/elasticsearch-plugin remove search-guard-ssl > /dev/null 2>&1
  $ES_BIN/elasticsearch-plugin remove x-pack > /dev/null 2>&1
  
  $ES_BIN/elasticsearch-plugin install -b discovery-ec2 > /dev/null 
  check_ret "Installing discovery-ec2 plugin"
  
  #INSTALL PLUGIN
  if [ "$SG_SSLONLY" == "true" ]; then
      $ES_BIN/elasticsearch-plugin install -b com.floragunn:search-guard-ssl:$SGSSL_VERSION
  else
      $ES_BIN/elasticsearch-plugin install -b com.floragunn:search-guard-6:$SG_VERSION > /dev/null 
  fi
  
  check_ret "Installing SG plugin"
  
  #$ES_BIN/elasticsearch-plugin install -b x-pack > /dev/null 
  #check_ret "Installing xpack plugin"
  
  cd /demo_root_ca
  git pull > /dev/null 2>&1
  
  #dolog "Generate certificates"
  #cp truststore.jks truststore.jks.orig
  rm -rf *.jks *.p12 *.pem *.csr *.key
  #<organisation name> <nodedn> <nodedns> <filename> <key password> <root ca passsord> 
  ./gen_node_cert.sh "$ORG_NAME" "/CN=$SG_PUBHOST" "$SG_PUBHOST" "CN=$SG_PUBHOST" changeit "ca pass" > /dev/null 2>&1
  check_ret "generate certificate"
  ./gen_node_cert.sh "$ORG_NAME" "/CN=$SG_PRIVHOST" "$SG_PRIVHOST" "CN=$SG_PRIVHOST" changeit "ca pass" > /dev/null 2>&1
  check_ret "generate certificate"
  ./gen_client_node_cert.sh "$ORG_NAME" "/CN=user" "CN=user" changeit "ca pass" > /dev/null 2>&1
  check_ret "generate certificate"
  ./gen_client_node_cert.sh "$ORG_NAME" "/CN=sgadmin" "CN=sgadmin" changeit "ca pass" > /dev/null 2>&1
  check_ret "generate certificate"
  #./gen_nonsgserver_certificate.sh "$ORG_NAME" "/C=DE/ST=Berlin/L=City/O=floragunn/OU=IT Department/CN=topbeat" $SG_PUBHOST topbeat "ca pass"  > /dev/null 2>&1
  #check_ret "generate certificate"
  #./gen_nonsgserver_certificate.sh "$ORG_NAME" "/C=DE/ST=Berlin/L=City/O=floragunn/OU=IT Department/CN=kibana" $SG_PUBHOST kibana "ca pass"  > /dev/null 2>&1
  #check_ret "generate certificate"

  #cp truststore.jks.orig truststore.jks

  #cp *.jks $ES_CONF/
  #cp *.p12 $ES_CONF/
  cp *.pem $ES_CONF/
  cp *.key $ES_CONF/
  cp ca/*.pem $ES_CONF/

  chown -R elasticsearch:elasticsearch $ES_CONF
  
  chmod -R 755 $ES_CONF
  
  #static version which supports hnv
  if [ "$SG_SSLONLY" == "false" ]; then
      wget -O "$ES_PLUGINS/search-guard-6/netty-tcnative-$NETTY_NATIVE_VERSION-linux-x86_64.jar" "https://bintray.com/floragunncom/netty-tcnative/download_file?file_path=netty-tcnative-openssl-$OPENSSL_VERSION-static-$NETTY_NATIVE_VERSION-non-fedora-linux-x86_64.jar" > downloadnetty 2>&1
      check_ret "Downloading netty native to search-guard-6: $(cat downloadnetty)"
  else
      wget -O "$ES_PLUGINS/search-guard-ssl/netty-tcnative-$NETTY_NATIVE_VERSION-linux-x86_64.jar" "https://bintray.com/floragunncom/netty-tcnative/download_file?file_path=netty-tcnative-openssl-$OPENSSL_VERSION-static-$NETTY_NATIVE_VERSION-non-fedora-linux-x86_64.jar" > downloadnetty 2>&1
      check_ret "Downloading netty native to search-guard-ssl: $(cat downloadnetty)"
  fi

  
  cd - > /dev/null 2>&1

  #dns seems to be broken on aws currently, so we need to disable hostname verification
  echo "cluster.name: $STACKNAME" > $ES_CONF/elasticsearch.yml
  echo "discovery.zen.hosts_provider: ec2" >> $ES_CONF/elasticsearch.yml
  echo "discovery.ec2.host_type: public_dns" >> $ES_CONF/elasticsearch.yml
  echo 'discovery.ec2.endpoint: ec2.eu-west-1.amazonaws.com' >> $ES_CONF/elasticsearch.yml
  echo "network.host: _ec2:publicDns_" >> $ES_CONF/elasticsearch.yml
  echo "transport.host: _ec2:publicDns_" >> $ES_CONF/elasticsearch.yml
  echo "transport.tcp.port: 9300" >> $ES_CONF/elasticsearch.yml
  
  echo "http.host: _ec2:publicDns_" >> $ES_CONF/elasticsearch.yml
  echo "http.port: 9200" >> $ES_CONF/elasticsearch.yml
  echo "http.cors.enabled: true" >> $ES_CONF/elasticsearch.yml
  echo 'http.cors.allow-origin: "*"' >> $ES_CONF/elasticsearch.yml
  
  echo 'logger.org.elasticsearch.discovery.ec2: TRACE'  >> $ES_CONF/elasticsearch.yml
  echo "node.name: $SG_PUBHOST" >> $ES_CONF/elasticsearch.yml
  echo "bootstrap.memory_lock: true" >> $ES_CONF/elasticsearch.yml
  echo "path.logs: /var/log/elasticsearch" >> $ES_CONF/elasticsearch.yml
  echo "path.data: /mnt/esdata" >> $ES_CONF/elasticsearch.yml
  #echo "discovery.zen.minimum_master_nodes: 2" >> $ES_CONF/elasticsearch.yml
  #echo "xpack.security.enabled: false" >> $ES_CONF/elasticsearch.yml
  #echo "xpack.watcher.enabled: false" >> $ES_CONF/elasticsearch.yml
  #echo "xpack.monitoring.enabled: true" >> $ES_CONF/elasticsearch.yml
  #echo "xpack.ml.enabled: false" >> $ES_CONF/elasticsearch.yml
  echo "" >> $ES_CONF/elasticsearch.yml
  echo "" >> $ES_CONF/elasticsearch.yml
  echo "" >> $ES_CONF/elasticsearch.yml
  echo "" >> $ES_CONF/elasticsearch.yml
  
  
  echo "##################################################" >> $ES_CONF/elasticsearch.yml
  echo "#          Search Guard 6 configuration          " >> $ES_CONF/elasticsearch.yml
  echo "#                                                " >> $ES_CONF/elasticsearch.yml
  echo "#Host: $SG_PUBHOST    $SG_PRIVHOST               " >> $ES_CONF/elasticsearch.yml
  echo "#Generated: $(date)                              " >> $ES_CONF/elasticsearch.yml
  echo "#ES-Version: $ES_VERSION                         " >> $ES_CONF/elasticsearch.yml
  echo "#SG-Version: $SG_VERSION                         " >> $ES_CONF/elasticsearch.yml
  echo "#NettyNative-Version: $NETTY_NATIVE_VERSION      " >> $ES_CONF/elasticsearch.yml
  echo "#                                                " >> $ES_CONF/elasticsearch.yml
  echo "##################################################" >> $ES_CONF/elasticsearch.yml	

  #echo "searchguard.ssl.transport.keystore_filepath: CN=$SG_PUBHOST-keystore.jks" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.transport.truststore_filepath: truststore.jks" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.transport.pemkey_filepath: CN=$SG_PUBHOST.key" >> $ES_CONF/elasticsearch.yml
  # Key password (omit this setting if the key has no password)
  echo "searchguard.ssl.transport.pemkey_password: changeit" >> $ES_CONF/elasticsearch.yml
  # X509 node certificate chain in PEM format, must be placed under the config/ dir
  echo "searchguard.ssl.transport.pemcert_filepath: CN=$SG_PUBHOST.chain.pem" >> $ES_CONF/elasticsearch.yml
  # Trusted certificates
  echo "searchguard.ssl.transport.pemtrustedcas_filepath: chain-ca.pem" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.transport.enforce_hostname_verification: false" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.transport.enabled_ciphers: ECDHE-ECDSA-AES128-GCM-SHA256" >> $ES_CONF/elasticsearch.yml

  echo "searchguard.ssl.http.enabled: true" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.http.keystore_filepath: CN=$SG_PUBHOST-keystore.jks" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.http.truststore_filepath: truststore.jks" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.pemkey_filepath: CN=$SG_PUBHOST.key" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.pemkey_password: changeit" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.pemcert_filepath: CN=$SG_PUBHOST.chain.pem" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.pemtrustedcas_filepath: chain-ca.pem" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.enabled_ciphers: ECDHE-ECDSA-AES128-GCM-SHA256" >> $ES_CONF/elasticsearch.yml

  if [ "$SG_SSLONLY" == "false" ]; then
  
      echo "searchguard.disabled: $SG_DISABLED" >> $ES_CONF/elasticsearch.yml

	  echo "searchguard.audit.type: internal_elasticsearch" >> $ES_CONF/elasticsearch.yml

	  echo "searchguard.authcz.admin_dn:">> $ES_CONF/elasticsearch.yml
	  echo "  - CN=sgadmin" >> $ES_CONF/elasticsearch.yml
  
	  echo 'searchguard.restapi.roles_enabled: ["sg_all_access"]' >> $ES_CONF/elasticsearch.yml

  fi
  
  mkdir -p /mnt/esdata
  chown -R elasticsearch:elasticsearch /mnt/esdata

  echo "vm.max_map_count=262144" >> /etc/sysctl.conf
  echo 262144 > /proc/sys/vm/max_map_count 
  
  mkdir -p /etc/systemd/system/elasticsearch.service.d
  echo "[Service]" > /etc/systemd/system/elasticsearch.service.d/override.conf
  echo "LimitMEMLOCK=infinity" >> /etc/systemd/system/elasticsearch.service.d/override.conf
  echo "LimitNOFILE=1000000" >> /etc/systemd/system/elasticsearch.service.d/override.conf
  
  echo "MAX_LOCKED_MEMORY=unlimited" >> /etc/default/elasticsearch
  echo "MAX_OPEN_FILES=1000000" >> /etc/default/elasticsearch
  echo "MAX_MAP_COUNT=262144"  >> /etc/default/elasticsearch
  
  echo "elasticsearch  -  nofile  1000000" >> /etc/security/limits.conf
  
  #filebeat  
  #cat "/demo_root_ca/filebeat/$FYML" | sed -e "s/RPLC_HOST/$SG_PUBHOST/g" > /etc/filebeat/filebeat.yml

  #/bin/systemctl daemon-reload

  #/bin/systemctl enable filebeat.service
  #systemctl start filebeat.service
  #filebeat end

 
  check_ret "daemon-reload"
  /bin/systemctl enable elasticsearch.service
  check_ret "enable elasticsearch.service"
  systemctl start elasticsearch.service
  check_ret "start elasticsearch.service"
  
  sleep 25
  
  while ! nc -z $SG_PUBHOST 9200 > /dev/null 2>&1; do
    dolog "Wait for elasticsearch ..."
    sleep 15
    dolog "$(cat /var/log/elasticsearch/*)"
  done
  
  echo "elasticsearch up"
  sleep 5
  
  
  if [ "$SG_DISABLED" == "false" ] && [ "$SG_SSLONLY" == "false" ]; then
  
     dolog "run sgadmin $SG_PUBHOST $SG_PRIVHOST"
  
     chmod +x $ES_PLUGINS/search-guard-6/tools/sgadmin.sh
     $ES_PLUGINS/search-guard-6/tools/sgadmin.sh -cd /demo_root_ca/sgconfig -h $SG_PUBHOST -icl -cacert $ES_CONF/root-ca.pem -cert $ES_CONF/CN=sgadmin.chain.pem -key $ES_CONF/CN=sgadmin.key -keypass changeit -nhnv
     check_ret "running sgadmin"
     post_slack "SG $SG_VERSION initialized on https://$SG_PUBHOST:9200"
  
  
	  curl -XPUT -k -u admin:admin "https://$SG_PUBHOST:9200/twitter/tweet/1?pretty" -H'Content-Type: application/json' -d'
	  {
		"user" : "searchguard",
		"post_date" : "2013-11-15T14:12:12",
		"message" : "rockn roll"
	  }'

	  curl -XPUT -k -u admin:admin "https://$SG_PUBHOST:9200/twitter1/tweet/1?pretty" -H'Content-Type: application/json' -d'
	  {
		"user" : "searchguard1",
		"post_date" : "2015-11-15T14:12:12",
		"message" : "rockn roll"
	  }'
  
  fi
  
  dolog "Finished"
  #no kibana and metricbeat
  exit 0
  
  #dolog "Install Kibana"

   if [ "$SG_DISABLED" == "false" ] && [ "$SG_SSLONLY" == "false" ]; then
      /usr/share/kibana/bin/kibana-plugin install https://oss.sonatype.org/content/repositories/releases/com/floragunn/search-guard-kibana-plugin/$ES_VERSION-$SG_KIBANA_VERSION/search-guard-kibana-plugin-$ES_VERSION-$SG_KIBANA_VERSION.zip
   fi
  
  /usr/share/kibana/bin/kibana-plugin install x-pack
  cat "/demo_root_ca/kibana/$KYML" | sed -e "s/RPLC_HOST/$SG_PUBHOST/g" > /etc/kibana/kibana.yml 
  #echo 'searchguard.cookie.password: "a12345678912345678912345678912345678987654c"' >> /etc/kibana/kibana.yml 
  chown -R kibana /usr/share/kibana/

  /bin/systemctl enable kibana.service
  systemctl start kibana.service  
  
  dolog "Kibana $SG_VERSION running on https://$SG_PUBHOST:5601"
  
  #dolog "Install Metricbeat"
  
  cat "/demo_root_ca/metricbeat/$MYML" | sed -e "s/RPLC_HOST/$SG_PUBHOST/g" > /etc/metricbeat/metricbeat.yml

  /bin/systemctl enable metricbeat.service
  systemctl start metricbeat.service
  dolog "Finished"
  
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
  apt-get -y remove openjdk-7-jdk openjdk-7-jre openjdk-7-jre-headless || true
  echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections > /dev/null 2>&1
  apt-get -yqq install software-properties-common > /dev/null 2>&1
  add-apt-repository -y ppa:webupd8team/java > /dev/null 2>&1
  apt-get -yqq update > /dev/null 2>&1
  apt-get -yqq install oracle-java8-installer oracle-java8-unlimited-jce-policy > /dev/null 2>&1
  ########## end Oracle 8 Java

  apt-get -yqq install ntp ntpdate haveged libssl-dev autoconf libtool build-essential libffi6 libffi-dev wget openssl libapr1 iputils-ping dnsutils host netcat telnet > /dev/null 2>&1
  apt-get -yqq install unzip curl git jq apt-transport-https
  apt-get -y autoremove || true

  
  if ! check_cmd curl; then
    do_error_exit "curl is not installed"
  fi
  
  if ! check_cmd git; then
    do_error_exit "git is not installed"
  fi
  
  if ! check_cmd unzip; then
    do_error_exit "unzip is not installed"
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
