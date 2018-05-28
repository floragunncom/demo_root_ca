#!/bin/bash
set -x

post_slack() {
   curl -X POST --data-urlencode 'payload={"channel": "#aws_notify", "username": "awsbot", "text": "'"$1"'", "icon_emoji": ":cyclone:"}' $SLACKURL > /dev/null 2>&1
}

do_install() {

  mkfs -t ext4 -V /dev/xvdb
  mount -a
  
  export REGION=$(wget -qO- http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//' | tr -d '"')
  export INSTANCE_ID="$(curl -s http://169.254.169.254/latest/meta-data/instance-id)"
  export AUTOSCALING_GROUP_NAME="$(aws autoscaling describe-auto-scaling-groups --region $REGION | jq --raw-output ".[] | map(select(.Instances[].InstanceId | contains(\"$INSTANCE_ID\"))) | .[].AutoScalingGroupName")"  
  export STACKNAME=$(aws ec2 describe-tags --region $REGION --filters "Name=resource-id,Values=${INSTANCE_ID}" | grep -2 stack | grep Value | tr -d ' ' | cut -f2 -d: | tr -d '"' | tr -d ',')
  
  if [ -z "$STACKNAME" ];then
  	dolog "empty STACKNAME $STACKNAME"
  	exit -1
  fi
  
  export SG_PUBHOST=$(curl -s http://169.254.169.254/latest/meta-data/public-hostname)
  export SG_PRIVHOST=$(curl -s http://169.254.169.254/latest/meta-data/hostname)
  dolog "Will bootstrap stack: $STACKNAME in $REGION on $SG_PUBHOST ($DIST)"
  dolog "Instanceid: $INSTANCE_ID autoscalinggroup: $AUTOSCALING_GROUP_NAME"
  
  echo "Stopping services"

  systemctl stop elasticsearch.service > /dev/null 2>&1
  
  #Make sure we have enough entropie
  cat /proc/sys/kernel/random/entropy_avail
  dolog "Entropie on $SG_PUBHOST is $(cat /proc/sys/kernel/random/entropy_avail)"
  #rngd -r /dev/urandom -o /dev/random -t 1
  
  cat /proc/sys/net/core/somaxconn
  dolog "somaxconn on $SG_PUBHOST is $(cat /proc/sys/net/core/somaxconn)"
    
  if [ ! -f "elasticsearch-$ES_VERSION.deb" ]; then
    wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ES_VERSION.deb > /dev/null 2>&1
    check_ret "Downloading ES"
  fi
  
  dpkg --force-all -i elasticsearch-$ES_VERSION.deb > /dev/null 2>&1
  check_ret "Installing ES"
  
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
  $ES_BIN/elasticsearch-plugin remove repository-s3 > /dev/null 2>&1
  
  $ES_BIN/elasticsearch-plugin install -b discovery-ec2 > /dev/null 
  check_ret "Installing discovery-ec2 plugin"
  
  #INSTALL PLUGIN
  if [ "$SG_SSLONLY" == "true" ]; then
  	  if [[ $SGSSL_VERSION = *"http"* ]]; then
  	      $ES_BIN/elasticsearch-plugin install -b "$SGSSL_VERSION" > /dev/null 
  	  else
          $ES_BIN/elasticsearch-plugin install -b com.floragunn:search-guard-ssl:$SGSSL_VERSION > /dev/null 
      fi
  else
      
      if [[ $SG_VERSION = *"http"* ]]; then
  	      $ES_BIN/elasticsearch-plugin install -b "$SG_VERSION" > /dev/null 
  	  else
          $ES_BIN/elasticsearch-plugin install -b com.floragunn:search-guard-6:$SG_VERSION > /dev/null 
      fi
  fi
  
  check_ret "Installing SG plugin"
  
  
  $ES_BIN/elasticsearch-plugin install -b repository-s3 > /dev/null 
  
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
  
  rm -rf "$ES_PLUGINS/search-guard-6/netty-tcnative*"
  rm -rf "$ES_PLUGINS/search-guard-ssl/netty-tcnative*"
  
  if [ -z "$NETTY_NATIVE_VERSION" ]; then
  	dolog "NO TC-NATIVE"
  else
      dolog "TC-NATIVE $OPENSSL_VERSION-static-$NETTY_NATIVE_VERSION"
	  #static version which supports hnv
	  if [ "$SG_SSLONLY" == "false" ]; then
		  wget -O "$ES_PLUGINS/search-guard-6/netty-tcnative-$NETTY_NATIVE_VERSION-linux-x86_64.jar" "https://bintray.com/floragunncom/netty-tcnative/download_file?file_path=netty-tcnative-openssl-$OPENSSL_VERSION-static-$NETTY_NATIVE_VERSION-non-fedora-linux-x86_64.jar" > downloadnetty 2>&1
		  check_ret "Downloading netty native to search-guard-6: $(cat downloadnetty)"
	  else
		  wget -O "$ES_PLUGINS/search-guard-ssl/netty-tcnative-$NETTY_NATIVE_VERSION-linux-x86_64.jar" "https://bintray.com/floragunncom/netty-tcnative/download_file?file_path=netty-tcnative-openssl-$OPENSSL_VERSION-static-$NETTY_NATIVE_VERSION-non-fedora-linux-x86_64.jar" > downloadnetty 2>&1
		  check_ret "Downloading netty native to search-guard-ssl: $(cat downloadnetty)"
	  fi
  fi

  
  cd - > /dev/null 2>&1

  #dns seems to be broken on aws currently, so we need to disable hostname verification
  echo "cluster.name: $STACKNAME" > $ES_CONF/elasticsearch.yml
  echo "discovery.zen.hosts_provider: ec2" >> $ES_CONF/elasticsearch.yml
  echo "discovery.ec2.host_type: public_dns" >> $ES_CONF/elasticsearch.yml
  echo 'discovery.ec2.endpoint: ec2.eu-west-1.amazonaws.com' >> $ES_CONF/elasticsearch.yml
  echo "discovery.ec2.tag.stack: $STACKNAME" >> $ES_CONF/elasticsearch.yml
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

######## compliance
if [ "$SG_COMPLIANCE" == "true" ]; then
 echo "searchguard.compliance.history.external_config_enabled: true" >> $ES_CONF/elasticsearch.yml
 echo "searchguard.compliance.history.internal_config_enabled: true" >> $ES_CONF/elasticsearch.yml
 echo 'searchguard.compliance.history.read.watched_fields: "*,*"' >> $ES_CONF/elasticsearch.yml
 echo 'searchguard.compliance.history.write.watched_indices: "*"' >> $ES_CONF/elasticsearch.yml
 echo 'searchguard.compliance.history.write.metadata_only: false' >> $ES_CONF/elasticsearch.yml
 echo 'searchguard.compliance.history.read.metadata_only: false' >> $ES_CONF/elasticsearch.yml
 # slow until 6.3.x
 echo 'searchguard.compliance.history.write.log_diffs: false' >> $ES_CONF/elasticsearch.yml
fi
#######


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
  
  if ! [ -z "$CIPHER" ]; then
      echo "searchguard.ssl.transport.enabled_ciphers: $CIPHER" >> $ES_CONF/elasticsearch.yml
  fi

  echo "searchguard.ssl.http.enabled: true" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.http.keystore_filepath: CN=$SG_PUBHOST-keystore.jks" >> $ES_CONF/elasticsearch.yml
  #echo "searchguard.ssl.http.truststore_filepath: truststore.jks" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.pemkey_filepath: CN=$SG_PUBHOST.key" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.pemkey_password: changeit" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.pemcert_filepath: CN=$SG_PUBHOST.chain.pem" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.ssl.http.pemtrustedcas_filepath: chain-ca.pem" >> $ES_CONF/elasticsearch.yml
  echo "searchguard.enable_snapshot_restore_privilege: true" >> $ES_CONF/elasticsearch.yml
  
  if ! [ -z "$CIPHER" ]; then
      echo "searchguard.ssl.http.enabled_ciphers: $CIPHER" >> $ES_CONF/elasticsearch.yml
  fi
  
  if [ "$SG_SSLONLY" == "false" ]; then
  
      echo "searchguard.disabled: $SG_DISABLED" >> $ES_CONF/elasticsearch.yml

	  echo "searchguard.audit.type: internal_elasticsearch" >> $ES_CONF/elasticsearch.yml

	  echo "searchguard.authcz.admin_dn:">> $ES_CONF/elasticsearch.yml
	  echo "  - CN=sgadmin" >> $ES_CONF/elasticsearch.yml
  
	  echo 'searchguard.restapi.roles_enabled: ["sg_all_access"]' >> $ES_CONF/elasticsearch.yml

  fi
  
  if [ -z "$NETTY_VERSION" ]; then
  	dolog "no special netty version"
  else
      dolog "netty version $NETTY_VERSION"
	  #static version which supports hnv
	  if [ "$SG_SSLONLY" == "false" ]; then
		  cd "$ES_PLUGINS/search-guard-6/"
	  else
		  cd "$ES_PLUGINS/search-guard-ssl/"
	  fi
	  
	  rm -rf netty-*4.1*
      wget "http://central.maven.org/maven2/io/netty/netty-handler/$NETTY_VERSION/netty-handler-$NETTY_VERSION.jar"
      wget "http://central.maven.org/maven2/io/netty/netty-buffer/$NETTY_VERSION/netty-buffer-$NETTY_VERSION.jar"
      wget "http://central.maven.org/maven2/io/netty/netty-codec/$NETTY_VERSION/netty-codec-$NETTY_VERSION.jar"
      wget "http://central.maven.org/maven2/io/netty/netty-codec-http/$NETTY_VERSION/netty-codec-http-$NETTY_VERSION.jar"
      wget "http://central.maven.org/maven2/io/netty/netty-common/$NETTY_VERSION/netty-common-$NETTY_VERSION.jar"
      wget "http://central.maven.org/maven2/io/netty/netty-resolver/$NETTY_VERSION/netty-resolver-$NETTY_VERSION.jar"
      wget "http://central.maven.org/maven2/io/netty/netty-transport/$NETTY_VERSION/netty-transport-$NETTY_VERSION.jar"
  
      cd -
	  
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
	  
	  #register s3 snapshot repo
	  curl -XPUT -k -u admin:admin  "https://$SG_PUBHOST:9200/_snapshot/mys3reposg" -H 'Content-Type: application/json' -d'
		{
		  "type": "s3",
		  "settings": {
			"bucket": "sgperftest"
		  }
		}'
		
	  curl -XPOST -k -u admin:admin "https://$SG_PUBHOST:9200/_snapshot/mys3reposg/snapshot_2/_restore"

  
  fi
  
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
