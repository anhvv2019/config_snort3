#! /bin/sh
# ___________________________________________________________________
#
# Oracle Linux 	  :	8.3 
# UEK Kernel	  :	5.4.17-2036.103.3.1.el8uek
# RHCK Kernel	  : 4.18.0-240.15.1.el8_3
# Base on Author  : https://www.howtoforge.com/how-to-install-elastic-stack-on-centos-8/
#                   How to Install Elastic Stack (Elasticsearch, Logstash and Kibana) on CentOS 8
# ___________________________________________________________________
#
#
clear
echo '___________________________________________________________________'
echo '                                                                   ' 
echo ' 1 - Add Elastic Repository'
echo '___________________________________________________________________'
echo '                                                                   ' 
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
dnf install java -y
echo '  1.1 - Create /etc/yum.repos.d/elasticsearch.repo                 '
# nano /etc/yum.repos.d/elasticsearch.repo
echo [elasticsearch-7.x] >> /etc/yum.repos.d/elasticsearch.repo
echo name=Elasticsearch repository for 7.x packages >> /etc/yum.repos.d/elasticsearch.repo
echo baseurl=https://artifacts.elastic.co/packages/7.x/yum >> /etc/yum.repos.d/elasticsearch.repo
echo gpgcheck=1 >> /etc/yum.repos.d/elasticsearch.repo
echo gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch >> /etc/yum.repos.d/elasticsearch.repo
echo enabled=1 >> /etc/yum.repos.d/elasticsearch.repo
echo autorefresh=1 >> /etc/yum.repos.d/elasticsearch.repo
echo type=rpm-md >> /etc/yum.repos.d/elasticsearch.repo
dnf repolist
echo '___________________________________________________________________'
echo '                                                                   ' 
echo ' 2 - Install and Configure Elasticsearch'
echo '___________________________________________________________________'
echo '                                                                   ' 
dnf install elasticsearch -y
cd /etc/elasticsearch/

# nano /etc/elasticsearch/elasticsearch.yml
# Copy and Paste file: /etc/elasticsearch/elasticsearch.yml
# Uncomment the following lines and change the value for each line as below.
# network.host: 127.0.0.1
# http.port: 9200
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch
curl -XGET 'http://127.0.0.1:9200/?pretty'
curl -X GET http://192.168.1.251:9200
curl -XGET '192.168.1.251:9200/_cluster/health?pretty'

echo '___________________________________________________________________'
echo '                                                                   ' 
echo ' 3 - Install and Configure Kibana Dashboard'
echo '___________________________________________________________________'
echo '                                                                   ' 
dnf install kibana

# Copy and Paste file: /etc/kibana/kibana.yml'
# Uncomment and change some lines configuration as below.
# server.port: 5601
# server.host: "127.0.0.1"
# elasticsearch.url: "http://127.0.0.1:9200"

systemctl daemon-reload
systemctl enable kibana
systemctl start kibana
systemctl status kibana
netstat -plntu

echo '___________________________________________________________________'
echo '                                                                   ' 
echo ' 4 - Setup Nginx as a Reverse Proxy for Kibana'
echo '___________________________________________________________________'
echo '                                                                   ' 
dnf install nginx httpd-tools

# Create file /etc/nginx/conf.d/kibana.conf

echo server { >> /etc/nginx/conf.d/kibana.conf
echo 	listen 80; >> /etc/nginx/conf.d/kibana.conf
echo 	server_name elk.hakase-labs.io; >> /etc/nginx/conf.d/kibana.conf
echo    auth_basic "Restricted Access"; >> /etc/nginx/conf.d/kibana.conf
echo    auth_basic_user_file /etc/nginx/.kibana-user; >> /etc/nginx/conf.d/kibana.conf
echo 	location / { >> /etc/nginx/conf.d/kibana.conf
echo        proxy_pass http://127.0.0.1:5601; >> /etc/nginx/conf.d/kibana.conf
echo 		proxy_http_version 1.1; >> /etc/nginx/conf.d/kibana.conf
echo 		proxy_set_header Upgrade $http_upgrade; >> /etc/nginx/conf.d/kibana.conf
echo 		proxy_set_header Connection 'upgrade'; >> /etc/nginx/conf.d/kibana.conf
echo 		proxy_set_header Host $host; >> /etc/nginx/conf.d/kibana.conf
echo 		proxy_cache_bypass $http_upgrade; >> /etc/nginx/conf.d/kibana.conf
echo 		} >> /etc/nginx/conf.d/kibana.conf
echo	} >> /etc/nginx/conf.d/kibana.conf

echo ' Please type password kibanaadmin for user kibanaadmin below'
htpasswd -c /etc/nginx/.kibana-user kibanaadmin
nginx -t
systemctl enable nginx
systemctl start nginx
