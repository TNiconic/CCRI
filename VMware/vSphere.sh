#!/bin/bash

#****************************************************************
#*************Written By Mitchell Gibson USACPB CRIA*************
#*************Last Updated Jul 27, 2023 v1.0*********************
#****************************************************************

clear

#Get Host Information
hostname_var=$(hostname)
ip_address=$(ip -o -4 addr show dev eth0 | awk '{print $4}' | cut -d '/' -f 1)
mac_address=$(ip -o link show dev eth0 | awk '{print $17}')
domain=$(dnsdomainname)

echo " "
echo -----------------------------------------------------------------------------------
echo ----------VMware vSphere 7.0 VAMI Security Technical Implementation Guide----------
echo -----------------------------------------------------------------------------------
echo " "

echo "Hostname:"$hostname_var 
echo "IP Address:"$ip_address
echo "MAC Address:"$mac_address
echo "FQDN:"$hostname_var.$domain
echo "Role: Member Server"
echo "Technology Area: Other Review"
echo " "
echo "------------ V-256645 ------------"
sim_requests=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null |grep "server.max-connections"|sed -e 's/^[ ]*//')
sim_requests_output="server.max-connections            = 1024"
sim_requests=$( echo "$startup_shutdown" | awk '{$1=$1};1' )
sim_requests_output=$( echo "$startup_shutdown_output" | awk '{$1=$1};1' )
if [ "$sim_requests" = "$sim_requests_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $sim_requests
fi
echo " "
echo "------------ V-256646 ------------"
fips_140v=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "ssl.cipher-list"|sed -e 's/^[ ]*//')
fips_140v_output='ssl.cipher-list                   = "!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES"'
fips_140v=$( echo "$startup_shutdown" | awk '{$1=$1};1' )
fips_140v_output=$( echo "$startup_shutdown_output" | awk '{$1=$1};1' )
if [ "$fips_140v" = "$fips_140v_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $fips_140v
fi
echo " "
echo "------------ V-256647 ------------"
crypto=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "ssl.engine"|sed -e 's/^[ ]*//')
crypto_output='ssl.engine                        = "enable"'
crypto=$( echo "$startup_shutdown" | awk '{$1=$1};1' )
crypto_output=$( echo "$startup_shutdown_output" | awk '{$1=$1};1' )
if [ "$crypto" = "$crypto_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $crypto
fi
echo " "
echo "------------ V-256648 ------------"
remote_access=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\)/'|grep mod_accesslog|sed -e 's/^[ ]*//')
remote_access_output='"mod_accesslog",'
remote_access=$( echo "$startup_shutdown" | awk '{$1=$1};1' )
remote_access_output=$( echo "$startup_shutdown_output" | awk '{$1=$1};1' )
if [ "$remote_access" = "$remote_access_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $remote_access
fi
echo " "
echo "------------ V-256649 ------------"
startup_shutdown=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "server.errorlog"|sed -e 's/^[ ]*//')
startup_shutdown_output='server.errorlog                   = "/opt/vmware/var/log/lighttpd/error.log"'
startup_shutdown=$( echo "$startup_shutdown" | awk '{$1=$1};1' )
startup_shutdown_output=$( echo "$startup_shutdown_output" | awk '{$1=$1};1' )
if [ "$startup_shutdown" = "$startup_shutdown_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $startup_shutdown
fi
echo " "
echo "------------ V-256650 ------------"
log_records=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "accesslog.format"|sed -e 's/^[ ]*//')
log_records_output=""
log_records_grep=$($log_records | grep -v '^#')
if [ "$log_records" = "$log_records_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [$log_records_output = ""]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $log_records
fi
echo " "
echo "------------ V-256651 ------------"
vami_logs=$(find /opt/vmware/var/log/lighttpd/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \;)
if [ "$vami_logs" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_logs
fi
echo " "
echo "------------ V-256652 ------------"
rsyslog_vami=$(rpm -V VMware-visl-integration|grep vmware-services-applmgmt.conf)
if [ "$rsyslog_vami" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $rsyslog_vami
fi
echo " "
echo "------------ V-256653 ------------"
vami_bins=$(rpm -qa|grep lighttpd|xargs rpm -V|grep -v -E "lighttpd.conf|vami-lighttp.service")
if [ "$vami_bins" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_bins
fi
echo " "
echo "------------ V-256654 ------------"
vami_modules=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\)/'|sed -e 's/^[ ]*//')
vami_modules_output=$(cat << EOF
server.modules = (
"mod_access",
"mod_accesslog",
"mod_proxy",
"mod_cgi",
"mod_rewrite",
"mod_magnet",
"mod_setenv",
# 7
)
EOF
)
vami_modules=$( echo "$vami_modules" | awk '{$1=$1};1' )
vami_modules_output=$( echo "$vami_modules_output" | awk '{$1=$1};1' )
if [ "$vami_modules" = "$vami_modules_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_modules
fi
echo " "
echo "------------ V-256655 ------------"
vami_mime=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/mimetype\.assign/,/\)/'|grep -E "\.sh|\.csh")
if [ "$vami_mime" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_mime
fi
echo " "
echo "------------ V-256656 ------------"
vami_mime2=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "mimetype.use-xattr"|sed 's: ::g')
vami_mime2_output='mimetype.use-xattr="disable"'
vami_mime2=$( echo "$vami_mime2" | awk '{$1=$1};1' )
vami_mime2_output=$( echo "$vami_mime2_output" | awk '{$1=$1};1' )
if [ "$vami_mime2" = "$vami_mime2_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_mime2
fi
echo " "
echo "------------ V-256657 ------------"
vami_mappings=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/cgi\.assign/,/\)/'|sed -e 's/^[ ]*//')
vami_mappings_output=$(cat << EOF
cgi.assign                        = (
".py"  => "/usr/bin/python",
".cgi" => "/usr/bin/python",
# 2
)
EOF
)
vami_mappings=$( echo "$vami_mappings" | awk '{$1=$1};1' )
vami_mappings_output=$( echo "$vami_mappings_output" | awk '{$1=$1};1' )
if [ "$vami_mappings" = "$vami_mappings_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_mappings
fi
echo " "
echo "------------ V-256658 ------------"
vami_mappings2=$(grep "url.access-deny" /opt/vmware/etc/lighttpd/lighttpd.conf)
vami_mappings2_output='url.access-deny             = ( "~", ".inc" )'
vami_mappings2=$( echo "$vami_mappings2" | awk '{$1=$1};1' )
vami_mappings2_output=$( echo "$vami_mappings2_output" | awk '{$1=$1};1' )
if [ "$vami_mappings2" = "$vami_mappings2_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_mappings2
fi
echo " "
echo "------------ V-256659 ------------"
vami_webdav=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\)/'|grep mod_webdav)
if [ "$vami_webdav" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_webdav
fi
echo " "
echo "------------ V-256660 ------------"
vami_dos=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "server.max-keep-alive-idle"|sed 's: ::g')
vami_dos_output='server.max-keep-alive-idle=30'
vami_dos=$( echo "$vami_dos" | awk '{$1=$1};1' )
vami_dos=$( echo "$vami_dos_output" | awk '{$1=$1};1' )
if [ "$vami_dos" = "$vami_dos_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_dos
fi
echo " "
echo "------------ V-256661 ------------"
vami_unauthorized=$(stat -c "%n has %a permissions and is owned by %U:%G" /etc/applmgmt/appliance/server.pem)
vami_unauthorized_output='/etc/applmgmt/appliance/server.pem has 600 permissions and is owned by root:root'
vami_unauthorized=$( echo "$vami_unauthorized" | awk '{$1=$1};1' )
vami_unauthorized=$( echo "$vami_unauthorized_output" | awk '{$1=$1};1' )
if [ "$vami_unauthorized" = "$vami_unauthorized_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_unauthorized
fi
echo " "
echo "------------ V-256662 ------------"
vami_http=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "server.max-fds"|sed 's: ::g')
vami_http_output='server.max-fds=2048'
vami_http=$( echo "$vami_http" | awk '{$1=$1};1' )
vami_http=$( echo "$vami_http_output" | awk '{$1=$1};1' )
if [ "$vami_http" = "$vami_http_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_http
fi
echo " "
echo "------------ V-256663 ------------"
vami_utf=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/mimetype\.assign/,/\)/'|grep "text/"|grep -v "charset=utf-8"|sed -e 's/^[ ]*//')
if [ "$vami_utf" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_utf
fi
echo " "
echo "------------ V-256664 ------------"
vami_dir=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "dir-listing.activate"|sed 's: ::g')
vami_dir_output='dir-listing.activate="disable"'
vami_dir=$( echo "$vami_dir" | awk '{$1=$1};1' )
vami_dir=$( echo "$vami_dir_output" | awk '{$1=$1};1' )
if [ "$vami_dir" = "$vami_dir_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_dir
fi
echo " "
echo "------------ V-256665 ------------"
vami_modstatus=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\)/'|grep mod_status)
if [ "$vami_modstatus" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_modstatus
fi
echo " "
echo "------------ V-256666 ------------"
vami_debug_logging=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "debug.log-request-handling"|sed 's: ::g')
vami_debug_logging_output='dir-listing.activate="disable"'
vami_debug_logging=$( echo "$vami_debug_logging" | awk '{$1=$1};1' )
vami_debug_logging_output=$( echo "$vami_debug_logging_output" | awk '{$1=$1};1' )
if [ "$vami_dir" = "$vami_dir_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_dir
fi
echo " "
echo "------------ V-256667 ------------"
vami_privileged=$(ps -f -U root | awk '$0 ~ /vami-lighttpd/ && $0 !~ /awk/ {print $1}')
vami_privileged_output='root'
vami_privileged=$( echo "$vami_privileged" | awk '{$1=$1};1' )
vami_privileged_output=$( echo "$vami_privileged_output" | awk '{$1=$1};1' )
if [ "$vami_privileged" = "$vami_privileged_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_privileged
fi
echo " "
echo "------------ V-256668 ------------"
vami_tls=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "ssl.use"|sed 's: ::g')
vami_tls_output=$(cat << EOF
ssl.use-sslv2="disable"
ssl.use-sslv3="disable"
ssl.use-tlsv10="disable"
ssl.use-tlsv11="disable"
ssl.use-tlsv12="enable"
EOF
)
vami_tls=$( echo "$vami_tls" | awk '{$1=$1};1' )
vami_tls_output=$( echo "$vami_tls_output" | awk '{$1=$1};1' )
if [ "$vami_tls" = "$vami_tls_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_tls
fi
echo " "
echo "------------ V-256669 ------------"
vami_cipher=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "ssl\.honor-cipher-order"|sed 's: ::g')
vami_cipher_output='ssl.honor-cipher-order = "enable"'
vami_cipher=$( echo "$vami_cipher" | awk '{$1=$1};1' )
vami_cipher_output=$( echo "$vami_cipher_output" | awk '{$1=$1};1' )
if [ "$vami_cipher" = "$vami_cipher_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_cipher
fi
echo " "
echo "------------ V-256670 ------------"
vami_cipher=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "ssl\.disable-client-renegotiation"|sed 's: ::g')
if [ "$vami_cipher" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ "$vami_cipher" = "disabled" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_cipher
fi
echo " "
echo "------------ V-256671 ------------"
vami_server=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "server.tag"|sed 's: ::g')
vami_server_output='server.tag="vami"'
vami_server=$( echo "$vami_server" | awk '{$1=$1};1' )
vami_server_output=$( echo "$vami_server_output" | awk '{$1=$1};1' )
if [ "$vami_server" = "$vami_server_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_server
fi
echo " "
echo "------------ V-256672 ------------"
vami_fips=$(/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep "server.fips-mode"|sed -e 's/^[ ]*//')
vami_fips_output='server.fips-mode                  = "enable"'
vami_fips=$( echo "$vami_fips" | awk '{$1=$1};1' )
vami_fips_output=$( echo "$vami_fips_output" | awk '{$1=$1};1' )
if [ "$vami_fips" = "$vami_fips_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $vami_fips
fi
echo " "
echo " "
echo ----------------------------------------------------------------------------------------------------
echo ----------VMware vSphere 7.0 vCenter Appliance EAM Security Technical Implementation Guide----------
echo ----------------------------------------------------------------------------------------------------
echo " "

echo "------------ V-256673 ------------"
esx_keepalive=$(xmllint --xpath '/Server/Service/Connector/@connectionTimeout' /usr/lib/vmware-eam/web/conf/server.xml)
esx_keepalive_output='connectionTimeout="60000"'
esx_keepalive=$( echo "$esx_keepalive" | awk '{$1=$1};1' )
esx_keepalive_output=$( echo "$esx_keepalive_output" | awk '{$1=$1};1' )
if [ "$esx_keepalive" = "$esx_keepalive_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_keepalive
fi
echo " "
echo "------------ V-256674 ------------"
esx_concurrent=$(xmllint --xpath '/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads' /usr/lib/vmware-eam/web/conf/server.xml)
esx_concurrent_output='maxThreads="300"'
esx_concurrent=$( echo "$esx_concurrent" | awk '{$1=$1};1' )
esx_concurrent_output=$( echo "$esx_concurrent_output" | awk '{$1=$1};1' )
if [ "$esx_concurrent" = "$esx_concurrent_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_concurrent
fi
echo " "
echo "------------ V-256675 ------------"
esx_post=$(xmllint --xpath '/Server/Service/Connector/@maxPostSize' /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_post=$( echo "$esx_post" | awk '{$1=$1};1' )
if [  -z "$esx_post" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_post
fi
echo " "
echo "------------ V-256676 ------------"
esx_xss=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' -)
esx_xss_output='<http-only>true</http-only>'
esx_xss=$( echo "$esx_xss" | awk '{$1=$1};1' )
esx_xss_output=$( echo "$esx_xss_output" | awk '{$1=$1};1' )
if [ "$esx_xss" = "$esx_xss_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_xss
fi
echo " "
echo "------------ V-256677 ------------"
esx_user_access=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-eam/web/conf/server.xml)
esx_user_access_output='pattern="%h %{X-Forwarded-For}i %l %u %t [%I] &quot;%r&quot; %s %b [Processing time %D msec] &quot;%{User-Agent}i&quot;"'
esx_user_access=$( echo "$esx_user_access" | awk '{$1=$1};1' )
esx_user_access_output=$( echo "$esx_user_access_output" | awk '{$1=$1};1' )
if [ "$esx_user_access" = "$esx_user_access_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_user_access
fi
echo " "
echo "------------ V-256678 ------------"
esx_log_system=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/eam.json)
esx_log_system_output='"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/eam/jvm.log",'
esx_log_system=$( echo "$esx_log_system" | awk '{$1=$1};1' )
esx_log_system_output=$( echo "$esx_log_system_output" | awk '{$1=$1};1' )
if [ "$esx_log_system" = "$esx_log_system_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_log_system
fi
echo " "
echo "------------ V-256679 ------------"
esx_priv_users=$(find /var/log/vmware/eam/web/ -xdev -type f -a '(' -perm -o+w -o -not -user eam -o -not -group users ')' -exec ls -ld {} \;)
if [ "$esx_priv_users" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_priv_users
fi
echo " "
echo "------------ V-256680 ------------"
esx_file_integrity=$(rpm -V vmware-eam|grep "^..5......" | grep -v 'c /' | grep -v -E ".installer|.properties|.xml")
if [ "$esx_file_integrity" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_file_integrity
fi
echo " "
echo "------------ V-256681 ------------"
esx_web_app=$(ls -A /usr/lib/vmware-eam/web/webapps)
esx_web_app_output='eam'
esx_web_app=$( echo "$esx_web_app" | awk '{$1=$1};1' )
esx_web_app_output=$( echo "$esx_web_app_output" | awk '{$1=$1};1' )
if [ "$esx_web_app" = "$esx_web_app_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_web_app
fi
echo " "
echo "------------ V-256682 ------------"
esx_unsupported_realms=$(grep UserDatabaseRealm /usr/lib/vmware-eam/web/conf/server.xml)
if [ "$esx_unsupported_realms" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_unsupported_realms
fi
echo " "
