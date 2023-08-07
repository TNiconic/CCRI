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
echo "------------ V-256683 ------------"
esx_internal_packages=$(awk -F'=' '/^package.access=/{print; for (i=1; i<=5; i++) {getline; print}}' /etc/vmware-eam/catalina.properties)
esx_internal_packages_output=$(cat << EOF
package.access=\\ 
sun.,\\ 
org.apache.catalina.,\\ 
org.apache.coyote.,\\ 
org.apache.tomcat.,\\ 
org.apache.jasper.
EOF
)
esx_internal_packages=$( echo "$esx_internal_packages" | awk '{$1=$1};1' )
esx_internal_packages_output=$( echo "$esx_internal_packages_output" | awk '{$1=$1};1' )
if [ "$esx_internal_packages" = "$esx_internal_packages_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_internal_packages
fi
echo " "
echo "------------ V-256684 ------------"
esx_mime_shell=$(grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)' /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml)
if [ "$esx_mime_shell" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_mime_shell
fi
echo " "
echo "------------ V-256685 ------------"
esx_java_mappings=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/servlet-mapping/servlet-name[text()="JspServlet"]/parent::servlet-mapping' -)
esx_java_mappings_output=$(cat << EOF
<servlet-mapping>
    <servlet-name>JspServlet</servlet-name>
    <url-pattern>*.jsp</url-pattern>
  </servlet-mapping>
EOF
)
esx_java_mappings=$( echo "$esx_java_mappings" | awk '{$1=$1};1' )
esx_java_mappings_output=$( echo "$esx_java_mappings_output" | awk '{$1=$1};1' )
if [ "$esx_java_mappings" = "$esx_java_mappings_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_java_mappings
fi
echo " "
echo "------------ V-256686 ------------"
esx_webdav=$(grep -n 'webdav' /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml)
if [ "$esx_webdav" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_webdav
fi
echo " "
echo "------------ V-256687 ------------"
esx_leak_protection=$(grep JreMemoryLeakPreventionListener /usr/lib/vmware-eam/web/conf/server.xml)
esx_leak_protection_output=$(cat << EOF
<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>
EOF
)
esx_leak_protection=$( echo "$esx_leak_protection" | awk '{$1=$1};1' )
esx_leak_protection_output=$( echo "$esx_leak_protection_output" | awk '{$1=$1};1' )
if [ "$esx_leak_protection" = "$esx_leak_protection_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_leak_protection
fi
echo " "
echo "------------ V-256688 ------------"
esx_web_dir=$(find /usr/lib/vmware-eam/web/webapps/ -type l -ls)
if [ "$esx_web_dir" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_web_dir
fi
echo " "
echo "------------ V-256689 ------------"
esx_dir_tree=$(find /usr/lib/vmware-eam/web/ -xdev -type f -a '(' -not -user root -o -not -group root ')' -exec ls -ld {} \;)
if [ "$esx_dir_tree" = "" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_dir_tree
fi
echo " "
echo "------------ V-256690 ------------"
esx_safe_state=$(grep EXIT_ON_INIT_FAILURE /etc/vmware-eam/catalina.properties)
esx_safe_state_output=$(cat << EOF
org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
EOF
)
esx_safe_state=$( echo "$esx_safe_state" | awk '{$1=$1};1' )
esx_safe_state_output=$( echo "$esx_safe_state_output" | awk '{$1=$1};1' )
if [ "$esx_safe_state" = "$esx_safe_state_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_safe_state
fi
echo " "
echo "------------ V-256691 ------------"
esx_allowed_connections=$(xmllint --xpath '/Server/Service/Connector/@acceptCount' /usr/lib/vmware-eam/web/conf/server.xml)
esx_allowed_connections_output=$(cat << EOF
acceptCount="300"
EOF
)
esx_allowed_connections=$( echo "$esx_allowed_connections" | awk '{$1=$1};1' )
esx_allowed_connections_output=$( echo "$esx_allowed_connections_output" | awk '{$1=$1};1' )
if [ "$esx_allowed_connections" = "$esx_allowed_connections_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_allowed_connections
fi
echo " "
echo "------------ V-256692 ------------"
esx_uriencoding=$(xmllint --xpath '/Server/Service/Connector/@URIEncoding' /usr/lib/vmware-eam/web/conf/server.xml)
esx_uriencoding_output=$(cat << EOF
URIEncoding="UTF-8"
EOF
)
esx_uriencoding=$( echo "$esx_uriencoding" | awk '{$1=$1};1' )
esx_uriencoding_output=$( echo "$esx_uriencoding_output" | awk '{$1=$1};1' )
if [ "$esx_uriencoding" = "$esx_uriencoding_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_uriencoding
fi
echo " "
echo "------------ V-256693 ------------"
esx_character_encoding=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/filter-mapping/filter-name[text()="setCharacterEncodingFilter"]/parent::filter-mapping' -)
esx_character_encoding_output=$(cat << EOF
<filter-mapping>
    <filter-name>setCharacterEncodingFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
EOF
)
esx_character_encoding=$( echo "$esx_character_encoding" | awk '{$1=$1};1' )
esx_character_encoding_output=$( echo "$esx_character_encoding_output" | awk '{$1=$1};1' )
if [ "$esx_character_encoding" = "$esx_character_encoding_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_character_encoding
fi
echo " "
echo "------------ V-256694 ------------"
esx_web_default=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/welcome-file-list' -)
esx_web_default_output=$(cat << EOF
<welcome-file-list>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
EOF
)
esx_web_default=$( echo "$esx_web_default" | awk '{$1=$1};1' )
esx_web_default_output=$( echo "$esx_web_default_output" | awk '{$1=$1};1' )
if [ "$esx_web_default" = "$esx_web_default_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_web_default
fi
echo " "
echo "------------ V-256695 ------------"
esx_dir_listings=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' - 2>/dev/null)
esx_dir_listings=$( echo "$esx_dir_listings" | awk '{$1=$1};1' )
if [  -z "$esx_dir_listings" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_dir_listings
fi
echo " "
echo "------------ V-256696 ------------"
esx_error_pages=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/error-page/exception-type["text()=java.lang.Throwable"]/parent::error-page' -)
esx_error_pages_output=$(cat << EOF
<error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/error.jsp</location>
  </error-page>
EOF
)
esx_error_pages=$( echo "$esx_error_pages" | awk '{$1=$1};1' )
esx_error_pages_output=$( echo "$esx_error_pages_output" | awk '{$1=$1};1' )
if [ "$esx_error_pages" = "$esx_error_pages_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_error_pages
fi
echo " "
echo "------------ V-256697 ------------"
esx_error_reports=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-eam/web/conf/server.xml)
esx_error_reports_output=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>
EOF
)
esx_error_reports=$( echo "$esx_error_reports" | awk '{$1=$1};1' )
esx_error_reports_output=$( echo "$esx_error_reports_output" | awk '{$1=$1};1' )
if [ "$esx_error_reports" = "$esx_error_reports_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_error_reports
fi
echo " "
echo "------------ V-256698 ------------"
esx_server_version=$(xmllint --xpath '/Server/Service/Connector/@server' /usr/lib/vmware-eam/web/conf/server.xml)
esx_server_version_output=$(cat << EOF
server="Anonymous"
EOF
)
esx_server_version=$( echo "$esx_server_version" | awk '{$1=$1};1' )
esx_server_version_output=$( echo "$esx_server_version_output" | awk '{$1=$1};1' )
if [ "$esx_server_version" = "$esx_server_version_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_server_version
fi
echo " "
echo "------------ V-256699 ------------"
esx_trace_requests=$(grep allowTrace /usr/lib/vmware-eam/web/conf/server.xml)
esx_trace_requests_output=$(cat << EOF
false
EOF
)
esx_trace_requests=$( echo "$esx_trace_requests" | awk '{$1=$1};1' )
esx_trace_requests_output=$( echo "$esx_trace_requests_output" | awk '{$1=$1};1' )
if [ "$esx_trace_requests" = "$esx_trace_requests_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$esx_trace_requests" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_trace_requests
fi
echo " "
echo "------------ V-256700 ------------"
esx_debug_disabled=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="debug"]/parent::init-param' - 2>/dev/null)
esx_debug_disabled_output=$(cat << EOF
<init-param>
      <param-name>debug</param-name>
      <param-value>0</param-value>
</init-param>
EOF
)
esx_debug_disabled=$( echo "$esx_debug_disabled" | awk '{$1=$1};1' )
esx_debug_disabled_output=$( echo "$esx_debug_disabled_output" | awk '{$1=$1};1' )
if [ "$esx_debug_disabled" = "$esx_debug_disabled_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$esx_debug_disabled" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_debug_disabled
fi
echo " "
echo "------------ V-256701 ------------"
esx_log_files=$(rpm -V VMware-visl-integration|grep vmware-services-eam.conf|grep "^..5......")
esx_log_files=$( echo "$esx_log_files" | awk '{$1=$1};1' )
if [  -z "$esx_log_files" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_log_files
fi
echo " "
echo "------------ V-256702 ------------"
esx_secure_cookies=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' -)
esx_secure_cookies_output=$(cat << EOF
<secure>true</secure>
EOF
)
esx_secure_cookies=$( echo "$esx_secure_cookies" | awk '{$1=$1};1' )
esx_secure_cookies_output=$( echo "$esx_secure_cookies_output" | awk '{$1=$1};1' )
if [ "$esx_secure_cookies" = "$esx_secure_cookies_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_secure_cookies
fi
echo " "
echo "------------ V-256703 ------------"
esx_appropriate_ports=$(grep 'bio.http.port' /etc/vmware-eam/catalina.properties)
esx_appropriate_ports_output=$(cat << EOF
bio.http.port=15005
EOF
)
esx_appropriate_ports=$( echo "$esx_appropriate_ports" | awk '{$1=$1};1' )
esx_appropriate_ports_output=$( echo "$esx_appropriate_ports_output" | awk '{$1=$1};1' )
if [ "$esx_appropriate_ports" = "$esx_appropriate_ports_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_appropriate_ports
fi
echo " "
echo "------------ V-256704 ------------"
esx_shutdown_port=$(grep 'base.shutdown.port' /etc/vmware-eam/catalina.properties)
esx_shutdown_port_output=$(cat << EOF
base.shutdown.port=-1
EOF
)
esx_shutdown_port=$( echo "$esx_shutdown_port" | awk '{$1=$1};1' )
esx_shutdown_port_output=$( echo "$esx_shutdown_port_output" | awk '{$1=$1};1' )
if [ "$esx_shutdown_port" = "$esx_shutdown_port_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_shutdown_port
fi
echo " "
echo "------------ V-256705 ------------"
esx_servlet_readonly=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed '2 s/xmlns=".*"//g' | xmllint --xpath '/web-app/servlet/servlet-name[text()="default"]/../init-param/param-name[text()="readonly"]/../param-value[text()="false"]' - 2>/dev/null)
esx_servlet_readonly=$( echo "$esx_servlet_readonly" | awk '{$1=$1};1' )
if [  -z "$esx_servlet_readonly" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_servlet_readonly
fi
echo " "
echo " "
echo ---------------------------------------------------------------------------------------------------------------
echo ----------VMware vSphere 7.0 vCenter Appliance Lookup Service Security Technical Implementation Guide----------
echo ---------------------------------------------------------------------------------------------------------------
echo " "
echo "------------ V-256706 ------------"
lookup_keep_alive=$(xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@connectionTimeout' /usr/lib/vmware-lookupsvc/conf/server.xml)
lookup_keep_alive_output=$(cat << EOF
connectionTimeout="60000"
EOF
)
lookup_keep_alive=$( echo "$lookup_keep_alive" | awk '{$1=$1};1' )
lookup_keep_alive_output=$( echo "$lookup_keep_alive_output" | awk '{$1=$1};1' )
if [ "$lookup_keep_alive" = "$lookup_keep_alive_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_keep_alive
fi
echo " "
echo "------------ V-256707 ------------"
concurrent_lookup=$(xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@maxThreads' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
concurrent_lookup=$( echo "$concurrent_lookup" | awk '{$1=$1};1' )
if [  -z "$concurrent_lookup" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $concurrent_lookup
fi
echo " "
echo "------------ V-256708 ------------"
post_request_lookup=$(xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@maxPostSize' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
post_request_lookup=$( echo "$post_request_lookup" | awk '{$1=$1};1' )
if [  -z "$post_request_lookup" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $post_request_lookup
fi
echo " "
echo "------------ V-256709 ------------"
lookup_xss=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/context.xml | xmllint --xpath '/Context/@useHttpOnly' - 2>/dev/null)
lookup_xss_output=$(cat << EOF
useHttpOnly="true"
EOF
)
lookup_xss=$( echo "$lookup_xss" | awk '{$1=$1};1' )
lookup_xss_output=$( echo "$lookup_xss_output" | awk '{$1=$1};1' )
if [ "$lookup_xss" = "$lookup_xss_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_xss
fi
echo " "
echo "------------ V-256710 ------------"
lookup_remote_access=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-lookupsvc/conf/server.xml)
lookup_remote_access_output=$(cat << EOF
pattern="%t %I [RemoteIP] %{X-Forwarded-For}i %u [Request] %h:%{remote}p to local %{local}p - %H %m %U%q    [Response] %s - %b bytes    [Perf] process %Dms / commit %Fms / conn [%X]"
EOF
)
lookup_remote_access=$( echo "$lookup_remote_access" | awk '{$1=$1};1' )
lookup_remote_access_output=$( echo "$lookup_remote_access_output" | awk '{$1=$1};1' )
if [ "$lookup_remote_access" = "$lookup_remote_access_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_remote_access
fi
echo " "
echo "------------ V-256711 ------------"
lookup_startup_shutdown=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/lookupsvc.json)
lookup_startup_shutdown_output=$(cat << EOF
"StreamRedirectFile": "%VMWARE_LOG_DIR%/vmware/lookupsvc/lookupsvc_stream.log",
EOF
)
lookup_startup_shutdown=$( echo "$lookup_startup_shutdown" | awk '{$1=$1};1' )
lookup_startup_shutdown_output=$( echo "$lookup_startup_shutdown_output" | awk '{$1=$1};1' )
if [ "$lookup_startup_shutdown" = "$lookup_startup_shutdown_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$lookup_startup_shutdown"]; then
    echo -e "\e[31mOpen\e[0m"
    echo "No log file detected"
fi
echo " "
echo "------------ V-256712 ------------"
lookup_privileged_users=$(find /var/log/vmware/lookupsvc -xdev -type f ! -name lookupsvc-init.log -a '(' -perm -o+w -o -not -user lookupsvc -o -not -group lookupsvc ')' -exec ls -ld {} \; 2>/dev/null)
lookup_privileged_users=$( echo "$lookup_privileged_users" | awk '{$1=$1};1' )
if [  -z "$lookup_privileged_users" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_privileged_users
fi
echo " "
echo "------------ V-256713 ------------"
lookup_file_integrity=$(rpm -V vmware-lookupsvc|grep "^..5......"|grep -E "\.war|\.jar|\.sh|\.py")
lookup_file_integrity=$( echo "$lookup_file_integrity" | awk '{$1=$1};1' )
if [  -z "$lookup_file_integrity" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_file_integrity
fi
echo " "
echo "------------ V-256714 ------------"
lookup_web_app=$(ls -A /usr/lib/vmware-lookupsvc/webapps/*.war)
lookup_web_app_output=$(cat << EOF
/usr/lib/vmware-lookupsvc/webapps/ROOT.war
EOF
)
lookup_web_app=$( echo "$lookup_web_app" | awk '{$1=$1};1' )
lookup_web_app_output=$( echo "$lookup_web_app_output" | awk '{$1=$1};1' )
if [ "$lookup_web_app" = "$lookup_web_app_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_xss
fi
echo " "
echo "------------ V-256715 ------------"
lookup_userdatabaserealm_disabled=$(grep UserDatabaseRealm /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
lookup_userdatabaserealm_disabled=$( echo "$lookup_userdatabaserealm_disabled" | awk '{$1=$1};1' )
if [  -z "$lookup_userdatabaserealm_disabled" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_userdatabaserealm_disabled
fi
echo " "
echo "------------ V-256716 ------------"
lookup_internal_packages=$(grep "package.access" /usr/lib/vmware-lookupsvc/conf/catalina.properties)
lookup_internal_packages_output=$(cat << EOF
package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat.,org.apache.jasper.
EOF
)
lookup_internal_packages=$( echo "$lookup_internal_packages" | awk '{$1=$1};1' )
lookup_internal_packages_output=$( echo "$lookup_internal_packages_output" | awk '{$1=$1};1' )
if [ "$lookup_internal_packages" = "$lookup_internal_packages_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_internal_packages
fi
echo " "
echo "------------ V-256717 ------------"
lookup_mime_disabled=$(grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)' /usr/lib/vmware-lookupsvc/conf/web.xml)
lookup_mime_disabled=$( echo "$lookup_mime_disabled" | awk '{$1=$1};1' )
if [  -z "$lookup_mime_disabled" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_mime_disabled
fi
echo " "
echo "------------ V-256718 ------------"
lookup_java_servlet=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/servlet-mapping/servlet-name[text()="jsp"]/parent::servlet-mapping' -)
lookup_java_servlet_output=$(cat << EOF
<servlet-mapping>
    <servlet-name>jsp</servlet-name>
    <url-pattern>*.jsp</url-pattern>
    <url-pattern>*.jspx</url-pattern>
</servlet-mapping>
EOF
)
lookup_java_servlet=$( echo "$lookup_java_servlet" | awk '{$1=$1};1' )
lookup_java_servlet_output=$( echo "$lookup_java_servlet_output" | awk '{$1=$1};1' )
if [ "$lookup_java_servlet" = "$lookup_java_servlet_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_java_servlet
fi
echo " "
echo "------------ V-256719 ------------"
lookup_webdav_installed=$(grep -n 'webdav' /usr/lib/vmware-lookupsvc/conf/web.xml)
lookup_webdav_installed=$( echo "$lookup_webdav_installed" | awk '{$1=$1};1' )
if [  -z "$lookup_webdav_installed" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_webdav_installed
fi
echo " "
echo "------------ V-256720 ------------"
lookup_memory_leak=$(grep JreMemoryLeakPreventionListener /usr/lib/vmware-lookupsvc/conf/server.xml)
lookup_memory_leak_output=$(cat << EOF
<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>
EOF
)
lookup_memory_leak=$( echo "$lookup_memory_leak" | awk '{$1=$1};1' )
lookup_memory_leak_output=$( echo "$lookup_memory_leak_output" | awk '{$1=$1};1' )
if [ "$lookup_memory_leak" = "$lookup_memory_leak_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_memory_leak
fi
echo " "
echo "------------ V-256721 ------------"
lookup_symbolic_links=$(find /usr/lib/vmware-vsphere-ui/server/static/ -type l -ls 2>/dev/null)
lookup_symbolic_links=$( echo "$lookup_symbolic_links" | awk '{$1=$1};1' )
if [  -z "$lookup_symbolic_links" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_symbolic_links
fi
echo " "
echo "------------ V-256721 ------------"
lookup_dirtree_permissions=$(find  /usr/lib/vmware-lookupsvc/lib  /usr/lib/vmware-lookupsvc/conf -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
lookup_dirtree_permissions=$( echo "$lookup_dirtree_permissions" | awk '{$1=$1};1' )
if [  -z "$lookup_dirtree_permissions" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_dirtree_permissions
fi
echo " "
echo "------------ V-256723 ------------"
lookup_init_fail=$(grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-lookupsvc/conf/catalina.properties)
lookup_init_fail_output=$(cat << EOF
org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
EOF
)
lookup_init_fail=$( echo "$lookup_init_fail" | awk '{$1=$1};1' )
lookup_init_fail_output=$( echo "$lookup_init_fail_output" | awk '{$1=$1};1' )
if [ "$lookup_init_fail" = "$lookup_init_fail_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_init_fail
fi
echo " "
echo "------------ V-256724 ------------"
lookup_allowed_connections=$(xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@acceptCount' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
lookup_allowed_connections_output=$(cat << EOF
acceptCount="100"
EOF
)
lookup_allowed_connections=$( echo "$lookup_allowed_connections" | awk '{$1=$1};1' )
lookup_allowed_connections_output=$( echo "$lookup_allowed_connections_output" | awk '{$1=$1};1' )
if [ "$lookup_allowed_connections" = "$lookup_allowed_connections_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_allowed_connections
fi
echo " "
echo "------------ V-256725 ------------"
lookup_uri_encoding=$(xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@URIEncoding' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
lookup_uri_encoding_output=$(cat << EOF
URIEncoding="UTF-8"
EOF
)
lookup_uri_encoding=$( echo "$lookup_uri_encoding" | awk '{$1=$1};1' )
lookup_uri_encoding_output=$( echo "$lookup_uri_encoding_output" | awk '{$1=$1};1' )
if [ "$lookup_uri_encoding" = "$lookup_uri_encoding_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_uri_encoding
fi
echo " "
echo "------------ V-256726 ------------"
lookup_default_web=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/welcome-file-list' - 2>/dev/null)
lookup_default_web_output=$(cat << EOF
<welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.htm</welcome-file>
    <welcome-file>index.jsp</welcome-file>
</welcome-file-list>
EOF
)
lookup_default_web=$( echo "$lookup_default_web" | awk '{$1=$1};1' )
lookup_default_web_output=$( echo "$lookup_default_web_output" | awk '{$1=$1};1' )
if [ "$lookup_default_web" = "$lookup_default_web_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_default_web
fi
echo " "
echo "------------ V-256727 ------------"
lookup_dir_listings=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/..' - 2>/dev/null)
lookup_dir_listings_output=$(cat << EOF
<init-param>
      <param-name>listings</param-name>
      <param-value>false</param-value>
</init-param>
EOF
)
lookup_dir_listings=$( echo "$lookup_dir_listings" | awk '{$1=$1};1' )
lookup_dir_listings_output=$( echo "$lookup_dir_listings_output" | awk '{$1=$1};1' )
if [ "$lookup_dir_listings" = "$lookup_dir_listings_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_dir_listings
fi
echo " "
echo "------------ V-256728 ------------"
lookup_server_version=$(xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@server' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
lookup_server_version_output=$(cat << EOF
server="Anonymous"
EOF
)
lookup_server_version=$( echo "$lookup_server_version" | awk '{$1=$1};1' )
lookup_server_version_output=$( echo "$lookup_server_version_output" | awk '{$1=$1};1' )
if [ "$lookup_server_version" = "$lookup_server_version_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_server_version
fi
echo " "
echo "------------ V-256729 ------------"
lookup_error_page=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
lookup_error_page_output=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>
EOF
)
lookup_error_page_output_2=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false"/>
EOF
)
lookup_error_page=$( echo "$lookup_error_page" | awk '{$1=$1};1' )
lookup_error_page_output=$( echo "$lookup_error_page_output" | awk '{$1=$1};1' )
lookup_error_page_output_2=$( echo "$lookup_error_page_output_2" | awk '{$1=$1};1' )
if [ "$lookup_error_page" = "$lookup_error_page_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ "$lookup_error_page" = "$lookup_error_page_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_error_page
fi
echo " "
echo "------------ V-256730 ------------"
lookup_trace_requests=$(grep allowTrace /usr/lib/vmware-lookupsvc/conf/server.xml)
lookup_trace_requests=$( echo "$lookup_trace_requests" | awk '{$1=$1};1' )
if [[ -z $lookup_trace_requests ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ $lookup_trace_requests =~ "true" ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_trace_requests
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256731 ------------"
lookup_debug_option=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="debug"]/..' - 2>/dev/null)
lookup_debug_option_output=$(cat << EOF
<init-param>
  <param-name>debug</param-name>
  <param-value>0</param-value>
</init-param>
EOF
)
lookup_debug_option=$( echo "$lookup_debug_option" | awk '{$1=$1};1' )
lookup_debug_option_output=$( echo "$lookup_debug_option_output" | awk '{$1=$1};1' )
if [ "$lookup_debug_option" = "$lookup_debug_option_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_debug_option
fi
echo " "
echo "------------ V-256732 ------------"
lookup_storage_capacity=$(rpm -V vmware-lookupsvc|grep logging.properties|grep "^..5......")
lookup_storage_capacity=$( echo "$lookup_storage_capacity" | awk '{$1=$1};1' )
if [  -z "$lookup_storage_capacity" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_storage_capacity
fi
echo " "
echo "------------ V-256733 ------------"
lookup_central_log=$(rpm -V VMware-visl-integration|grep vmware-services-lookupsvc.conf)
lookup_central_log=$( echo "$lookup_central_log" | awk '{$1=$1};1' )
if [  -z "$lookup_central_log" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_central_log
fi
echo " "
echo "------------ V-256734 ------------"
lookup_appro_port=$(grep '\.port' /usr/lib/vmware-lookupsvc/conf/catalina.properties)
lookup_appro_port_output=$(cat << EOF
base.shutdown.port=-1
base.jmx.port=-1
bio-custom.http.port=7090
bio-custom.https.port=8443
EOF
)
lookup_appro_port=$( echo "$lookup_appro_port" | awk '{$1=$1};1' )
lookup_appro_port_output=$( echo "$lookup_appro_port_output" | awk '{$1=$1};1' )
if [ "$lookup_appro_port" = "$lookup_appro_port_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_appro_port
fi
echo " "
echo "------------ V-256735 ------------"
lookup_shutdown_port=$(xmllint --xpath '/Server/@port' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
lookup_shutdown_port_output=$(cat << 'EOF'
port="${base.shutdown.port}"
EOF
)
lookup_shutdown_port=$( echo "$lookup_shutdown_port" | awk '{$1=$1};1' )
lookup_shutdown_port_output=$( echo "$lookup_shutdown_port_output" | awk '{$1=$1};1' )
if [ "$lookup_shutdown_port" = "$lookup_shutdown_port_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo "$lookup_shutdown_port"
fi
echo " "
echo "------------ V-256736 ------------"
lookup_secure_cookies=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' - 2>/dev/null)
lookup_secure_cookies_output=$(cat << EOF
<secure>true</secure>
EOF
)
lookup_secure_cookies=$( echo "$lookup_secure_cookies" | awk '{$1=$1};1' )
lookup_secure_cookies_output=$( echo "$lookup_secure_cookies_output" | awk '{$1=$1};1' )
if [ "$lookup_secure_cookies" = "$lookup_secure_cookies_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $lookup_secure_cookies
fi
echo " "
echo " "
echo -----------------------------------------------------------------------------------------------------------
echo ----------VMware vSphere 7.0 vCenter Appliance Perfcharts Security Technical Implementation Guide----------
echo -----------------------------------------------------------------------------------------------------------
echo " "
echo "------------ V-256611 ------------"
pc_keep_alive=$(xmllint --xpath '/Server/Service/Connector/@connectionTimeout' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
pc_keep_alive_output=$(cat << EOF
connectionTimeout="20000"
EOF
)
pc_keep_alive=$( echo "$pc_keep_alive" | awk '{$1=$1};1' )
pc_keep_alive_output=$( echo "$pc_keep_alive_output" | awk '{$1=$1};1' )
if [ "$pc_keep_alive" = "$pc_keep_alive_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_keep_alive
fi
echo " "
echo "------------ V-256612 ------------"
pc_concurrent_connections=$(xmllint --xpath '/Server/Service/Executor/@maxThreads' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
pc_concurrent_connections_output=$(cat << EOF
maxThreads="300"
EOF
)
pc_concurrent_connections=$( echo "$pc_concurrent_connections" | awk '{$1=$1};1' )
pc_concurrent_connections_output=$( echo "$pc_concurrent_connections_output" | awk '{$1=$1};1' )
if [ "$pc_concurrent_connections" = "$pc_concurrent_connections_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_concurrent_connections
fi
echo " "
echo "------------ V-256613 ------------"
pc_post_request=$(xmllint --xpath '/Server/Service/Connector/@maxPostSize' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
pc_post_request=$( echo "$pc_post_request" | awk '{$1=$1};1' )
if [  -z "$pc_post_request" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_post_request
fi
echo " "
echo "------------ V-256614 ------------"
pc_xss=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed '2 s/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' - 2>/dev/null)
pc_xss_output=$(cat << EOF
<http-only>true</http-only>
EOF
)
pc_xss=$( echo "$pc_xss" | awk '{$1=$1};1' )
pc_xss_output=$( echo "$pc_xss_output" | awk '{$1=$1};1' )
if [ "$pc_xss" = "$pc_xss_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_xss
fi
echo " "
echo "------------ V-256615 ------------"
pc_monitor_remote=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml | sed '2 s/xmlns=".*"//g' |  xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' - 2>/dev/null)
pc_monitor_remote_output=$(cat << EOF
pattern="%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b &quot;%{User-Agent}i&quot;"
EOF
)
pc_monitor_remote=$( echo "$pc_monitor_remote" | awk '{$1=$1};1' )
pc_monitor_remote_output=$( echo "$pc_monitor_remote_output" | awk '{$1=$1};1' )
if [ "$pc_monitor_remote" = "$pc_monitor_remote_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_monitor_remote
fi
echo " "
echo "------------ V-256616 ------------"
pc_startup_shutdown=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/perfcharts.json)
pc_startup_shutdown_output=$(cat << EOF
"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/perfcharts/vmware-perfcharts-runtime.log",
EOF
)
pc_startup_shutdown=$( echo "$pc_startup_shutdown" | awk '{$1=$1};1' )
pc_startup_shutdown_output=$( echo "$pc_startup_shutdown_output" | awk '{$1=$1};1' )
if [ "$pc_startup_shutdown" = "$pc_startup_shutdown_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_startup_shutdown
fi
echo " "
echo "------------ V-256617 ------------"
pc_priv_users=$(find /storage/log/vmware/perfcharts/ -xdev -type f -a '(' -perm -o+w -o -not -user perfcharts -o -not -group users ')' -exec ls -ld {} \; 2>/dev/null)
pc_priv_users=$( echo "$pc_priv_users" | awk '{$1=$1};1' )
if [  -z "$pc_priv_users" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_priv_users
fi
echo " "
echo "------------ V-256618 ------------"
pc_file_integrity=$(rpm -V VMware-perfcharts|grep "^..5......"|grep -v -E "\.properties|\.conf|\.xml|\.password")
pc_file_integrity=$( echo "$pc_file_integrity" | awk '{$1=$1};1' )
if [  -z "$pc_file_integrity" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_file_integrity
fi
echo " "
echo "------------ V-256619 ------------"
pc_one_webapp=$(ls -A /usr/lib/vmware-perfcharts/tc-instance/webapps)
pc_one_webapp_output=$(cat << EOF
statsreport
EOF
)
pc_one_webapp=$( echo "$pc_one_webapp" | awk '{$1=$1};1' )
pc_one_webapp_output=$( echo "$pc_one_webapp_output" | awk '{$1=$1};1' )
if [ "$pc_one_webapp" = "$pc_one_webapp_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_one_webapp
fi
echo " "
echo "------------ V-256620 ------------"
pc_unsupported_realms=$(grep UserDatabaseRealm /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml)
pc_unsupported_realms=$( echo "$pc_unsupported_realms" | awk '{$1=$1};1' )
if [  -z "$pc_unsupported_realms" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_unsupported_realms
fi
echo " "
echo "------------ V-256621 ------------"
pc_internal_packages=$(grep "package.access" /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties)
pc_internal_packages_output=$(cat << EOF
package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.,org.apache.tomcat.
EOF
)
pc_internal_packages=$( echo "$pc_internal_packages" | awk '{$1=$1};1' )
pc_internal_packages_output=$( echo "$pc_internal_packages_output" | awk '{$1=$1};1' )
if [ "$pc_internal_packages" = "$pc_internal_packages_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_internal_packages
fi
echo " "
echo "------------ V-256622 ------------"
pc_mime_disabled=$(grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)' /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml)
pc_mime_disabled=$( echo "$pc_mime_disabled" | awk '{$1=$1};1' )
if [  -z "$pc_mime_disabled" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_mime_disabled
fi
echo " "
echo "------------ V-256623 ------------"
pc_servlet_pages=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/servlet-mapping/servlet-name[text()="jsp"]/parent::servlet-mapping' - 2>/dev/null)
pc_servlet_pages_output=$(cat << EOF
<servlet-mapping>
    <servlet-name>jsp</servlet-name>
    <url-pattern>*.jsp</url-pattern>
    <url-pattern>*.jspx</url-pattern>
</servlet-mapping>
EOF
)
pc_servlet_pages=$( echo "$pc_servlet_pages" | awk '{$1=$1};1' )
pc_servlet_pages_output=$( echo "$pc_servlet_pages_output" | awk '{$1=$1};1' )
if [ "$pc_servlet_pages" = "$pc_servlet_pages_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_servlet_pages
fi
echo " "
echo "------------ V-256624 ------------"
pc_webdav_installed=$(grep -n 'webdav' /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml)
pc_webdav_installed=$( echo "$pc_webdav_installed" | awk '{$1=$1};1' )
if [  -z "$pc_webdav_installed" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_webdav_installed
fi
echo " "
echo "------------ V-256625 ------------"
pc_memory_leak=$(grep JreMemoryLeakPreventionListener /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml)
pc_memory_leak_output=$(cat << EOF
<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>
EOF
)
pc_memory_leak=$( echo "$pc_memory_leak" | awk '{$1=$1};1' )
pc_memory_leak_output=$( echo "$pc_memory_leak_output" | awk '{$1=$1};1' )
if [ "$pc_memory_leak" = "$pc_memory_leak_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_memory_leak
fi
echo " "
echo "------------ V-256626 ------------"
pc_dir_tree=$(find /usr/lib/vmware-perfcharts/tc-instance/webapps/ -type l -ls)
pc_dir_tree=$( echo "$pc_dir_tree" | awk '{$1=$1};1' )
if [  -z "$pc_dir_tree" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_dir_tree
fi
echo " "
echo "------------ V-256627 ------------"
pc_permissions_state=$(find /usr/lib/vmware-perfcharts/tc-instance/webapps/ -xdev -type f -a '(' -not -user root -a -not -user perfcharts -o -not -group root ')' -exec ls -la {} \;)
pc_permissions_state=$( echo "$pc_permissions_state" | awk '{$1=$1};1' )
if [  -z "$pc_permissions_state" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    find /usr/lib/vmware-perfcharts/tc-instance/webapps/ -xdev -type f -a '(' -not -user root -a -not -user perfcharts -o -not -group root ')' -exec ls -la {} \; | tail
fi
echo " "
echo "------------ V-256628 ------------"
pc_known_fail=$(grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties)
pc_known_fail_output=$(cat << EOF
org.apache.catalina.startup.EXIT_ON_INIT_FAILURE = true
EOF
)
pc_known_fail_output_2=$(cat << EOF
org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
EOF
)
pc_known_fail=$( echo "$pc_known_fail" | awk '{$1=$1};1' )
pc_known_fail_output=$( echo "$pc_known_fail_output" | awk '{$1=$1};1' )
pc_known_fail_output_2=$( echo "$pc_known_fail_output_2" | awk '{$1=$1};1' )
if [ "$pc_known_fail" = "$pc_known_fail_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ "$pc_known_fail" = "$pc_known_fail_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_known_fail
fi
echo " "
echo "------------ V-256629 ------------"
pc_known_fail=$(xmllint --xpath '/Server/Service/Connector/@acceptCount' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
pc_known_fail_output=$(cat << EOF
acceptCount="300"
EOF
)
pc_known_fail=$( echo "$pc_known_fail" | awk '{$1=$1};1' )
pc_known_fail_output=$( echo "$pc_known_fail_output" | awk '{$1=$1};1' )
if [ "$pc_known_fail" = "$pc_known_fail_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_known_fail
fi
echo " "
echo "------------ V-256630 ------------"
pc_uri_encoding=$(xmllint --xpath '/Server/Service/Connector/@URIEncoding' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
pc_uri_encoding_output=$(cat << EOF
URIEncoding="UTF-8"
EOF
)
pc_uri_encoding=$( echo "$pc_uri_encoding" | awk '{$1=$1};1' )
pc_uri_encoding_output=$( echo "$pc_uri_encoding_output" | awk '{$1=$1};1' )
if [ "$pc_uri_encoding" = "$pc_uri_encoding_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_uri_encoding
fi
echo " "
echo "------------ V-256631 ------------"
pc_char_encoding=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/filter-mapping/filter-name[text()="setCharacterEncodingFilter"]/parent::filter-mapping' - 2>/dev/null)
pc_char_encoding_output=$(cat << EOF
<filter-mapping>
    <filter-name>setCharacterEncodingFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
EOF
)
pc_char_encoding=$( echo "$pc_char_encoding" | awk '{$1=$1};1' )
pc_char_encoding_output=$( echo "$pc_char_encoding_output" | awk '{$1=$1};1' )
if [ "$pc_char_encoding" = "$pc_char_encoding_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_char_encoding
fi
echo " "
echo "------------ V-256632 ------------"
pc_def_webpage=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/welcome-file-list' - 2>/dev/null)
pc_def_webpage_output=$(cat << EOF
<welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.htm</welcome-file>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
EOF
)
pc_def_webpage=$( echo "$pc_def_webpage" | awk '{$1=$1};1' )
pc_def_webpage_output=$( echo "$pc_def_webpage_output" | awk '{$1=$1};1' )
if [ "$pc_def_webpage" = "$pc_def_webpage_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_def_webpage
fi
echo " "
echo "------------ V-256633 ------------"
pc_no_dir=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' - 2>/dev/null)
pc_no_dir_output=$(cat << EOF
<init-param>
      <param-name>listings</param-name>
      <param-value>false</param-value>
</init-param>
EOF
)
pc_no_dir=$( echo "$pc_no_dir" | awk '{$1=$1};1' )
pc_no_dir_output=$( echo "$pc_no_dir_output" | awk '{$1=$1};1' )
if [ "$pc_no_dir" = "$pc_no_dir_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_no_dir
fi
echo " "
echo "------------ V-256634 ------------"
pc_error_pages=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/error-page/exception-type["text()=java.lang.Throwable"]/parent::error-page' - 2>/dev/null)
pc_error_pages_output=$(cat << EOF
<error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/http_error.jsp</location>
</error-page>
EOF
)
pc_error_pages=$( echo "$pc_error_pages" | awk '{$1=$1};1' )
pc_error_pages_output=$( echo "$pc_error_pages_output" | awk '{$1=$1};1' )
if [ "$pc_error_pages" = "$pc_error_pages_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_error_pages
fi
echo " "
echo "------------ V-256635 ------------"
pc_error_reports=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
pc_error_reports_output=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>
EOF
)
pc_error_reports=$( echo "$pc_error_reports" | awk '{$1=$1};1' )
pc_error_reports_output=$( echo "$pc_error_reports_output" | awk '{$1=$1};1' )
if [ "$pc_error_reports" = "$pc_error_reports_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_error_reports
fi
echo " "
echo "------------ V-256636 ------------"
pc_hide_version=$(xmllint --xpath '/Server/Service/Connector/@server' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
pc_hide_version_output=$(cat << EOF
server="Anonymous"
EOF
)
pc_hide_version=$( echo "$pc_hide_version" | awk '{$1=$1};1' )
pc_hide_version_output=$( echo "$pc_hide_version_output" | awk '{$1=$1};1' )
if [ "$pc_hide_version" = "$pc_hide_version_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_hide_version
fi
echo " "
echo "------------ V-256637 ------------"
pc_trace_requests=$(grep allowTrace /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml)
pc_trace_requests=$( echo "$pc_trace_requests" | awk '{$1=$1};1' )
if [[ -z $pc_trace_requests ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ $pc_trace_requests =~ "true" ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $pc_trace_requests
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256638 ------------"
pc_debug_off=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="debug"]/parent::init-param' - 2>/dev/null)
pc_debug_off_output=$(cat << EOF
<init-param>
      <param-name>debug</param-name>
      <param-value>0</param-value>
</init-param>
EOF
)
pc_debug_off=$( echo "$pc_debug_off" | awk '{$1=$1};1' )
pc_debug_off_output=$( echo "$pc_debug_off_output" | awk '{$1=$1};1' )
if [ "$pc_debug_off" = "$pc_debug_off_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_debug_off
fi
echo " "
echo "------------ V-256639 ------------"
pc_log_size=$(rpm -V VMware-perfcharts|grep log4j|grep "^..5......")
pc_log_size=$( echo "$pc_log_size" | awk '{$1=$1};1' )
if [  -z "$pc_log_size" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_log_size
fi
echo " "
echo "------------ V-256640 ------------"
pc_log_files=$(rpm -V VMware-visl-integration|grep vmware-services-perfcharts.conf|grep "^..5......")
pc_log_files=$( echo "$pc_log_files" | awk '{$1=$1};1' )
if [  -z "$pc_log_files" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_log_files
fi
echo " "
echo "------------ V-256641 ------------"
pc_appro_ports=$(grep '^bio\.' /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties 2>/dev/null)
pc_appro_ports_output=$(cat << EOF
bio.http.port=13080
EOF
)
pc_appro_ports=$( echo "$pc_appro_ports" | awk '{$1=$1};1' )
pc_appro_ports_output=$( echo "$pc_appro_ports_output" | awk '{$1=$1};1' )
if [ "$pc_appro_ports" = "$pc_appro_ports_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_appro_ports
fi
echo " "
echo "------------ V-256642 ------------"
pc_shutdown_port=$(grep base.shutdown.port /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties 2>/dev/null)
pc_shutdown_port_output=$(cat << EOF
base.shutdown.port=-1
EOF
)
pc_shutdown_port=$( echo "$pc_shutdown_port" | awk '{$1=$1};1' )
pc_shutdown_port_output=$( echo "$pc_shutdown_port_output" | awk '{$1=$1};1' )
if [ "$pc_shutdown_port" = "$pc_shutdown_port_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_shutdown_port
fi
echo " "
echo "------------ V-256643 ------------"
pc_cookie_flag=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' - 2>/dev/null)
pc_cookie_flag_output=$(cat << EOF
<secure>true</secure>
EOF
)
pc_cookie_flag=$( echo "$pc_cookie_flag" | awk '{$1=$1};1' )
pc_cookie_flag_output=$( echo "$pc_cookie_flag_output" | awk '{$1=$1};1' )
if [ "$pc_cookie_flag" = "$pc_cookie_flag_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_cookie_flag
fi
echo " "
echo "------------ V-256644 ------------"
pc_read_only=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/servlet/servlet-name[text()="default"]/../init-param/param-name[text()="readonly"]/../param-value[text()="false"]' - 2>/dev/null)
pc_read_only=$( echo "$pc_read_only" | awk '{$1=$1};1' )
if [  -z "$pc_read_only" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $pc_read_only
fi
echo " "
echo " "
echo ----------------------------------------------------------------------------------------------------------
echo ----------VMware vSphere 7.0 vCenter Appliance Photon OS Security Technical Implementation Guide----------
echo ----------------------------------------------------------------------------------------------------------
echo " "
echo "------------ V-256478 ------------"
photon_account_creation=$(auditctl -l | grep -E "(useradd|groupadd)" 2>/dev/null)
photon_account_creation_output=$(cat << EOF
<secure>true</secure>
EOF
)
photon_account_creation=$( echo "$photon_account_creation" | awk '{$1=$1};1' )
photon_account_creation_output=$( echo "$photon_account_creation_output" | awk '{$1=$1};1' )
if [ "$photon_account_creation" = "$photon_account_creation_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ -z "$photon_account_creation" || "$photon_account_creation" != *"x"* ]]; then
    echo -e "\e[31mOpen\e[0m" 
    echo $photon_account_creation
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256479 ------------"
photon_pam_tall2_1=$(grep pam_tally2 /etc/pam.d/system-auth 2>/dev/null)
photon_pam_tall2_2=$(grep pam_tally2 /etc/pam.d/system-account 2>/dev/null)
photon_pam_tall2_1_output=$(cat << EOF
auth       required pam_tally2.so deny=3 onerr=fail audit even_deny_root unlock_time=900 root_unlock_time=300
EOF
)
photon_pam_tall2_2_output=$(cat << EOF
account    required pam_tally2.so onerr=fail audit
EOF
)
photon_pam_tall2_1=$( echo "$photon_pam_tall2_1" | awk '{$1=$1};1' )
photon_pam_tall2_1_output=$( echo "$photon_pam_tall2_1_output" | awk '{$1=$1};1' )
photon_pam_tall2_2=$( echo "$photon_pam_tall2_2" | awk '{$1=$1};1' )
photon_pam_tall2_2_output=$( echo "$photon_pam_tall2_2_output" | awk '{$1=$1};1' )
if [ "$photon_pam_tall2_1" = "$photon_pam_tall2_1_output" ] && [ "$photon_pam_tall2_2" = "$photon_pam_tall2_2_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m" 
    echo system-auth= $photon_pam_tall2_1
    echo system-account= $photon_pam_tall2_2
fi
echo " "
echo "------------ V-256480 ------------"
photon_banner_1=$(sshd -T|&grep -i Banner 2>/dev/null)
photon_banner_2=$(cat /etc/issue 2>/dev/null)
photon_banner_1_output=$(cat << EOF
banner /etc/issue
EOF
)
photon_banner_1=$( echo "$photon_banner_1" | awk '{$1=$1};1' )
photon_banner_1_output=$( echo "$photon_banner_1_output" | awk '{$1=$1};1' )
photon_banner_2=$( echo "$photon_banner_2" | awk '{$1=$1};1' )
if [ "$photon_banner_1" = "$photon_banner_1_output" ] && [[ "$photon_banner_2" == *"You are accessing a U.S Government"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m" 
    echo system-auth= $photon_banner_1
    echo system-account= $photon_banner_2
fi
echo " "
echo "------------ V-256481 ------------"
photon_concurrent_sessions=$(grep "^[^#].*maxlogins.*" /etc/security/limits.conf)
photon_concurrent_sessions_output=$(cat << EOF
*       hard    maxlogins       10
EOF
)
photon_concurrent_sessions=$( echo "$photon_concurrent_sessions" | awk '{$1=$1};1' )
photon_concurrent_sessions_output=$( echo "$photon_concurrent_sessions_output" | awk '{$1=$1};1' )
if [ "$photon_concurrent_sessions" = "$photon_concurrent_sessions_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_concurrent_sessions
fi
echo " "
echo "------------ V-256482 ------------"
photon_time_out=$(cat /etc/profile.d/tmout.sh 2>/dev/null)
photon_time_out_output=$(cat << EOF
TMOUT=900
readonly TMOUT 
export TMOUT
mesg n 2>/dev/null
EOF
)
photon_time_out=$( echo "$photon_time_out" | awk '{$1=$1};1' )
photon_time_out_output=$( echo "$photon_time_out_output" | awk '{$1=$1};1' )
if [ "$photon_time_out" = "$photon_time_out_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_time_out
fi
echo " "
echo "------------ V-256483 ------------"
photon_sshd_authpriv=$(sshd -T|&grep -i SyslogFacility)
photon_sshd_authpriv_output=$(cat << EOF
syslogfacility AUTHPRIV
EOF
)
photon_sshd_authpriv=$( echo "$photon_sshd_authpriv" | awk '{$1=$1};1' )
photon_sshd_authpriv_output=$( echo "$photon_sshd_authpriv_output" | awk '{$1=$1};1' )
if [ "$photon_sshd_authpriv" = "$photon_sshd_authpriv_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_sshd_authpriv
fi
echo " "
echo "------------ V-256484 ------------"
photon_sshd_logging=$(grep "^authpriv" /etc/rsyslog.conf)
photon_sshd_logging_output=$(cat << EOF
authpriv.*   /var/log/auth.log
EOF
)
photon_sshd_logging=$( echo "$photon_sshd_logging" | awk '{$1=$1};1' )
photon_sshd_logging_output=$( echo "$photon_sshd_logging_output" | awk '{$1=$1};1' )
if [ "$photon_sshd_logging" = "$photon_sshd_logging_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$photon_sshd_logging" == "authpriv.*"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_sshd_loggingpriv
fi
echo " "
echo "------------ V-256485 ------------"
photon_loglevel_info=$(sshd -T 2>&1 | grep -i LogLevel | awk '{print $2}')
photon_loglevel_info_output="info"
photon_loglevel_info=$(echo "$photon_loglevel_info" | awk '{$1=$1};1' | tr '[:upper:]' '[:lower:]')
photon_loglevel_info_output=$(echo "$photon_loglevel_info_output" | tr '[:upper:]' '[:lower:]')
if [ "$photon_loglevel_info" = "$photon_loglevel_info_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo "$photon_loglevel_info"
fi
echo " "
echo "------------ V-256486 ------------"
photon_fips_mode=$(sshd -T 2>&1 | grep -i FipsMode | awk '{print $2}')
photon_fips_mode_output="yes"
photon_fips_mode=$(echo "$photon_fips_mode" | awk '{$1=$1};1' | tr '[:upper:]' '[:lower:]')
photon_fips_mode_output=$(echo "$photon_fips_mode_output" | tr '[:upper:]' '[:lower:]')
if [ "$photon_fips_mode" = "$photon_fips_mode_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo "$photon_fips_mode"
fi
echo " "
echo "------------ V-256487 ------------"
photon_auditd_log=$(grep "^write_logs" /etc/audit/auditd.conf)
photon_auditd_log_output=$(cat << EOF
write_logs = yes
EOF
)
photon_auditd_log=$( echo "$photon_auditd_log" | awk '{$1=$1};1' )
photon_auditd_log_output=$( echo "$photon_auditd_log_output" | awk '{$1=$1};1' )
if [ "$photon_auditd_log" = "$photon_auditd_log_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$photon_auditd_log" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_auditd_log
fi
echo " "
echo "------------ V-256488 ------------"
photon_auditd_logformat=$(grep "^log_format" /etc/audit/auditd.conf)
photon_auditd_logformat_output=$(cat << EOF
log_format = RAW
EOF
)
photon_auditd_logformat=$( echo "$photon_auditd_logformat" | awk '{$1=$1};1' )
photon_auditd_logformat_output=$( echo "$photon_auditd_logformat_output" | awk '{$1=$1};1' )
if [ "$photon_auditd_logformat" = "$photon_auditd_logformat_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$photon_auditd_logformat" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_auditd_logformat
fi
echo " "
echo "------------ V-256489 ------------"
photon_priv_functions=$(auditctl -l | grep execve)
photon_priv_functions_output=$(cat << EOF
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv
EOF
)
photon_priv_functions=$( echo "$photon_priv_functions" | awk '{$1=$1};1' )
photon_priv_functions_output=$( echo "$photon_priv_functions_output" | awk '{$1=$1};1' )
if [ "$photon_priv_functions" = "$photon_priv_functions_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_priv_functions
fi
echo " "
echo "------------ V-256490 ------------"
photon_auditd_status=$(systemctl is-active auditd 2>/dev/null)
photon_auditd_status_output="active"
photon_auditd_status=$(echo "$photon_auditd_status" | awk '{$1=$1};1' | tr '[:upper:]' '[:lower:]')
photon_auditd_status_output=$(echo "$photon_auditd_status_output" | tr '[:upper:]' '[:lower:]')
if [ "$photon_auditd_status" = "$photon_auditd_status_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo "Auditd is $photon_auditd_status"
fi
echo " "
echo "------------ V-256491 ------------"
photon_log_space=$(grep "^space_left_action" /etc/audit/auditd.conf)
photon_log_space_output=$(cat << EOF
space_left_action = SYSLOG
EOF
)
photon_log_space=$( echo "$photon_log_space" | awk '{$1=$1};1' )
photon_log_space_output=$( echo "$photon_log_space_output" | awk '{$1=$1};1' )
if [ "$photon_log_space" = "$photon_log_space_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_log_space
fi
echo " "
echo "------------ V-256492 ------------"
photon_log_syslog=$(grep -E "^disk_full_action|^disk_error_action|^admin_space_left_action" /etc/audit/auditd.conf)
photon_log_syslog_output=$(cat << EOF
admin_space_left_action = SYSLOG
disk_full_action = SYSLOG
disk_error_action = SYSLOG
EOF
)
photon_log_syslog=$( echo "$photon_log_syslog" | awk '{$1=$1};1' )
photon_log_syslog_output=$( echo "$photon_log_syslog_output" | awk '{$1=$1};1' )
if [ "$photon_log_syslog" = "$photon_log_syslog_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_log_syslog
fi
echo " "
echo "------------ V-256493 ------------"
photon_output_array=($(audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//); if [ -f "${audit_log_file}" ]; then stat -c "%a" ${audit_log_file%}*; fi))
photon_found_open=false
for number in "${photon_output_array[@]}"; do
    first_digit=${number:0:1}
    last_two_digits=${number:1}
    if [ "$first_digit" -eq 7 ] || [ "$last_two_digits" -ne 0 ]; then
        photon_found_open=true
        break
    fi
done
if $photon_found_open; then
    echo -e "\e[31mOpen\e[0m"
    (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\n"; stat -c "%n permissions are %a" ${audit_log_file%}*; else printf "audit log file(s) not found\n"; fi)
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256494 ------------"
photon_root_log=$(audit_log_file1=$(grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//) && if [ -f "${audit_log_file1}" ]; then stat -c "%n is owned by %U" ${audit_log_file1%}* | grep -v "is owned by root" | sed 's/Log(s) found in .*://' ; else printf "audit log file(s) not found\n"; fi)
photon_root_log=$( echo "$photon_root_log" | awk '{$1=$1};1' )
if [ -z "$photon_root_log" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    audit_log_file2=$(grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//)
    photon_root_log2=$(audit_log_file2=$(grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//) && if [ -f "${audit_log_file2}" ]; then stat -c "%n is owned by %U" ${audit_log_file2%}* ; else printf "audit log file(s) not found\n"; fi)
    photon_root_log2=$(echo "$photon_root_log2" | awk '{$1=$1};1')
    echo "$photon_root_log2"
fi
echo " "
echo "------------ V-256495 ------------"
photon_root_group_log=$(audit_log_file1=$(grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//) && if [ -f "${audit_log_file1}" ]; then stat -c "%n is owned by %G" ${audit_log_file1%}* | grep -v "root" | sed 's/Log(s) found in .*://' ; else printf "audit log file(s) not found\n"; fi)
photon_root_group_log=$( echo "$photon_root_group_log" | awk '{$1=$1};1' )
if [ -z "$photon_root_group_log" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    audit_log_file2=$(grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//)
    photon_root_group_log2=$(audit_log_file2=$(grep "^log_file" /etc/audit/auditd.conf | sed s/^[^\/]*//) && if [ -f "${audit_log_file2}" ]; then stat -c "%n is owned by %G" ${audit_log_file2%}* ; else printf "audit log file(s) not found\n"; fi)
    photon_root_group_log2=$(echo "$photon_root_group_log2" | awk '{$1=$1};1')
    echo "$photon_root_group_log2"
fi
echo " "
echo "------------ V-256496 ------------"
photon_output_array_2=($(find /etc/audit/* -type f -exec stat -c "%a" {} $1\;))
photon_found_open_2=false
for number in "${photon_output_array_2[@]}"; do
    first_digit=${number:0:1}
    second_digit=${number:1:1}
    third_digit=${number:2:1}
    if [ "$first_digit" -eq 7 ] || [ "$second_digit" -eq 6 ] || [ "$second_digit" -eq 5 ] || [ "$second_digit" -eq 7 ] || [ "$third_digit" -ne 0 ]; then
        photon_found_open_2=true
        break
    fi
done
if $photon_found_open_2; then
    echo -e "\e[31mOpen\e[0m"
    find /etc/audit/* -type f -exec stat -c "%n permissions are %a" {} $1\;
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256497 ------------"
photon_access_privilege=$(auditctl -l | grep chmod)
photon_access_privilege_output=$(cat << EOF
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod
EOF
)
photon_access_privilege_output_2=$(cat << EOF
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod
EOF
)
photon_access_privilege=$( echo "$photon_access_privilege" | awk '{$1=$1};1' )
photon_access_privilege_output=$( echo "$photon_access_privilege_output" | awk '{$1=$1};1' )
photon_access_privilege_output_2=$( echo "$photon_access_privilege_output_2" | awk '{$1=$1};1' )
if [ "$photon_access_privilege" = "$photon_access_privilege_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif    [ "$photon_access_privilege" = "$photon_access_privilege_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_access_privilege
fi
echo " "
echo "------------ V-256498 ------------"
photon_password_one_upper=$(grep pam_cracklib /etc/pam.d/system-password|grep --color=always "ucredit=..")
photon_password_one_upper=$( echo "$photon_password_one_upper" | awk '{$1=$1};1' )
if [[ "$photon_password_one_upper" == *"ucredit=-1"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_password_one_upper
fi
echo " "
echo "------------ V-256499 ------------"
photon_password_one_lower=$(grep pam_cracklib /etc/pam.d/system-password|grep --color=always "lcredit=..")
photon_password_one_lower=$( echo "$photon_password_one_lower" | awk '{$1=$1};1' )
if [[ "$photon_password_one_lower" == *"lcredit=-1"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_password_one_lower
fi
echo " "
echo "------------ V-256500 ------------"
photon_password_one_num=$(grep pam_cracklib /etc/pam.d/system-password|grep --color=always "difok=.")
photon_password_one_num=$( echo "$photon_password_one_num" | awk '{$1=$1};1' )
if [[ "$photon_password_one_num" == *"dcredit=-1"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_password_one_num
fi
echo " "
echo "------------ V-256501 ------------"
photon_password_four_diff=$(grep pam_cracklib /etc/pam.d/system-password)
photon_password_four_diff_output=$(echo "$photon_password_four_diff" | awk -F 'difok=' '{print $2}' | cut -d ' ' -f 1)
if [ "$photon_password_four_diff_output" -ge 4 ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_password_four_diff
fi
echo " "
echo "------------ V-256502 ------------"
photon_encrypted_passwords=$(grep SHA512 /etc/login.defs|grep -v "#")
photon_encrypted_passwords_output=$(cat << EOF
ENCRYPT_METHOD SHA512
EOF
)
photon_encrypted_passwords=$( echo "$photon_encrypted_passwords" | awk '{$1=$1};1' )
photon_encrypted_passwords_output=$( echo "$photon_encrypted_passwords_output" | awk '{$1=$1};1' )
if [ "$photon_encrypted_passwords" = "$photon_encrypted_passwords_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_encrypted_passwords
fi
echo " "
echo "------------ V-256503 ------------"
version_compare() {
    if [[ "$1" == "$2" ]]; then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 2
        fi
    done
    return 0
}
photon_openssh_version=$(rpm -qa | grep openssh | grep -v server | grep -v client | awk -F- '{print $2}' | sed 's/p.*$//')
photon_required_version="7.4"
version_compare "$photon_openssh_version" "$photon_required_version"
photon_comparison_result=$?
if [[ $photon_comparison_result -eq 1 ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo rpm -qa|grep openssh
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256504 ------------"
photon_newuser_minimum=$(grep "^PASS_MIN_DAYS" /etc/login.defs)
photon_newuser_minimum_output=$(cat << EOF
PASS_MIN_DAYS   1
EOF
)
photon_newuser_minimum=$( echo "$photon_newuser_minimum" | awk '{$1=$1};1' )
photon_newuser_minimum_output=$( echo "$photon_newuser_minimum_output" | awk '{$1=$1};1' )
if [ "$photon_newuser_minimum" = "$photon_newuser_minimum_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_newuser_minimum
fi
echo " "
echo "------------ V-256505 ------------"
photon_newuser_maximum=$(grep "^PASS_MAX_DAYS" /etc/login.defs)
photon_newuser_maximum_output=$(cat << EOF
PASS_MAX_DAYS   90
EOF
)
photon_newuser_maximum=$( echo "$photon_newuser_maximum" | awk '{$1=$1};1' )
photon_newuser_maximum_output=$( echo "$photon_newuser_maximum_output" | awk '{$1=$1};1' )
if [ "$photon_newuser_maximum" = "$photon_newuser_maximum_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_newuser_maximum
fi
echo " "
echo "------------ V-256506 ------------"
photon_password_five_gen=$(grep pam_pwhistory /etc/pam.d/system-password|grep --color=always "remember=.")
photon_password_five_gen=$( echo "$photon_password_five_gen" | awk '{$1=$1};1' )
if [[ "$photon_password_five_gen" == *"remember=5"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_password_five_gen
fi
echo " "
echo "------------ V-256507 ------------"
photon_password_eight_length=$(grep pam_cracklib /etc/pam.d/system-password|grep --color=always "minlen=..")
photon_password_eight_length_output=$(echo "$photon_password_eight_length" | awk -F 'minlen=' '{print $2}' | cut -d ' ' -f 1)
if [ "$photon_password_eight_length_output" -ge 8 ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_password_eight_length
fi
echo " "
echo "------------ V-256508 ------------"
photon_grub_login=$(grep -i ^password_pbkdf2 /boot/grub2/grub.cfg)
photon_grub_login_output=$(cat << EOF
"password_pbkdf2 root"
EOF
)
photon_grub_login=$( echo "$photon_grub_login" | awk '{$1=$1};1' )
photon_grub_login_output=$( echo "$photon_grub_login_output" | awk '{$1=$1};1' )
if [ -z "$photon_grub_login" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "No output"
elif [[ "$photon_grub_login" == "$photon_grub_login_output"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_grub_login
fi
echo " "
echo "------------ V-256509 ------------"
photon_unnecessary_modules=$(modprobe --showconfig | grep "^install" | grep "/bin")
photon_unnecessary_modules_output=$(cat << EOF
install sctp /bin/false
install dccp /bin/false
install dccp_ipv4 /bin/false
install dccp_ipv6 /bin/false
install ipx /bin/false
install appletalk /bin/false
install decnet /bin/false
install rds /bin/false
install tipc /bin/false
install bluetooth /bin/false
install usb_storage /bin/false
install ieee1394 /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
EOF
)
photon_unnecessary_modules=$( echo "$photon_unnecessary_modules" | awk '{$1=$1};1' )
photon_unnecessary_modules_output=$( echo "$photon_unnecessary_modules_output" | awk '{$1=$1};1' )
if [[ "$photon_unnecessary_modules" == *"$photon_unnecessary_modules_output"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_unnecessary_modules
fi
echo " "
echo "------------ V-256510 ------------"
photon_user_ids=$(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd)
photon_user_ids=$( echo "$photon_user_ids" | awk '{$1=$1};1' )
if [  -z "$photon_user_ids" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_user_ids
fi
echo " "
echo "------------ V-256511 ------------"
photon_disable_password=$(grep INACTIVE /etc/default/useradd)
photon_disable_password_output=$(cat << EOF
INACTIVE=0
EOF
)
photon_disable_password=$( echo "$photon_disable_password" | awk '{$1=$1};1' )
photon_disable_password_output=$( echo "$photon_disable_password_output" | awk '{$1=$1};1' )
if [ "$photon_disable_password" = "$photon_disable_password_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_disable_password
fi
echo " "
echo "------------ V-256512 ------------"
photon_tcp_syncookies=$(/sbin/sysctl -a --pattern tcp_syncookies)
photon_tcp_syncookies_output=$(cat << EOF
net.ipv4.tcp_syncookies = 1
EOF
)
photon_tcp_syncookies=$( echo "$photon_tcp_syncookies" | awk '{$1=$1};1' )
photon_tcp_syncookies_output=$( echo "$photon_tcp_syncookies_output" | awk '{$1=$1};1' )
if [ "$photon_tcp_syncookies" = "$photon_tcp_syncookies_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_tcp_syncookies
fi
echo " "
echo "------------ V-256513 ------------"
photon_ssh_idle=$(sshd -T|&grep -i ClientAliveInterval)
photon_ssh_idle_output=$(cat << EOF
ClientAliveInterval 900
EOF
)
photon_ssh_idle=$( echo "$photon_ssh_idle" | awk '{$1=$1};1' )
photon_ssh_idle_output=$( echo "$photon_ssh_idle_output" | awk '{$1=$1};1' )
if [ "$photon_ssh_idle" = "$photon_ssh_idle_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_ssh_idle
fi
echo " "
echo "------------ V-256514 ------------"
photon_ssh_idle_2=$(sshd -T|&grep -i ClientAliveCountMax)
photon_ssh_idle_2_output=$(cat << EOF
ClientAliveCountMax 0
EOF
)
photon_ssh_idle_2=$( echo "$photon_ssh_idle_2" | awk '{$1=$1};1' )
photon_ssh_idle_2_output=$( echo "$photon_ssh_idle_2_output" | awk '{$1=$1};1' )
if [ "$photon_ssh_idle_2" = "$photon_ssh_idle_2_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_ssh_idle_2
fi
echo " "
echo "------------ V-256515 ------------"
photon_ssh_idle_2=$(stat -c "%n is owned by %U and group owned by %G" /var/log | awk '{print $5}')
photon_ssh_idle_2_output=$(cat << EOF
root
EOF
)
photon_varlog_root=$( echo "$photon_varlog_root" | awk '{$1=$1};1' )
photon_varlog_root_output=$( echo "$photon_varlog_root_output" | awk '{$1=$1};1' )
if [ "$photon_varlog_root" = "$photon_varlog_root_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_varlog_root
fi
echo " "
echo "------------ V-256516 ------------"
photon_varlog_messages=($(stat -c "%n is owned by %U and group owned by %G with %a permissions" /var/log/messages | awk '{print $12}'))
photon_varlog_messages_user=$(stat -c "%n is owned by %U and group owned by %G" /var/log/messages | awk '{print $5}')
photon_varlog_messages_output=$(cat << EOF
root
EOF
)
photon_varlog_messages_group=$(stat -c "%n is owned by %U and group owned by %G" /var/log/messages | awk '{print $10}')
photon_varlog_messages_open=false
for number in "${photon_varlog_messages[@]}"; do
    first_digit=${number:0:1}
    second_digit=${number:1:1}
    third_digit=${number:2:1}
    if [ "$first_digit" -eq 7 ] || [ "$second_digit" -eq 6 ] || [ "$second_digit" -eq 5 ] || [ "$second_digit" -eq 7 ] || [ "$third_digit" -ne 0 ]; then
        photon_varlog_messages_open=true
        break
    fi
done
if $photon_varlog_messages_open; then
    echo -e "\e[31mOpen\e[0m"
    stat -c "%n is owned by %U and group owned by %G with %a permissions" /var/log/messages
elif [ "$photon_varlog_messages_user" != "$photon_varlog_messages_output" ]; then
    echo -e "\e[31mOpen\e[0m"
    stat -c "%n is owned by %U and group owned by %G with %a permissions" /var/log/messages
elif [ "$photon_varlog_messages_group" != "$photon_varlog_messages_output" ]; then
    echo -e "\e[31mOpen\e[0m"
    stat -c "%n is owned by %U and group owned by %G with %a permissions" /var/log/messages
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256517 ------------"
photon_account_mod=$(auditctl -l | grep -E "(usermod|groupmod)")
photon_account_mod_output=$(cat << EOF
-w /usr/sbin/usermod -p x -k usermod
-w /usr/sbin/groupmod -p x -k groupmod
EOF
)
photon_account_mod=$( echo "$photon_account_mod" | awk '{$1=$1};1' )
photon_account_mod_output=$( echo "$photon_account_mod_output" | awk '{$1=$1};1' )
if [ "$photon_account_mod" = "$photon_account_mod_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_account_mod
fi
echo " "
echo "------------ V-256518 ------------"
photon_account_mod_2=$(auditctl -l | grep -E "(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)")
photon_account_mod_2_output=$(cat << EOF
-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/group -p wa -k group
-w /etc/gshadow -p wa -k gshadow
EOF
)
photon_account_mod_2=$( echo "$photon_account_mod_2" | awk '{$1=$1};1' )
photon_account_mod_2_output=$( echo "$photon_account_mod_2_output" | awk '{$1=$1};1' )
if [ "$photon_account_mod_2" = "$photon_account_mod_2_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_account_mod_2
fi
echo " "
echo "------------ V-256519 ------------"
photon_account_disabling=$(auditctl -l | grep "w /usr/bin/passwd")
photon_account_disabling_output=$(cat << EOF
-w /usr/bin/passwd -p x -k passwd
EOF
)
photon_account_disabling=$( echo "$photon_account_disabling" | awk '{$1=$1};1' )
photon_account_disabling_output=$( echo "$photon_account_disabling_output" | awk '{$1=$1};1' )
if [ "$photon_account_disabling" = "$photon_account_disabling_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_account_disabling
fi
echo " "
echo "------------ V-256520 ------------"
photon_account_removal=$(auditctl -l | grep -E "(userdel|groupdel)")
photon_account_removal_output=$(cat << EOF
-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel
EOF
)
photon_account_removal=$( echo "$photon_account_removal" | awk '{$1=$1};1' )
photon_account_removal_output=$( echo "$photon_account_removal_output" | awk '{$1=$1};1' )
if [ "$photon_account_removal" = "$photon_account_removal_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_account_removal
fi
echo " "
echo "------------ V-256521 ------------"
photon_cmd_logging=$(grep "audit=1" /proc/cmdline)
photon_cmd_logging=$( echo "$photon_cmd_logging" | awk '{$1=$1};1' )
if [ -z "$photon_cmd_logging" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "No output"
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256522 ------------"
photon_audit_permissions_user=$(stat -c "%n is owned by %U and group owned by %G" /etc/audit/auditd.conf | awk '{print $5}')
photon_audit_permissions_group=$(stat -c "%n is owned by %U and group owned by %G" /etc/audit/auditd.conf | awk '{print $10}')
photon_audit_permissions_output=$(cat << EOF
root
EOF
)
if [ "$photon_audit_permissions_user" = "$photon_audit_permissions_output" ] && [ "$photon_audit_permissions_group" = "$photon_audit_permissions_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_audit_permissions
fi
echo " "
echo "------------ V-256523 ------------"
photon_audit_tools=($(stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace | awk '{print$14}'))
photon_audit_tools_user=($(stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace | awk '{print$5}'))
photon_audit_tools_output=$(cat << EOF
root
EOF
)
photon_audit_tools_group=($(stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace | awk '{print$10}'))
photon_audit_tools_user_open=false
for owner in "${photon_audit_tools_user[@]}"; do
    if [[ "$owner" != "$photon_audit_tools_output" ]]; then
        photon_audit_tools_user_open=true
        break
    fi
done
photon_audit_tools_group_open=false
for group in "${photon_audit_tools_group[@]}"; do
    if [[ "$group" != "$photon_audit_tools_output" ]]; then
        photon_audit_tools_group_open=true
        break
    fi
done
photon_audit_tools_open=false
for number in "${photon_audit_tools[@]}"; do
    first_digit=${number:0:1}
    second_digit=${number:1:1}
    third_digit=${number:2:1}
    if [ "$second_digit" -eq 6 ] || [ "$second_digit" -eq 7 ] || [ "$third_digit" -ne 0 ]; then
        photon_audit_tools_open=true
        break
    fi
done
if $photon_audit_tools_open; then
    echo -e "\e[31mOpen\e[0m"
    stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace
elif $photon_audit_tools_user_open; then
    echo -e "\e[31mOpen\e[0m"
    stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace
elif $photon_audit_tools_group_open; then
    echo -e "\e[31mOpen\e[0m"
    stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256524 ------------"
photon_password_one_special=$(grep pam_cracklib /etc/pam.d/system-password|grep --color=always "ocredit=..")
photon_password_one_special=$( echo "$photon_password_one_special" | awk '{$1=$1};1' )
if [[ "$photon_password_one_special" == *"ocredit=-1"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_password_one_special
fi
echo " "
echo "------------ V-256525 ------------"
photon_system_modified=$(rpm -V audit | grep "^..5" | grep -v "^...........c")
photon_system_modified=$( echo "$photon_system_modified" | awk '{$1=$1};1' )
if [  -z "$photon_system_modified" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_system_modified
fi
echo " "
echo "------------ V-256526 ------------"
photon_audit_privfunc=()
while IFS= read -r line; do
    photon_audit_privfunc+=("$line")
done < <(find / -xdev -path /var/lib/containerd -prune -o \( -perm -4000 -type f -o -perm -2000 \) -type f -print | sort)
photon_audit_privfunc_open=false
photon_audit_privfunc_output=""
for t in "${photon_audit_privfunc[@]}"; do
    photon_audit_privfunc_output=$(auditctl -l | grep "$t")
    if [ -z "$t" ]; then
        photon_audit_privfunc_open=true
        break
    fi
done
if $photon_audit_privfunc_open; then
    echo -e "\e[31mOpen\e[0m"
    printf '%s\n' "${photon_audit_privfunc[@]}"
else 
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256527 ------------"
photon_audit_five_logs=$(grep "^num_logs" /etc/audit/auditd.conf)
photon_audit_five_logs_output=$(cat << EOF
num_logs = 5
EOF
)
photon_audit_five_logs=$( echo "$photon_audit_five_logs" | awk '{$1=$1};1' )
photon_audit_five_logs_output=$( echo "$photon_audit_five_logs_output" | awk '{$1=$1};1' )
if [ "$photon_audit_five_logs" = "$photon_audit_five_logs_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_audit_five_logs
fi
echo " "
echo "------------ V-256528 ------------"
photon_audit_max_logs=$(grep "^max_log_file_action" /etc/audit/auditd.conf)
photon_audit_max_logs_bad_output=$(cat << EOF
max_log_file_action = ROTATE
max_log_file_action = IGNORE
EOF
)
photon_audit_max_logs_ignore_output=$(cat << EOF
max_log_file_action = IGNORE
EOF
)
photon_audit_max_logs_rotate_output=$(cat << EOF
max_log_file_action = ROTATE
EOF
)
photon_audit_max_logs=$( echo "$photon_audit_max_logs" | awk '{$1=$1};1' )
photon_audit_max_logs_output=$( echo "$photon_audit_max_logs_output" | awk '{$1=$1};1' )
photon_audit_max_logs_ignore_output=$( echo "$photon_audit_max_logs_ignore_output" | awk '{$1=$1};1' )
photon_audit_max_logs_rotate_output=$( echo "$photon_audit_max_logs_rotate_output" | awk '{$1=$1};1' )
if [ "$photon_audit_max_logs" = "$photon_audit_max_logs_output" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "Both options are set"
    echo $photon_audit_max_logs
elif [ "$photon_audit_max_logs" = "$photon_audit_max_logs_rotate_output" ]; then
    echo "Validate that logs are not rotated outisde of auditd"
    echo -e "\e[32mNot a Finding\e[0m"
    echo $photon_audit_max_logs
elif [ "$photon_audit_max_logs" = "$photon_audit_max_logs_ignore_output" ]; then
    echo "Validate that logs are rotated outisde of auditd"
    echo -e "\e[32mNot a Finding\e[0m"
    echo $photon_audit_max_logs
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_audit_max_logs
fi
echo " "
echo "------------ V-256529 ------------"
photon_audit_space_syslog=$(grep "^space_left " /etc/audit/auditd.conf)
photon_audit_space_syslog_output=$(cat << EOF
space_left = 75
EOF
)
photon_audit_space_syslog=$( echo "$photon_audit_space_syslog" | awk '{$1=$1};1' )
photon_audit_space_syslog_output=$( echo "$photon_audit_space_syslog_output" | awk '{$1=$1};1' )
if [ "$photon_audit_space_syslog" = "$photon_audit_space_syslog_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_audit_space_syslog
fi
echo " "
echo "------------ V-256530 ------------"
photon_crypto_verify=$(grep -s nosignature /usr/lib/rpm/rpmrc /etc/rpmrc ~root/.rpmrc)
photon_crypto_verify=$( echo "$photon_crypto_verify" | awk '{$1=$1};1' )
if [  -z "$photon_crypto_verify" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_crypto_verify
fi
echo " "
echo "------------ V-256531 ------------"
photon_crypto_verify_launch=$(grep "^gpgcheck" /etc/tdnf/tdnf.conf)
photon_crypto_verify_launch_output=$(cat << EOF
gpgcheck=1
EOF
)
photon_crypto_verify_launch=$( echo "$photon_crypto_verify_launch" | awk '{$1=$1};1' )
photon_crypto_verify_launch_output=$( echo "$photon_crypto_verify_launch_output" | awk '{$1=$1};1' )
if [ "$photon_crypto_verify_launch" = "$photon_crypto_verify_launch_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_crypto_verify_launch
fi
echo " "
echo "------------ V-256532 ------------"
photon_crypto_yum=($(grep gpgcheck /etc/yum.repos.d/* | awk -F 'gpgcheck=' '{print $2}'))
photon_crypto_yum_check=false
for num in "${photon_crypto_yum[@]}"; do
    if [[ "$num" != 1 ]]; then
        photon_crypto_yum_check=true
        break
    fi
done
if $photon_crypto_yum_check; then
    echo -e "\e[31mOpen\e[0m"
    echo $(grep gpgcheck /etc/yum.repos.d/*)
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256533 ------------"
photon_reauth_priv=$(grep -ihs nopasswd /etc/sudoers /etc/sudoers.d/* | grep -v "^#" | grep -v "^%" | awk '{print $1}')
photon_reauth_priv_2=$(awk -F: '($2 != "x" && $2 != "!") {print $1}' /etc/shadow)
photon_reauth_priv_check=false
for user in $photon_reauth_priv; do
    if [[ " $photon_reauth_priv_2 " == *" $user "* ]]; then
        photon_reauth_priv_check=true
    fi
done
if $photon_reauth_priv_check; then
    echo -e "\e[31mOpen\e[0m"
    echo $(grep -ihs nopasswd /etc/sudoers /etc/sudoers.d/* | grep -v "^#" | grep -v "^%" | awk '{print $1}')
    echo $(awk -F: '($2 != "x" && $2 != "!") {print $1}' /etc/shadow)
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256534 ------------"
photon_crypto_ciphers=$(sshd -T|&grep -i Ciphers)
photon_crypto_ciphers_output_1=$(cat << EOF
ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
EOF
)
photon_crypto_ciphers_output_2=$(cat << EOF
ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com
EOF
)
photon_crypto_ciphers_output_3=$(cat << EOF
ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com
EOF
)
photon_crypto_ciphers_output_4=$(cat << EOF
ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
EOF
)
photon_crypto_ciphers=$( echo "$photon_crypto_ciphers" | awk '{$1=$1};1' )
photon_crypto_ciphers_output=$( echo "$photon_crypto_ciphers_output" | awk '{$1=$1};1' )
photon_crypto_ciphers_output_2=$( echo "$photon_crypto_ciphers_output_2" | awk '{$1=$1};1' )
photon_crypto_ciphers_output_3=$( echo "$photon_crypto_ciphers_output_3" | awk '{$1=$1};1' )
photon_crypto_ciphers_output_4=$( echo "$photon_crypto_ciphers_output_4" | awk '{$1=$1};1' )
if [ "$photon_crypto_ciphers" = "$photon_crypto_ciphers_output" ] || [ "$photon_crypto_ciphers" = "$photon_crypto_ciphers_output_2" ] || [ "$photon_crypto_ciphers" = "$photon_crypto_ciphers_output_3" ] || [ "$photon_crypto_ciphers" = "$photon_crypto_ciphers_output_4" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_crypto_ciphers
fi
echo " "
echo "------------ V-256535 ------------"
photon_aslr_check=$(cat /proc/sys/kernel/randomize_va_space)
photon_aslr_check_output=$(cat << EOF
2
EOF
)
photon_aslr_check=$( echo "$photon_aslr_check" | awk '{$1=$1};1' )
photon_aslr_check_output=$( echo "$photon_aslr_check_output" | awk '{$1=$1};1' )
if [ "$photon_aslr_check" = "$photon_aslr_check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_aslr_check
fi
echo " "
echo "------------ V-256536 ------------"
photon_updated_versions=$(grep -i "^clean_requirements_on_remove" /etc/tdnf/tdnf.conf)
photon_updated_versions_output=$(cat << EOF
clean_requirements_on_remove=true
EOF
)
photon_updated_versions=$( echo "$photon_updated_versions" | awk '{$1=$1};1' )
photon_updated_versions_output=$( echo "$photon_updated_versions_output" | awk '{$1=$1};1' )
if [ "$photon_updated_versions" = "$photon_updated_versions_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_updated_versions
fi
echo " "
echo "------------ V-256537 ------------"
photon_sudo_audit=$(auditctl -l | grep sudo)
photon_sudo_audit_output=$(cat << EOF
-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
EOF
)
photon_sudo_audit_output_2=$(cat << EOF
-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged
EOF
)
photon_sudo_audit=$( echo "$photon_sudo_audit" | awk '{$1=$1};1' )
photon_sudo_audit_output=$( echo "$photon_sudo_audit_output" | awk '{$1=$1};1' )
photon_sudo_audit_output_2=$( echo "$photon_sudo_audit_output_2" | awk '{$1=$1};1' )
if [ "$photon_sudo_audit" = "$photon_sudo_audit_output" ] || [ "$photon_sudo_audit" = "$photon_sudo_audit_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_sudo_audit
fi
echo " "
echo "------------ V-256538 ------------"
photon_audit_logon=$(auditctl -l | grep -E "faillog|lastlog|tallylog")
photon_audit_logon_output=$(cat << EOF
-w /var/log/faillog -p wa
-w /var/log/lastlog -p wa
-w /var/log/tallylog -p wa
EOF
)
photon_audit_logon=$( echo "$photon_audit_logon" | awk '{$1=$1};1' )
photon_audit_logon_output=$( echo "$photon_audit_logon_output" | awk '{$1=$1};1' )
if [ "$photon_audit_logon" = "$photon_audit_logon_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_audit_logon
fi
echo " "
echo "------------ V-256539 ------------"
photon_audit_insmod=$(auditctl -l | grep "/sbin/insmod")
photon_audit_insmod_output=$(cat << EOF
-w /sbin/insmod -p x
EOF
)
photon_audit_insmod=$( echo "$photon_audit_insmod" | awk '{$1=$1};1' )
photon_audit_insmod_output=$( echo "$photon_audit_insmod_output" | awk '{$1=$1};1' )
if [ "$photon_audit_insmod" = "$photon_audit_insmod_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_audit_insmod
fi
echo " "
echo "------------ V-256540 ------------"
photon_audit_accounts=($(auditctl -l | grep -E /etc/security/opasswd | awk '{print $4}'))
photon_audit_accounts_check=false
for x in $photon_audit_accounts; do
    if [[ "$x" != *"w"* ]]; then
        photon_audit_accounts_check=true
    fi
done
if $photon_audit_accounts_check; then
    echo -e "\e[31mOpen\e[0m"
    echo $(auditctl -l | grep -E /etc/security/opasswd)
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-256541 ------------"
photon_pamcrack_module=$(grep pam_cracklib /etc/pam.d/system-password)
photon_pamcrack_module=$( echo "$photon_pamcrack_module" | awk '{$1=$1};1' )
if [[ "$photon_pamcrack_module" == "password requisite pam_cracklib.so"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_pamcrack_module
fi
echo " "
echo "------------ V-256542 ------------"
photon_fail_delay=$(grep FAIL_DELAY /etc/login.defs)
photon_fail_delay_output=$(cat << EOF
FAIL_DELAY 4
EOF
)
photon_fail_delay=$( echo "$photon_fail_delay" | awk '{$1=$1};1' )
photon_fail_delay_output=$( echo "$photon_fail_delay_output" | awk '{$1=$1};1' )
if [ "$photon_fail_delay" = "$photon_fail_delay_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_fail_delay
fi
echo " "
echo "------------ V-256543 ------------"
photon_four_second=$(grep pam_faildelay /etc/pam.d/system-auth)
photon_four_second_output=$(cat << EOF
auth       optional pam_faildelay.so delay=4000000
EOF
)
photon_four_second=$( echo "$photon_four_second" | awk '{$1=$1};1' )
photon_four_second_output=$( echo "$photon_four_second_output" | awk '{$1=$1};1' )
if [ "$photon_four_second" = "$photon_four_second_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_four_second
fi
echo " "
echo "------------ V-256544 ------------"
photon_audit_flush=$(grep -E "freq|flush" /etc/audit/auditd.conf)
photon_audit_flush_output=$(cat << EOF
flush = INCREMENTAL_ASYNC
freq = 50
EOF
)
photon_audit_flush=$( echo "$photon_audit_flush" | awk '{$1=$1};1' )
photon_audit_flush_output=$( echo "$photon_audit_flush_output" | awk '{$1=$1};1' )
if [ "$photon_audit_flush" = "$photon_audit_flush_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_audit_flush
fi
echo " "
echo "------------ V-256545 ------------"
photon_home_dir=$(grep -i "^create_home" /etc/login.defs)
photon_home_dir_output=$(cat << EOF
CREATE_HOME     yes
EOF
)
photon_home_dir=$( echo "$photon_home_dir" | awk '{$1=$1};1' )
photon_home_dir_output=$( echo "$photon_home_dir_output" | awk '{$1=$1};1' )
if [ "$photon_home_dir" = "$photon_home_dir_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_home_dir
fi
echo " "
echo "------------ V-256546 ------------"
photon_disable_debug_shell=$(systemctl status debug-shell.service | grep disabled)
photon_disable_debug_shell_output=$(cat << EOF
Loaded: loaded (/lib/systemd/system/debug-shell.service; disabled; vendor preset: disabled)
EOF
)
photon_disable_debug_shell=$( echo "$photon_disable_debug_shell" | awk '{$1=$1};1' )
photon_disable_debug_shell_output=$( echo "$photon_disable_debug_shell_output" | awk '{$1=$1};1' )
if [ "$photon_disable_debug_shell" = "$photon_disable_debug_shell_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_disable_debug_shell
fi
echo " "
echo "------------ V-256547 ------------"
photon_gssapi_auth=$(sshd -T|&grep -i GSSAPIAuthentication)
photon_gssapi_auth_output=$(cat << EOF
GSSAPIAuthentication no
EOF
)
photon_gssapi_auth_output_2=$(cat << EOF
gssapiauthentication no
EOF
)
photon_gssapi_auth=$( echo "$photon_gssapi_auth" | awk '{$1=$1};1' )
photon_gssapi_auth_output=$( echo "$photon_gssapi_auth_output" | awk '{$1=$1};1' )
photon_gssapi_auth_output_2=$( echo "$photon_gssapi_auth_output_2" | awk '{$1=$1};1' )
if [ "$photon_gssapi_auth" = "$photon_gssapi_auth_output" ] || [ "$photon_gssapi_auth" = "$photon_gssapi_auth_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_gssapi_auth
fi
echo " "
echo "------------ V-256548 ------------"
photon_disable_env_proc=$(sshd -T|&grep -i PermitUserEnvironment)
photon_disable_env_proc_output=$(cat << EOF
PermitUserEnvironment no
EOF
)
photon_disable_env_proc_output_2=$(cat << EOF
permituserenvironment no
EOF
)
photon_disable_env_proc=$( echo "$photon_disable_env_proc" | awk '{$1=$1};1' )
photon_disable_env_proc_output=$( echo "$photon_disable_env_proc_output" | awk '{$1=$1};1' )
photon_disable_env_proc_output_2=$( echo "$photon_disable_env_proc_output_2" | awk '{$1=$1};1' )
if [ "$photon_disable_env_proc" = "$photon_disable_env_proc_output" ] || [ "$photon_disable_env_proc" = "$photon_disable_env_proc_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_disable_env_proc
fi
echo " "
echo "------------ V-256549 ------------"
photon_disable_xforwarding=$(sshd -T|&grep -i X11Forwarding)
photon_disable_xforwarding_output=$(cat << EOF
X11Forwarding no
EOF
)
photon_disable_xforwarding_output_2=$(cat << EOF
x11forwarding no
EOF
)
photon_disable_xforwarding=$( echo "$photon_disable_xforwarding" | awk '{$1=$1};1' )
photon_disable_xforwarding_output=$( echo "$photon_disable_xforwarding_output" | awk '{$1=$1};1' )
photon_disable_xforwarding_output_2=$( echo "$photon_disable_xforwarding_output_2" | awk '{$1=$1};1' )
if [ "$photon_disable_xforwarding" = "$photon_disable_xforwarding_output" ] || [ "$photon_disable_xforwarding" = "$photon_disable_xforwarding_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_disable_xforwarding
fi
echo " "
echo "------------ V-256550 ------------"
photon_strict_mode=$(sshd -T|&grep -i StrictModes)
photon_strict_mode_output=$(cat << EOF
StrictModes yes
EOF
)
photon_strict_mode_output_2=$(cat << EOF
strictmodes yes
EOF
)
photon_strict_mode=$( echo "$photon_strict_mode" | awk '{$1=$1};1' )
photon_strict_mode_output=$( echo "$photon_strict_mode_output" | awk '{$1=$1};1' )
photon_strict_mode_output_2=$( echo "$photon_strict_mode_output_2" | awk '{$1=$1};1' )
if [ "$photon_strict_mode" = "$photon_strict_mode_output" ] || [ "$photon_strict_mode" = "$photon_strict_mode_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_strict_mode
fi
echo " "
echo "------------ V-256551 ------------"
photon_disallow_kerberos=$(sshd -T|&grep -i KerberosAuthentication)
photon_disallow_kerberos_output=$(cat << EOF
kerberosauthentication no
EOF
)
photon_disallow_kerberos_output_2=$(cat << EOF
kerberosauthentication no
EOF
)
photon_disallow_kerberos=$( echo "$photon_disallow_kerberos" | awk '{$1=$1};1' )
photon_disallow_kerberos_output=$( echo "$photon_disallow_kerberos_output" | awk '{$1=$1};1' )
photon_disallow_kerberos_output_2=$( echo "$photon_disallow_kerberos_output_2" | awk '{$1=$1};1' )
if [ "$photon_disallow_kerberos" = "$photon_disallow_kerberos_output" ] || [ "$photon_disallow_kerberos" = "$photon_disallow_kerberos_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_disallow_kerberos
fi
echo " "
echo "------------ V-256552 ------------"
photon_disallow_empty_password=$(sshd -T|&grep -i PermitEmptyPasswords)
photon_disallow_empty_password_output=$(cat << EOF
PermitEmptyPasswords no
EOF
)
photon_disallow_empty_password_output_2=$(cat << EOF
permitemptypasswords no
EOF
)
photon_disallow_empty_password=$( echo "$photon_disallow_empty_password" | awk '{$1=$1};1' )
photon_disallow_empty_password_output=$( echo "$photon_disallow_empty_password_output" | awk '{$1=$1};1' )
photon_disallow_empty_password_output_2=$( echo "$photon_disallow_empty_password_output_2" | awk '{$1=$1};1' )
if [ "$photon_disallow_empty_password" = "$photon_disallow_empty_password_output" ] || [ "$photon_disallow_empty_password" = "$photon_disallow_empty_password_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_disallow_empty_password
fi
echo " "
echo "------------ V-256553 ------------"
photon_disallow_compression=$(sshd -T|&grep -i Compression)
photon_disallow_compression_output=$(cat << EOF
Compression no
EOF
)
photon_disallow_compression_output_2=$(cat << EOF
compression no
EOF
)
photon_disallow_compression=$( echo "$photon_disallow_compression" | awk '{$1=$1};1' )
photon_disallow_compression_output=$( echo "$photon_disallow_compression_output" | awk '{$1=$1};1' )
photon_disallow_compression_output_2=$( echo "$photon_disallow_compression_output_2" | awk '{$1=$1};1' )
if [ "$photon_disallow_compression" = "$photon_disallow_compression_output" ] || [ "$photon_disallow_compression" = "$photon_disallow_compression_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_disallow_compression
fi
echo " "
echo "------------ V-256554 ------------"
photon_last_login=$(sshd -T|&grep -i PrintLastLog)
photon_last_login_output=$(cat << EOF
PrintLastLog yes
EOF
)
photon_last_login_output_2=$(cat << EOF
printlastlog yes
EOF
)
photon_last_login=$( echo "$photon_last_login" | awk '{$1=$1};1' )
photon_last_login_output=$( echo "$photon_last_login_output" | awk '{$1=$1};1' )
photon_last_login_output_2=$( echo "$photon_last_login_output_2" | awk '{$1=$1};1' )
if [ "$photon_last_login" = "$photon_last_login_output" ] || [ "$photon_last_login" = "$photon_last_login_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_last_login
fi
echo " "
echo "------------ V-256555 ------------"
photon_ignore_trusted_host=$(sshd -T|&grep -i IgnoreRhosts)
photon_ignore_trusted_host_output=$(cat << EOF
IgnoreRhosts yes
EOF
)
photon_ignore_trusted_host_output_2=$(cat << EOF
ignorerhosts yes
EOF
)
photon_ignore_trusted_host=$( echo "$photon_ignore_trusted_host" | awk '{$1=$1};1' )
photon_ignore_trusted_host_output=$( echo "$photon_ignore_trusted_host_output" | awk '{$1=$1};1' )
photon_ignore_trusted_host_output_2=$( echo "$photon_ignore_trusted_host_output_2" | awk '{$1=$1};1' )
if [ "$photon_ignore_trusted_host" = "$photon_ignore_trusted_host_output" ] || [ "$photon_ignore_trusted_host" = "$photon_ignore_trusted_host_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_ignore_trusted_host
fi
echo " "
echo "------------ V-256556 ------------"
photon_ignore_user_host=$(sshd -T|&grep -i IgnoreUserKnownHosts)
photon_ignore_user_host_output=$(cat << EOF
IgnoreUserKnownHosts yes
EOF
)
photon_ignore_user_host_output_2=$(cat << EOF
ignoreuserknownhosts yes
EOF
)
photon_ignore_user_host=$( echo "$photon_ignore_user_host" | awk '{$1=$1};1' )
photon_ignore_user_host_output=$( echo "$photon_ignore_user_host_output" | awk '{$1=$1};1' )
photon_ignore_user_host_output_2=$( echo "$photon_ignore_user_host_output_2" | awk '{$1=$1};1' )
if [ "$photon_ignore_user_host" = "$photon_ignore_user_host_output" ] || [ "$photon_ignore_user_host" = "$photon_ignore_user_host_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_ignore_user_host
fi
echo " "
echo "------------ V-256557 ------------"
photon_max_tries=$(sshd -T|&grep -i MaxAuthTries)
photon_max_tries_output=$(cat << EOF
MaxAuthTries 6
EOF
)
photon_max_tries_output_2=$(cat << EOF
maxAuthtries 6
EOF
)
photon_max_tries=$( echo "$photon_max_tries" | awk '{$1=$1};1' )
photon_max_tries_output=$( echo "$photon_max_tries_output" | awk '{$1=$1};1' )
photon_max_tries_output_2=$( echo "$photon_max_tries_output_2" | awk '{$1=$1};1' )
if [ "$photon_max_tries" = "$photon_max_tries_output" ] || [ "$photon_max_tries" = "$photon_max_tries_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_max_tries
fi
echo " "
echo "------------ V-256558 ------------"
photon_disable_ctrladel=$(systemctl show ctrl-alt-del.target | grep -i activestate)
photon_disable_ctrladel_output=$(cat << EOF
ActiveState=inactive
EOF
)
photon_disable_ctrladel=$( echo "$photon_disable_ctrladel" | awk '{$1=$1};1' )
photon_disable_ctrladel_output=$( echo "$photon_disable_ctrladel_output" | awk '{$1=$1};1' )
if [ "$photon_disable_ctrladel" = "$photon_disable_ctrladel_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_disable_ctrladel
fi
echo " "
echo "------------ V-256559 ------------"
photon_default_scripts=$(stat -c "%n permissions are %a and owned by %U:%G" /etc/skel/.[^.]*)
photon_default_scripts_output=$(cat << EOF
/etc/skel/.bash_logout permissions are 750 and owned by root:root
/etc/skel/.bash_profile permissions are 644 and owned by root:root
/etc/skel/.bashrc permissions are 750 and owned by root:root
EOF
)
photon_default_scripts=$( echo "$photon_default_scripts" | awk '{$1=$1};1' )
photon_default_scripts_output=$( echo "$photon_default_scripts_output" | awk '{$1=$1};1' )
if [ "$photon_default_scripts" = "$photon_default_scripts_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_default_scripts
fi
echo " "
echo "------------ V-256560 ------------"
photon_root_path=$(stat -c "%n permissions are %a and owned by %U:%G" /root)
photon_root_path_output=$(cat << EOF
/root permissions are 700 and owned by root:root
EOF
)
photon_root_path=$( echo "$photon_root_path" | awk '{$1=$1};1' )
photon_root_path_output=$( echo "$photon_root_path_output" | awk '{$1=$1};1' )
if [ "$photon_root_path" = "$photon_root_path_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_root_path
fi
echo " "
echo "------------ V-256561 ------------"
photon_init_scripts=$(find /etc/bash.bashrc /etc/profile /etc/profile.d/ -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
photon_init_scripts=$( echo "$photon_init_scripts" | awk '{$1=$1};1' )
if [ -z "$photon_init_scripts" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_init_scripts
fi
echo " "
echo "------------ V-256562 ------------"
photon_startup_scripts=$(find /etc/rc.d/* -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
photon_startup_scripts=$( echo "$photon_startup_scripts" | awk '{$1=$1};1' )
if [ -z "$photon_startup_scripts" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_startup_scripts
fi
echo " "
echo "------------ V-256563 ------------"
photon_valid_owner_group=$(find / -fstype ext4 -nouser -o -nogroup -exec ls -ld {} \; 2>/dev/null)
photon_valid_owner_group=$( echo "$photon_valid_owner_group" | awk '{$1=$1};1' )
if [ -z "$photon_valid_owner_group" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $photon_valid_owner_group
fi
echo " "
