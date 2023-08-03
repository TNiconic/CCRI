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
    find /usr/lib/vmware-perfcharts/tc-instance/webapps/ -xdev -type f -a '(' -not -user root -a -not -user perfcharts -o -not -group root ')' -exec ls -la {} \;
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
