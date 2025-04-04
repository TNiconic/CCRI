#!/bin/bash

#****************************************************************
#*************Written By Mitchell Gibson USACPB CRIA*************
#************Last Updated April 4, 2025 v1.0*********************
#****************************************************************

clear

#Get Host Information
hostname_var=$(hostname)
ip_address=$(ip -o -4 addr show dev eth0 | awk '{print $4}' | cut -d '/' -f 1)
mac_address=$(ip -o link show dev eth0 | awk '{print $17}')
domain=$(dnsdomainname)

count=0
echo "Hostname:"$hostname_var 
echo "IP Address:"$ip_address
echo "MAC Address:"$mac_address
echo "FQDN:"$hostname_var.$domain
echo "Role: Member Server"
echo "Technology Area: Other Review"
echo " "
echo ----------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 vCenter Security Technical Implementation Guide
echo ----------------------------------------------------------------------------
echo " "
echo "------------ V-258931 ------------"
appliancesh
snmp.get
exit
echo " If "Enable" is set to "False", this is not a finding.
If "Enable" is set to "True" and "Authentication" is not set to "SHA1", this is a finding.
If "Enable" is set to "True" and "Privacy" is not set to "AES128", this is a finding.
If any "Users" are configured with a "Sec_level" that does not equal "priv", this is a finding. "
echo " "
echo " "
echo " Other checks are performed via the GUI"
echo -----------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 ESX Agent Manager Technical Implementation Guide
echo -----------------------------------------------------------------------------
echo " "
echo "------------ V-259003 ------------"
esx_max=$(xmllint --xpath '/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads' /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_max_output=$(cat << EOF
maxThreads="300"
EOF
)
esx_max_output_2=$(cat << EOF
maxThreads=300
EOF
)
esx_max=$( echo "$esx_max" | awk '{$1=$1};1' )
esx_max_output=$( echo "$esx_max_output" | awk '{$1=$1};1' )
esx_max_output_2=$( echo "$esx_max_output_2" | awk '{$1=$1};1' )
if [ "$esx_max" = "$esx_max_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ "$esx_max" = "$esx_max_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_max
    ((count++))
fi
echo " "
echo "------------ V-259004 ------------"
esx_secure=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' - 2>/dev/null)
esx_secure_output=$(cat << EOF
<secure>true</secure>
EOF
)
esx_secure=$( echo "$esx_secure" | awk '{$1=$1};1' )
esx_secure_output=$( echo "$esx_secure_output" | awk '{$1=$1};1' )
if [ "$esx_secure" = "$esx_secure_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_secure
    ((count++))
fi
echo " "
echo "------------ V-259005 ------------"
esx_session=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/eam.json)
esx_session_output=$(cat << EOF
"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/eam/jvm.log",
EOF
)
esx_session_output_2=$(cat << EOF
"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/eam/jvm.log"
EOF
)
esx_session=$( echo "$esx_session" | awk '{$1=$1};1' )
esx_session_output=$( echo "$esx_session_output" | awk '{$1=$1};1' )
esx_session_output_2=$( echo "$esx_session_output_2" | awk '{$1=$1};1' )
if [ "$esx_session" = "$esx_session_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ "$esx_session" = "$esx_session_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_session
    ((count++))
fi
echo " "
echo "------------ V-259006 ------------"
esx_logs=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_logs_output=$(cat << EOF
%h %{X-Forwarded-For}i %l %t %u &quot;%r&quot; %s %b
EOF
)
esx_logs=$( echo "$esx_logs" | awk '{$1=$1};1' )
esx_logs_output=$( echo "$esx_logs_output" | awk '{$1=$1};1' )
if [ "$esx_logs" = "$esx_logs_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_logs
    ((count++))
    echo "Compare the above output with the pattern described in the check text"
fi
echo " "
echo "------------ V-259007 ------------"
esx_logs_permissions=$(find /var/log/vmware/eam/ -xdev ! -name install.log -type f -a '(' -perm -o+w -o -not -user eam -o -not -group eam ')' -exec ls -ld {} \; 2>/dev/null)
esx_logs_permissions=$( echo "$esx_logs_permissions" | awk '{$1=$1};1' )
if [ -z "$esx_logs_permissions" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_logs_permissions
    ((count++))
fi
echo " "
echo "------------ V-259008 ------------"
esx_agent_permissions=$(xmllint --xpath '/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]' /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_agent_permissions_output=$(cat << EOF
<Listener className="org.apache.catalina.security.SecurityListener"/>
EOF
)
eesx_agent_permissions=$( echo "$esx_agent_permissions" | awk '{$1=$1};1' )
esx_agent_permissions_output=$( echo "$esx_agent_permissions_output" | awk '{$1=$1};1' )
if [ -z "$esx_agent_permissions" ]; then
    echo -e "\e[31mOpen\e[0m"
    ((count++))
    echo "Listener not present"
elif [ "$esx_agent_permissions" = "$esx_agent_permissions_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_agent_permissions
    ((count++))
fi
echo " "
echo "------------ V-259009 ------------"
esx_tracing=$(xmllint --xpath "//Connector[@allowTrace = 'true']" /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_tracing=$( echo "$esx_tracing" | awk '{$1=$1};1' )
if [ -z "$esx_tracing" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_tracing
    ((count++))
fi
echo " "
echo "------------ V-259010 ------------"
esx_specific=$(xmllint --xpath "//Connector[(@port = '0') or not(@address)]" /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_specific=$( echo "$esx_specific" | awk '{$1=$1};1' )
if [ -z "$esx_specific" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_specific
    ((count++))
fi
echo " "
echo "------------ V-259011 ------------"
esx_limit_data=$(grep RECYCLE_FACADES /etc/vmware-eam/catalina.properties 2>/dev/null)
esx_limit_data_output=$(cat << EOF
org.apache.catalina.connector.RECYCLE_FACADES=true
EOF
)
esx_limit_data=$( echo "$esx_limit_data" | awk '{$1=$1};1' )
esx_limit_data_output=$( echo "$esx_limit_data_output" | awk '{$1=$1};1' )
if [ -z "$esx_limit_data" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ "$esx_limit_data" = "$esx_limit_data_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_limit_data
    ((count++))
fi
echo " "
echo "------------ V-259012 ------------"
esx_safe=$(grep EXIT_ON_INIT_FAILURE /etc/vmware-eam/catalina.properties 2>/dev/null)
esx_safe_output=$(cat << EOF
org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
EOF
)
esx_safe=$( echo "$esx_safe" | awk '{$1=$1};1' )
esx_safe_output=$( echo "$esx_safe_output" | awk '{$1=$1};1' )
if [ -z "$esx_safe" ]; then
    echo -e "\e[31mOpen\e[0m"
    ((count++))
elif [ "$esx_safe" = "$esx_safe_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_safe
    ((count++))
fi
echo " "
echo "------------ V-259013 ------------"
esx_post=$(xmllint --xpath '/Server/Service/Connector/@maxPostSize' /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_post=$( echo "$esx_post" | awk '{$1=$1};1' )
if [ -z "$esx_post" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_post
    ((count++))
fi
echo " "
echo "------------ V-259014 ------------"
esx_showserver=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_showserver_output=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>
EOF
)
esx_showserver=$( echo "$esx_showserver" | awk '{$1=$1};1' )
esx_showserver_output=$( echo "$esx_showserver_output" | awk '{$1=$1};1' )
if [ -z "$esx_showserver" ]; then
    echo -e "\e[31mOpen\e[0m"
    ((count++))
    echo "Element is not defined"
elif [ "$esx_showserver" = "$esx_showserver_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_showserver
    ((count++))
fi
echo " "
echo "------------ V-259015 ------------"
esx_showserver=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/session-timeout' - 2>/dev/null)
esx_showserver_output=$(cat << EOF
<session-timeout>30</session-timeout>
EOF
)
esx_showserver=$(echo "$esx_showserver" | awk '{$1=$1};1' )
esx_showserver_output=$( echo "$esx_showserver_output" | awk '{$1=$1};1' )
if [ -z "$esx_showserver" ]; then
    echo -e "\e[31mOpen\e[0m"
    ((count++))
    echo "Session timeout is missing"
elif [ "$esx_showserver" = "$esx_showserver_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_showserver
    ((count++))
fi
echo " "
echo "------------ V-259016 ------------"
esx_offload=$(cat /etc/vmware-syslog/vmware-services-eam.conf 2>/dev/null)
esx_offload_output=$(cat << EOF
#eam.log
input(type="imfile"
      File="/var/log/vmware/eam/eam.log"
      Tag="eam-main"
      Severity="info"
      Facility="local0")
#eam_api.log
input(type="imfile"
      File="/var/log/vmware/eam/eam_api.log"
      Tag="eam-api"
      Severity="info"
      Facility="local0")
#eam web access logs
input(type="imfile"
      File="/var/log/vmware/eam/web/localhost_access.log"
      Tag="eam-access"
      Severity="info"
      Facility="local0")
#eam jvm logs
input(type="imfile"
      File="/var/log/vmware/eam/jvm.log.stdout"
      Tag="eam-stdout"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/jvm.log.stderr"
      Tag="eam-stderr"
      Severity="info"
      Facility="local0")
#eam catalina logs
input(type="imfile"
      File="/var/log/vmware/eam/web/catalina.log"
      Tag="eam-catalina"
      Severity="info"
      Facility="local0")
#eam catalina localhost logs
input(type="imfile"
      File="/var/log/vmware/eam/web/localhost.log"
      Tag="eam-catalina"
      Severity="info"
      Facility="local0")
#eam firstboot logs
input(type="imfile"
      File="/var/log/vmware/firstboot/eam_firstboot.py*.log"
      Tag="eam-firstboot"
      Severity="info"
      Facility="local0")
EOF
)
esx_offload=$(echo "$esx_offload" | awk '{$1=$1};1' )
esx_offload_output=$(echo "$esx_offload_output" | awk '{$1=$1};1' )
if [ "$esx_offload" = "$esx_offload_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_offload
    ((count++))
fi
echo " "
echo "------------ V-259017 ------------"
esx_servlet_comply=$(grep STRICT_SERVLET_COMPLIANCE /etc/vmware-eam/catalina.properties 2>/dev/null)
esx_servlet_comply_output=$(cat << EOF
org.apache.catalina.STRICT_SERVLET_COMPLIANCE=true
EOF
)
esx_servlet_comply=$(echo "$esx_servlet_comply" | awk '{$1=$1};1' )
esx_servlet_comply_output=$( echo "$esx_servlet_comply_output" | awk '{$1=$1};1' )
if [ -z "$esx_servlet_comply" ]; then
    echo -e "\e[31mOpen\e[0m"
    ((count++))
    echo "No results found"
elif [ "$esx_servlet_comply" = "$esx_servlet_comply_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_servlet_comply
    ((count++))
fi
echo " "
echo "------------ V-259018 ------------"
esx_limit_tcp=$(xmllint --xpath "//Connector[@connectionTimeout = '-1']" /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_limit_tcp=$( echo "$esx_limit_tcp" | awk '{$1=$1};1' )
if [ -z "$esx_limit_tcp" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_limit_tcp
    ((count++))
fi
echo " "
echo "------------ V-259019 ------------"
esx_keepalive_tcp=$(xmllint --xpath "//Connector[@maxKeepAliveRequests = '-1']" /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
esx_keepalive_tcp=$( echo "$esx_keepalive_tcp" | awk '{$1=$1};1' )
if [ -z "$esx_keepalive_tcp" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_keepalive_tcp
    ((count++))
fi
echo " "
echo "------------ V-259020 ------------"
esx_char_encoding=$(xmllint --xpath "//*[contains(text(), 'setCharacterEncodingFilter')]/parent::*" /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml)
esx_char_encoding_output=$(cat << EOF
<filter-mapping>
  <filter-name>setCharacterEncodingFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
<filter>
  <filter-name>setCharacterEncodingFilter</filter-name>
  <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
  <async-supported>true</async-supported>
  <init-param>
    <param-name>encoding</param-name>
    <param-value>UTF-8</param-value>
  </init-param>
  <init-param>
    <param-name>ignore</param-name>
    <param-value>true</param-value>
  </init-param>
</filter>
EOF
)
esx_char_encoding=$( echo "$esx_char_encoding" | awk '{$1=$1};1' )
esx_char_encoding_output=$( echo "$esx_char_encoding_output" | awk '{$1=$1};1' )
if [ "$esx_char_encoding" = "$esx_char_encoding_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_char_encoding
    ((count++))
fi
echo " "
echo "------------ V-259021 ------------"
check=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' -)
check_output=$(cat << EOF
<http-only>true</http-only>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259022 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'DefaultServlet')]/parent::*" /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"false"* ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259023 ------------"
check=$(xmllint --xpath "//Server/@port" /usr/lib/vmware-eam/web/conf/server.xml)
check2=$(grep 'base.shutdown.port' /etc/vmware-eam/catalina.properties)
check_output1=$(cat << EOF
port="${base.shutdown.port}"
EOF
)
check_output2=$(cat << EOF
base.shutdown.port=-1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output1" ] && [ "$check2" = "$check_output2"]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    ((count++))
fi
echo " "
echo "------------ V-259024 ------------"
check=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="debug"]/parent::init-param' - 2>/dev/null)
check_output=$(cat << EOF
<init-param>
      <param-name>debug</param-name>
      <param-value>0</param-value>
</init-param>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259025 ------------"
check=$(xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' - 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259026 ------------"
check=$(xmllint --xpath "//Host/@deployXML" /usr/lib/vmware-eam/web/conf/server.xml)
check_output=$(cat << EOF
deployXML="false"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259027 ------------"
check=$( xmllint --xpath "//Host/@deployXML" /usr/lib/vmware-eam/web/conf/server.xml)
check_output=$(cat << EOF
deployXML="false"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259028 ------------"
check=$(xmllint --xpath "//Connector/@xpoweredBy" /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259029 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/examples 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259030 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/ROOT 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259031 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/docs 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259032 ------------"
check=$(find /usr/lib/vmware-eam/web/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259033 ------------"
check=$(grep ALLOW_BACKSLASH /etc/vmware-eam/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.connector.ALLOW_BACKSLASH=false
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259034 ------------"
check=$(grep ENFORCE_ENCODING_IN_GET_WRITER /etc/vmware-eam/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259035 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259036 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/host-manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo -----------------------------------------------------------------
echo ----------VMware vSphere 8.0 Envoy Technical Implementation Guide
echo -----------------------------------------------------------------
echo " "
echo "------------ V-259161 ------------"
check=$(find /var/log/vmware/rhttpproxy/ -xdev -type f -a '(' -perm -o+w -o -not -user rhttpproxy -o -not -group rhttpproxy ')' -exec ls -ld {} \; 2>/dev/null)
check2=$(find /var/log/vmware/envoy/ -xdev -type f -a '(' -perm -o+w -o -not -user envoy -o -not -group envoy ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ -z "$check" ] && [ -z "$check2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    ((count++))
fi
echo " "
echo "------------ V-259162 ------------"
check=$(stat -c "%n permissions are %a, is owned by %U and group owned by %G" /etc/vmware-rhttpproxy/ssl/rui.key)
check_output=$(cat << EOF
/etc/vmware-rhttpproxy/ssl/rui.key permissions are 600, is owned by rhttpproxy and group owned by rhttpproxy
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259163 ------------"
check=$(cat /etc/vmware-syslog/vmware-services-rhttpproxy.conf)
check_output=$(cat << EOF
#rhttpproxy log
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rhttpproxy.log"
      Tag="rhttpproxy-main"
      Severity="info"
      Facility="local0")
#rhttpproxy init stdout
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rproxy_init.log.stdout"
      Tag="rhttpproxy-stdout"
      Severity="info"
      Facility="local0")
#rhttpproxy init stderr
input(type="imfile"
      File="/var/log/vmware/rhttpproxy/rproxy_init.log.stderr"
      Tag="rhttpproxy-stderr"
      Severity="info"
      Facility="local0")
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259164 ------------"
check=$(cat /etc/vmware-syslog/vmware-services-envoy.conf)
check_output=$(cat << EOF
#envoy service log
input(type="imfile"
      File="/var/log/vmware/envoy/envoy.log"
      Tag="envoy-main"
      Severity="info"
      Facility="local0")
#envoy access log
input(type="imfile"
      File="/var/log/vmware/envoy/envoy-access.log"
      Tag="envoy-access"
      Severity="info"
      Facility="local0")
#envoy init stdout
input(type="imfile"
      File="/var/log/vmware/envoy/envoy_init.log.stdout"
      Tag="envoy-stdout"
      Severity="info"
      Facility="local0")
#envoy init stderr
input(type="imfile"
      File="/var/log/vmware/envoy/envoy_init.log.stderr"
      Tag="envoy-stderr"
      Severity="info"
      Facility="local0")
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259165 ------------"
check=$( xmllint --xpath '/config/envoy/L4Filter/maxRemoteHttpsConnections/text()' /etc/vmware-rhttpproxy/config.xml 2>/dev/null)
check2=$(xmllint --xpath '/config/envoy/L4Filter/maxRemoteHttpConnections/text()' /etc/vmware-rhttpproxy/config.xml 2>/dev/null)
check_output1=$(cat << EOF
2048
EOF
)
check_output2=$(cat << EOF
2048
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output1" ] && [ "$check2" = "$check_output2"]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ] && [ -z "$check2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    ((count++))
fi
echo " "
echo --------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 Lookup Service Technical Implementation Guide
echo --------------------------------------------------------------------------
echo " "
echo "------------ V-259037 ------------"
check=$(xmllint --xpath '/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads' /usr/lib/vmware-lookupsvc/conf/server.xml)
check_output=$(cat << EOF
maxThreads="300"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259038 ------------"
check=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' -)
check_output=$(cat << EOF
<secure>true</secure>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259039 ------------"
check=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/lookupsvc.json)
check_output=$(cat << EOF
"StreamRedirectFile": "%VMWARE_LOG_DIR%/vmware/lookupsvc/lookupsvc_stream.log",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo "Check if there is output behind "StremRedirectFile:" if there is this is NF"
    ((count++))
fi
echo " "
echo "------------ V-259040 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-lookupsvc/conf/server.xml)
check_elements() {
  local input_string="$1"
  local elements=("%h" "%{X-Forwarded-For}i" "%l" "%t" "%u" "\"%r\"" "%s" "%b")
  local all_present=true
  for element in "${elements[@]}"; do
    if [[ ! "$input_string" == *"$element"* ]]; then
      all_present=false
      break
    fi
  done

  if [ "$all_present" = true ]; then
    return 0
  else
    return 1
  fi
}
check_output=$(cat << EOF
pattern="%t %I [Request] &quot;%{User-Agent}i&quot; %{X-Forwarded-For}i/%h:%{remote}p %l %u to local %{local}p - &quot;%r&quot; %H %m %U%q    [Response] %s - %b bytes    [Perf] process %Dms / commit %Fms / conn [%X]"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif check_elements "$check"; then
    echo -e "\e[32mNot a Finding\e[0m"  
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259041 ------------"
check=$(find /var/log/vmware/lookupsvc/ -xdev ! -name lookupsvc-init.log ! -name lookupsvc-prestart.log -type f -a '(' -perm -o+w -o -not -user lookupsvc -o -not -group lookupsvc ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259042 ------------"
check=$(xmllint --xpath '/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]' /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
<Listener className="org.apache.catalina.security.SecurityListener"/>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    umask_value=$(xmllint --xpath 'string(/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]/@minimumUmask)' /usr/lib/vmware-lookupsvc/conf/server.xml)
    if [ -z "$umask_value" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        ((count++))
    elif [ "$umask_value" != "0007" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        ((count++))
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259043 ------------"
check=$(xmllint --xpath "//Connector[@allowTrace = 'true']" /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259044 ------------"
check=$(xmllint --xpath "//Connector[(@port = '0') or not(@address)]" /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259045 ------------"
check=$(grep RECYCLE_FACADES /usr/lib/vmware-lookupsvc/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.connector.RECYCLE_FACADES=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259046 ------------"
check=$(grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-lookupsvc/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "No Results"
    ((count++))
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259047 ------------"
check=$(xmllint --xpath "//Connector[@URIEncoding != 'UTF-8'] | //Connector[not[@URIEncoding]]" /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259048 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-lookupsvc/conf/server.xml)
check_output=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259049 ------------"
check=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/session-timeout' - 2>/dev/null)
check_output=$(cat << EOF
<session-timeout>30</session-timeout>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif
    [ -z "$check" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
else
    timeout=$(echo "$check" | grep -oP '<session-timeout>\K\d+(?=</session-timeout>)')
    if [[ -n "$timeout" ]]; then 
        if (( timeout <= 30 )); then
            echo "Session timeout is 30 or less."
        else
            echo "Session timeout is greater than 30."
        fi
    else
        echo -e "\e[31mOpen\e[0m"
        echo $check
        ((count++))
    fi
fi
echo " "
echo "------------ V-259050 ------------"
check=$(cat /etc/vmware-syslog/vmware-services-lookupsvc.conf)
check_output=$(cat << EOF
#catalina
input(type="imfile"
      File="/var/log/vmware/lookupsvc/tomcat/catalina.*.log"
      Tag="lookupsvc-tc-catalina"
      Severity="info"
      Facility="local0")
#localhost
input(type="imfile"
      File="/var/log/vmware/lookupsvc/tomcat/localhost.*.log"
      Tag="lookupsvc-tc-localhost"
      Severity="info"
      Facility="local0")
#localhost_access_log
input(type="imfile"
      File="/var/log/vmware/lookupsvc/tomcat/localhost_access.log"
      Tag="lookupsvc-localhost_access"
      Severity="info"
      Facility="local0")
#lookupsvc-init
input(type="imfile"
      File="/var/log/vmware/lookupsvc/lookupsvc-init.log"
      Tag="lookupsvc-init"
      Severity="info"
      Facility="local0")
#prestart
input(type="imfile"
      File="/var/log/vmware/lookupsvc/lookupsvc-prestart.log"
      Tag="lookupsvc-prestart"
      Severity="info"
      Facility="local0")
#health
input(type="imfile"
      File="/var/log/vmware/lookupsvc/lookupsvc-health.log"
      Tag="lookupsvc-health"
      Severity="info"
      Facility="local0")
#lookupserver-default
input(type="imfile"
      File="/var/log/vmware/lookupsvc/lookupserver-default.log"
      Tag="lookupsvc-lookupserver-default"
      Severity="info"
      Facility="local0")
#lookupsvc_stream.log.std
input(type="imfile"
      File="/var/log/vmware/lookupsvc/lookupsvc_stream.log.std*"
      Tag="lookupsvc-std"
      Severity="info"
      Facility="local0")
#ls-gc
input(type="imfile"
      File="/var/log/vmware/lookupsvc/vmware-lookupsvc-gc.log.*.current"
      Tag="lookupsvc-gc"
      Severity="info"
      Facility="local0")
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259051 ------------"
check=$(grep STRICT_SERVLET_COMPLIANCE /usr/lib/vmware-lookupsvc/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.STRICT_SERVLET_COMPLIANCE=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "No Results"
    ((count++))
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259052 ------------"
check=$(xmllint --xpath "//Connector[@connectionTimeout = '-1']" /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259053 ------------"
check=$(xmllint --xpath "//Connector[@maxKeepAliveRequests = '-1']" /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259054 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'setCharacterEncodingFilter')]/parent::*" /usr/lib/vmware-lookupsvc/conf/web.xml 2>/dev/null)
check_output=$(cat << EOF
<filter-mapping>
  <filter-name>setCharacterEncodingFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
<filter>
  <filter-name>setCharacterEncodingFilter</filter-name>
  <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
  <async-supported>true</async-supported>
  <init-param>
    <param-name>encoding</param-name>
    <param-value>UTF-8</param-value>
  </init-param>
  <init-param>
    <param-name>ignore</param-name>
    <param-value>true</param-value>
  </init-param>
</filter>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259055 ------------"
check=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' -)
check_output=$(cat << EOF
<http-only>true</http-only>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259056 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'DefaultServlet')]/parent::*" /usr/lib/vmware-lookupsvc/conf/web.xml)
check_output=$(cat << EOF
<servlet>
      <description>File servlet</description>
      <servlet-name>FileServlet</servlet-name>
      <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
</servlet>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$check" == *"false"* ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++)) 
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259057 ------------"
check=$(xmllint --xpath "//Server/@port" /usr/lib/vmware-lookupsvc/conf/server.xml)
check2=$(grep 'base.shutdown.port' /usr/lib/vmware-lookupsvc/conf/catalina.properties)
check_output1=$(cat << EOF
port="${base.shutdown.port}"
EOF
)
check_output2=$(cat << EOF
base.shutdown.port=-1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output1" ] && [ "$check2" = "$check_output2"]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    ((count++))
fi
echo " "
echo "------------ V-259058 ------------"
check=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="debug"]/parent::init-param' - 2>/dev/null)
check_output=$(cat << EOF
<init-param>
      <param-name>debug</param-name>
      <param-value>0</param-value>
</init-param>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259059 ------------"
check=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' - 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"false"* ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++)) 
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259060 ------------"
check=$(xmllint --xpath "//Host/@deployXML" /usr/lib/vmware-lookupsvc/conf/server.xml)
check_output=$(cat << EOF
deployXML="false"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259061 ------------"
check=$(xmllint --xpath "//Host/@autoDeploy" /usr/lib/vmware-lookupsvc/conf/server.xml)
check_output=$(cat << EOF
autoDeploy="false"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259062 ------------"
check=$(xmllint --xpath "//Connector/@xpoweredBy" /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"true"* ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++)) 
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259063 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/examples 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259064 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/ROOT 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259065 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/docs 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259066 ------------"
check=$(find /usr/lib/vmware-lookupsvc/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259067 ------------"
check=$(grep ALLOW_BACKSLASH /usr/lib/vmware-lookupsvc/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.connector.ALLOW_BACKSLASH=false
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259068 ------------"
check=$(grep ENFORCE_ENCODING_IN_GET_WRITER /usr/lib/vmware-lookupsvc/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259069 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259070 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/host-manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo ----------------------------------------------------------------------
echo ----------VMware vSphere 8.0 Perfcharts Technical Implementation Guide
echo ----------------------------------------------------------------------
echo " "
echo "------------ V-259071 ------------"
check=$(xmllint --xpath '/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
maxThreads="300"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259072 ------------"
check=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' - 2>/dev/null)
check_output=$(cat << EOF
<secure>true</secure>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259073 ------------"
chekc=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/perfcharts.json)
check_output=$(cat << EOF
"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/perfcharts/vmware-perfcharts-runtime.log",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check_session
    echo "Check if there is output behind "StremRedirectFile:" if there is this is NF"
    ((count++))
fi
echo " "
echo "------------ V-259074 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml)
check_elements() {
  local input_string="$1"
  local elements=("%h" "%{X-Forwarded-For}i" "%l" "%t" "%u" "\"%r\"" "%s" "%b")
  local all_present=true
  for element in "${elements[@]}"; do
    if [[ ! "$input_string" == *"$element"* ]]; then
      all_present=false
      break
    fi
  done

  if [ "$all_present" = true ]; then
    return 0
  else
    return 1
  fi
}
check_output=$(cat << EOF
pattern="%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b &quot;%{User-Agent}i&quot;"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif check_elements "$check"; then
    echo -e "\e[32mNot a Finding\e[0m"  
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259075 ------------"
check=$( find /var/log/vmware/perfcharts/ -xdev -type f -a '(' -perm -o+w -o -not -user perfcharts -o -not -group users ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259076 ------------"
check=$(xmllint --xpath '/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
<Listener className="org.apache.catalina.security.SecurityListener"/>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    umask_value=$(xmllint --xpath 'string(/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]/@minimumUmask)' /usr/lib/vmware-lookupsvc/conf/server.xml)
    if [ -z "$umask_value" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        ((count++))
    elif [ "$umask_value" != "0007" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        ((count++))
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259077 ------------"
check=$( xmllint --xpath "//Connector[@allowTrace = 'true']" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259078 ------------"
check=$( xmllint --xpath "//Connector[(@port = '0') or not(@address)]" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259079 ------------"
check=$(grep RECYCLE_FACADES /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.connector.RECYCLE_FACADES=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259080 ------------"
check=$(grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    ((count++))
fi
echo " "
echo "------------ V-259081 ------------"

echo " "
echo "------------ V-259082 ------------"

echo " "
echo "------------ V-259083 ------------"

echo " "
echo "------------ V-259084 ------------"

echo " "
echo "------------ V-259085 ------------"

echo " "
echo "------------ V-259086 ------------"

echo " "
echo "------------ V-259087 ------------"

echo " "
echo "------------ V-259088 ------------"

echo " "
echo "------------ V-259089 ------------"

echo " "
echo "------------ V-259090 ------------"

echo " "
echo "------------ V-259091 ------------"

echo " "
echo "------------ V-259092 ------------"

echo " "
echo "------------ V-259093 ------------"

echo " "
echo "------------ V-259094 ------------"

echo " "
echo "------------ V-259095 ------------"

echo " "
echo "------------ V-259096 ------------"

echo " "
echo "------------ V-259097 ------------"

echo " "
echo "------------ V-259098 ------------"

echo " "
echo "------------ V-259099 ------------"

echo " "
echo "------------ V-259100 ------------"

echo " "
echo "------------ V-259101 ------------"

echo " "
echo "------------ V-259102 ------------"

echo " "
echo "------------ V-259103 ------------"

echo " "
echo -------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 Photon OS 4.0 Technical Implementation Guide
echo -------------------------------------------------------------------------
echo " "
echo "------------ V-258801 ------------"

echo " "
echo "------------ V-258802 ------------"

echo " "
echo "------------ V-258803 ------------"

echo " "
echo "------------ V-258804 ------------"

echo " "
echo "------------ V-258805 ------------"

echo " "
echo "------------ V-258806 ------------"

echo " "
echo "------------ V-258807 ------------"

echo " "
echo "------------ V-258808 ------------"

echo " "
echo "------------ V-258809 ------------"

echo " "
echo "------------ V-258810 ------------"

echo " "
echo "------------ V-258811 ------------"

echo " "
echo "------------ V-258812 ------------"

echo " "
echo "------------ V-258813 ------------"

echo " "
echo "------------ V-258814 ------------"

echo " "
echo "------------ V-258815 ------------"

echo " "
echo "------------ V-258816 ------------"

echo " "
echo "------------ V-258817 ------------"

echo " "
echo "------------ V-258818 ------------"

echo " "
echo "------------ V-258819 ------------"

echo " "
echo "------------ V-258820 ------------"

echo " "
echo "------------ V-258821 ------------"

echo " "
echo "------------ V-258822 ------------"

echo " "
echo "------------ V-258823 ------------"

echo " "
echo "------------ V-258824 ------------"

echo " "
echo "------------ V-258825 ------------"

echo " "
echo "------------ V-258826 ------------"

echo " "
echo "------------ V-258827 ------------"

echo " "
echo "------------ V-258828 ------------"

echo " "
echo "------------ V-258829 ------------"

echo " "
echo "------------ V-258830 ------------"

echo " "
echo "------------ V-258831 ------------"

echo " "
echo "------------ V-258832 ------------"

echo " "
echo "------------ V-258833 ------------"

echo " "
echo "------------ V-258834 ------------"

echo " "
echo "------------ V-258835 ------------"

echo " "
echo "------------ V-258836 ------------"

echo " "
echo "------------ V-258837 ------------"

echo " "
echo "------------ V-258838 ------------"

echo " "
echo "------------ V-258839 ------------"

echo " "
echo "------------ V-258840 ------------"

echo " "
echo "------------ V-258841 ------------"

echo " "
echo "------------ V-258842 ------------"

echo " "
echo "------------ V-258843 ------------"

echo " "
echo "------------ V-258844 ------------"

echo " "
echo "------------ V-258845 ------------"

echo " "
echo "------------ V-258846 ------------"

echo " "
echo "------------ V-258847 ------------"

echo " "
echo "------------ V-258848 ------------"

echo " "
echo "------------ V-258849 ------------"

echo " "
echo "------------ V-258850 ------------"

echo " "
echo "------------ V-258851 ------------"

echo " "
echo "------------ V-258852 ------------"

echo " "
echo "------------ V-258853 ------------"

echo " "
echo "------------ V-258854 ------------"

echo " "
echo "------------ V-258855 ------------"

echo " "
echo "------------ V-258856 ------------"

echo " "
echo "------------ V-258857 ------------"

echo " "
echo "------------ V-258858 ------------"

echo " "
echo "------------ V-258859 ------------"

echo " "
echo "------------ V-258860 ------------"

echo " "
echo "------------ V-258861 ------------"

echo " "
echo "------------ V-258862 ------------"

echo " "
echo "------------ V-258863 ------------"

echo " "
echo "------------ V-258864 ------------"

echo " "
echo "------------ V-258865 ------------"

echo " "
echo "------------ V-258866 ------------"

echo " "
echo "------------ V-258867 ------------"

echo " "
echo "------------ V-258868 ------------"

echo " "
echo "------------ V-258869 ------------"

echo " "
echo "------------ V-258870 ------------"

echo " "
echo "------------ V-258871 ------------"

echo " "
echo "------------ V-258872 ------------"

echo " "
echo "------------ V-258873 ------------"

echo " "
echo "------------ V-258874 ------------"

echo " "
echo "------------ V-258875 ------------"

echo " "
echo "------------ V-258876 ------------"

echo " "
echo "------------ V-258877 ------------"

echo " "
echo "------------ V-258878 ------------"

echo " "
echo "------------ V-258879 ------------"

echo " "
echo "------------ V-258880 ------------"

echo " "
echo "------------ V-258881 ------------"

echo " "
echo "------------ V-258882 ------------"

echo " "
echo "------------ V-258883 ------------"

echo " "
echo "------------ V-258884 ------------"

echo " "
echo "------------ V-258885 ------------"

echo " "
echo "------------ V-258886 ------------"

echo " "
echo "------------ V-258887 ------------"

echo " "
echo "------------ V-258888 ------------"

echo " "
echo "------------ V-258889 ------------"

echo " "
echo "------------ V-258890 ------------"

echo " "
echo "------------ V-258891 ------------"

echo " "
echo "------------ V-258892 ------------"

echo " "
echo "------------ V-258893 ------------"

echo " "
echo "------------ V-258894 ------------"

echo " "
echo "------------ V-258895 ------------"

echo " "
echo "------------ V-258896 ------------"

echo " "
echo "------------ V-258897 ------------"

echo " "
echo "------------ V-258898 ------------"

echo " "
echo "------------ V-258899 ------------"

echo " "
echo "------------ V-258900 ------------"

echo " "
echo "------------ V-258901 ------------"

echo " "
echo "------------ V-258902 ------------"

echo " "
echo "------------ V-258903 ------------"

echo " "
echo "------------ V-258904 ------------"

echo " "
echo "------------ V-266062 ------------"

echo " "
echo "------------ V-266063 ------------"

echo " "
echo ----------------------------------------------------------------------
echo ----------VMware vSphere 8.0 PostgreSQL Technical Implementation Guide
echo ----------------------------------------------------------------------
echo " "
echo "------------ V-259166 ------------"

echo " "
echo "------------ V-259167 ------------"

echo " "
echo "------------ V-259168 ------------"

echo " "
echo "------------ V-259169 ------------"

echo " "
echo "------------ V-259170 ------------"

echo " "
echo "------------ V-259171 ------------"

echo " "
echo "------------ V-259172 ------------"

echo " "
echo "------------ V-259173 ------------"

echo " "
echo "------------ V-259174 ------------"

echo " "
echo "------------ V-259175 ------------"

echo " "
echo "------------ V-259176 ------------"

echo " "
echo "------------ V-259177 ------------"

echo " "
echo "------------ V-259178 ------------"

echo " "
echo "------------ V-259179 ------------"

echo " "
echo "------------ V-259180 ------------"

echo " "
echo "------------ V-259181 ------------"

echo " "
echo "------------ V-259182 ------------"

echo " "
echo "------------ V-259183 ------------"

echo " "
echo "------------ V-259184 ------------"

echo " "
echo "------------ V-259185 ------------"

echo " "
echo --------------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 Secure Token Service Technical Implementation Guide
echo --------------------------------------------------------------------------------
echo " "
echo "------------ V-258970 ------------"

echo " "
echo "------------ V-258972 ------------"

echo " "
echo "------------ V-258973 ------------"

echo " "
echo "------------ V-258974 ------------"

echo " "
echo "------------ V-258975 ------------"

echo " "
echo "------------ V-258976 ------------"

echo " "
echo "------------ V-258977 ------------"

echo " "
echo "------------ V-258978 ------------"

echo " "
echo "------------ V-258979 ------------"

echo " "
echo "------------ V-258980 ------------"

echo " "
echo "------------ V-258981 ------------"

echo " "
echo "------------ V-258982 ------------"

echo " "
echo "------------ V-258983 ------------"

echo " "
echo "------------ V-258984 ------------"

echo " "
echo "------------ V-258985 ------------"

echo " "
echo "------------ V-258986 ------------"

echo " "
echo "------------ V-258987 ------------"

echo " "
echo "------------ V-258988 ------------"

echo " "
echo "------------ V-258989 ------------"

echo " "
echo "------------ V-258990 ------------"

echo " "
echo "------------ V-258991 ------------"

echo " "
echo "------------ V-258992 ------------"

echo " "
echo "------------ V-258993 ------------"

echo " "
echo "------------ V-258994 ------------"

echo " "
echo "------------ V-258995 ------------"

echo " "
echo "------------ V-258996 ------------"

echo " "
echo "------------ V-258997 ------------"

echo " "
echo "------------ V-258998 ------------"

echo " "
echo "------------ V-258999 ------------"

echo " "
echo "------------ V-259000 ------------"

echo " "
echo "------------ V-259001 ------------"

echo " "
echo "------------ V-259002 ------------"

echo " "
echo "------------ V-266136 ------------"

echo " "
echo --------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 User Interface Technical Implementation Guide
echo --------------------------------------------------------------------------
echo " "
echo "------------ V-259104 ------------"

echo " "
echo "------------ V-259105 ------------"

echo " "
echo "------------ V-259106 ------------"

echo " "
echo "------------ V-259107 ------------"

echo " "
echo "------------ V-259108 ------------"

echo " "
echo "------------ V-259109 ------------"

echo " "
echo "------------ V-259110 ------------"

echo " "
echo "------------ V-259111 ------------"

echo " "
echo "------------ V-259112 ------------"

echo " "
echo "------------ V-259113 ------------"

echo " "
echo "------------ V-259114 ------------"

echo " "
echo "------------ V-259115 ------------"

echo " "
echo "------------ V-259116 ------------"

echo " "
echo "------------ V-259117 ------------"

echo " "
echo "------------ V-259118 ------------"

echo " "
echo "------------ V-259119 ------------"

echo " "
echo "------------ V-259120 ------------"

echo " "
echo "------------ V-259121 ------------"

echo " "
echo "------------ V-259122 ------------"

echo " "
echo "------------ V-259123 ------------"

echo " "
echo "------------ V-259124 ------------"

echo " "
echo "------------ V-259125 ------------"

echo " "
echo "------------ V-259126 ------------"

echo " "
echo "------------ V-259127 ------------"

echo " "
echo "------------ V-259128 ------------"

echo " "
echo "------------ V-259129 ------------"

echo " "
echo "------------ V-259130 ------------"

echo " "
echo "------------ V-259131 ------------"

echo " "
echo "------------ V-259132 ------------"

echo " "
echo "------------ V-259133 ------------"

echo " "
echo "------------ V-259134 ------------"

echo " "
echo "------------ V-259135 ------------"

echo " "
echo "------------ V-259136 ------------"

echo " "
echo ----------------------------------------------------------------
echo ----------VMware vSphere 8.0 VAMI Technical Implementation Guide
echo ----------------------------------------------------------------
echo " "
echo "------------ V-259137 ------------"

echo " "
echo "------------ V-259138 ------------"

echo " "
echo "------------ V-259139 ------------"

echo " "
echo "------------ V-259140 ------------"

echo " "
echo "------------ V-259141 ------------"

echo " "
echo "------------ V-259142 ------------"

echo " "
echo "------------ V-259143 ------------"

echo " "
echo "------------ V-259144 ------------"

echo " "
echo "------------ V-259145 ------------"

echo " "
echo "------------ V-259146 ------------"

echo " "
echo "------------ V-259147 ------------"

echo " "
echo "------------ V-259149 ------------"

echo " "
echo "------------ V-259150 ------------"

echo " "
echo "------------ V-259151 ------------"

echo " "
echo "------------ V-259152 ------------"

echo " "
echo "------------ V-259153 ------------"

echo " "
echo "------------ V-259155 ------------"

echo " "
echo "------------ V-259156 ------------"

echo " "
echo "------------ V-259157 ------------"

echo " "
echo "------------ V-259158 ------------"

echo " "
echo "------------ V-259159 ------------"

echo " "
echo "------------ V-259160 ------------"

echo " "