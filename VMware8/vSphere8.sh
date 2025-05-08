#!/bin/bash

#****************************************************************
#*************Written By Mitchell Gibson USACPB CRIA*************
#************Last Updated April 28, 2025 v1.0********************
#****************************************************************

clear

#Get Host Information
hostname_var=$(hostname)
ip_address=$(ip -o -4 addr show dev eth0 | awk '{print $4}' | cut -d '/' -f 1)
mac_address=$(ip -o link show dev eth0 | awk '{print $17}')
domain=$(dnsdomainname)

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
echo " Other checks are performed via the GUI"
echo " "
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
    
fi
echo " "
echo "------------ V-259006 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
check_elements() {
  local input_string="$1"
  local elements=("%h" "%{X-Forwarded-For}i" "%l" "%t" "%u" "&quot;%r&quot;" "%s" "%b")
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
pattern="%h %{X-Forwarded-For}i %l %u %t [%I] &quot;%r&quot; %s %b [Processing time %D msec] &quot;%{User-Agent}i&quot;"
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
    
fi
echo " "
echo "------------ V-259008 ------------"
check=$(xmllint --xpath '/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]' /usr/lib/vmware-eam/web/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
<Listener className="org.apache.catalina.security.SecurityListener"/>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    umask_value=$(xmllint --xpath 'string(/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]/@minimumUmask)' /usr/lib/vmware-lookupsvc/conf/server.xml)
    if [ -z "$umask_value" ]; then
        echo -e "\e[32mNot a Finding\e[0m"
    elif [ "$umask_value" != "0007" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
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
    
elif [ "$esx_safe" = "$esx_safe_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_safe
    
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
    
    echo "Element is not defined"
elif [ "$esx_showserver" = "$esx_showserver_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_showserver
    
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
    
    echo "Session timeout is missing"
elif [ "$esx_showserver" = "$esx_showserver_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_showserver
    
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
    
    echo "No results found"
elif [ "$esx_servlet_comply" = "$esx_servlet_comply_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_servlet_comply
    
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
    
fi
echo " "
echo "------------ V-259022 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'DefaultServlet')]/parent::*" /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"readOnly"* ]]; then
    if [[ "$check" == *"false"* ]]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
         
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259023 ------------"
check=$(xmllint --xpath "//Server/@port" /usr/lib/vmware-eam/web/conf/server.xml)
check2=$(grep 'base.shutdown.port' /etc/vmware-eam/catalina.properties)
check_output1=$(cat << EOF
port="\${base.shutdown.port}"
EOF
)
check_output2=$(cat << EOF
base.shutdown.port=-1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output1" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
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
    
fi
echo " "
echo "------------ V-259030 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/ROOT)
check_output=$(cat << EOF
total 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
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
        echo -e "\e[32mNot a Finding\e[0m"
    elif [ "$umask_value" != "0007" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
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
    
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
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
    
fi
echo " "
echo "------------ V-259048 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-lookupsvc/conf/server.xml)
check_output=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>
EOF
)
check_output2=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false"/>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
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
    
else
    timeout=$(echo "$check" | sed -n 's:.*<session-timeout>\([0-9]\+\)</session-timeout>.*:\1:p')
    if [[ -n "$timeout" ]]; then 
        if (( timeout <= 30 )); then
            echo -e "\e[32mNot a Finding\e[0m"
        fi
    else
        echo -e "\e[31mOpen\e[0m"
        echo $check
        
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
    
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
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
elif [[ "$check" == *"readOnly"* ]]; then
    if [[ "$check" == *"false"* ]]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
         
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259057 ------------"
check=$(xmllint --xpath "//Server/@port" /usr/lib/vmware-lookupsvc/conf/server.xml)
check2=$(grep 'base.shutdown.port' /usr/lib/vmware-lookupsvc/conf/catalina.properties)
check_output1=$(cat << EOF
port="\${base.shutdown.port}"
EOF
)
check_output2=$(cat << EOF
base.shutdown.port=-1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output1" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
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
    
fi
echo " "
echo "------------ V-259059 ------------"
check=$(xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' - 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
     
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
    
fi
echo " "
echo "------------ V-259062 ------------"
check=$(xmllint --xpath "//Connector/@xpoweredBy" /usr/lib/vmware-lookupsvc/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"true"* ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
     
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
    
fi
echo " "
echo "------------ V-259064 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/ROOT)
check_output=$(cat << EOF
total 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
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
    
fi
echo " "
echo "------------ V-259073 ------------"
check=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/perfcharts.json)
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
        echo -e "\e[32mNot a Finding\e[0m"
    elif [ "$umask_value" != "0007" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
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
    
fi
echo " "
echo "------------ V-259081 ------------"
check=$(xmllint --xpath "//Connector[@URIEncoding != 'UTF-8'] | //Connector[not[@URIEncoding]]" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259082 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259083 ------------"
check=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/session-timeout' - 2>/dev/null)
check_output=$(cat << EOF
<session-timeout>6</session-timeout>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
timeout=$(echo "$check" | sed -n 's:.*<session-timeout>\([0-9]\+\)</session-timeout>.*:\1:p')
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ -n "$timeout" ]]; then
  if (( timeout < 30 )); then
    echo -e "\e[32mNot a Finding\e[0m"
  else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
  fi
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259084 ------------"
check=$(cat /etc/vmware-syslog/vmware-services-perfcharts.conf 2>/dev/null)
check_output=$(cat << EOF
#stats
input(type="imfile"
      File="/var/log/vmware/perfcharts/stats.log"
      Tag="perfcharts-stats"
      Severity="info"
      Facility="local0")
#localhost_access_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/localhost_access_log.txt"
      Tag="perfcharts-localhost_access"
      Severity="info"
      Facility="local0")
#vmware-perfcharts-gc.log
input(type="imfile"
      File="/var/log/vmware/perfcharts/vmware-perfcharts-gc.log.*.current"
      Tag="perfcharts-gc"
      Severity="info"
      Facility="local0")
#vmware-perfcharts-runtime.log
input(type="imfile"
      File="/var/log/vmware/perfcharts/vmware-perfcharts-runtime.log.std*"
      Tag="perfcharts-runtime"
      Severity="info"
      Facility="local0")
#tomcat/catalina_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/tomcat/catalina.*.log"
      Tag="perfcharts-tomcat-catalina"
      Severity="info"
      Facility="local0")
#tomcat/localhost_log
input(type="imfile"
      File="/var/log/vmware/perfcharts/tomcat/localhost.*.log"
      Tag="perfcharts-tomcat-localhost"
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
    
fi
echo " "
echo "------------ V-259085 ------------"
check=$(grep STRICT_SERVLET_COMPLIANCE /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.STRICT_SERVLET_COMPLIANCE=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259086 ------------"
check=$(xmllint --xpath "//Connector[@connectionTimeout = '-1']" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259087 ------------"
check=$(xmllint --xpath "//Connector[@maxKeepAliveRequests = '-1']" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259088 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'setCharacterEncodingFilter')]/parent::*" /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml 2>/dev/null)
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
check_output2=$(cat << EOF
<filter>
      <filter-name>setCharacterEncodingFilter</filter-name>
      <filter-class>
         org.apache.catalina.filters.SetCharacterEncodingFilter
      </filter-class>
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
<filter-mapping>
      <filter-name>setCharacterEncodingFilter</filter-name>
      <url-pattern>/*</url-pattern>
   </filter-mapping>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo "------------ V-259089 ------------"
check=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' - 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259090 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'DefaultServlet')]/parent::*" /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml 2>/dev/null)
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
if [[ "$check" == *"readOnly"* ]]; then
    if [[ "$check" == *"false"* ]]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
         
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259091 ------------"
check=$(xmllint --xpath "//Server/@port" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check2=$(grep 'base.shutdown.port' /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
port="\${base.shutdown.port}"
EOF
)
check_output2=$(cat << EOF
base.shutdown.port=-1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-259092 ------------"
check=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="debug"]/parent::init-param' - 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259093 ------------"
check=$(xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' - 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m" 
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259094 ------------"
check=$(xmllint --xpath "//Host/@deployXML" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259095 ------------"
check=$(xmllint --xpath "//Host/@autoDeploy" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259096 ------------"
check=$(xmllint --xpath "//Connector/@xpoweredBy" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m" 
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259097 ------------"
check=$(ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/examples 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259098 ------------"
check=$(ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/docs 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259099 ------------"
check=$(find /usr/lib/vmware-perfcharts/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259100 ------------"
check=$(grep ALLOW_BACKSLASH /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259101 ------------"
check=$(grep ENFORCE_ENCODING_IN_GET_WRITER /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259102 ------------"
check=$(ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259103 ------------"
check=$(ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/host-manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo -------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 Photon OS 4.0 Technical Implementation Guide
echo -------------------------------------------------------------------------
echo " "
echo "------------ V-258801 ------------"
check=$(auditctl -l | grep -E "(useradd|groupadd)" 2>/dev/null)
check_output=$(cat << EOF
-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258802 ------------"
check=$(grep '^deny =' /etc/security/faillock.conf 2>/dev/null)
check2=$(grep '^fail_interval =' /etc/security/faillock.conf 2>/dev/null)
check_output=$(cat << EOF
deny = 3
EOF
)
check_outputa=$(cat << EOF
deny = 2
EOF
)
check_outputb=$(cat << EOF
deny = 1
EOF
)
check_output2=$(cat << EOF
fail_interval = 900
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_outputa=$( echo "$check_outputa" | awk '{$1=$1};1' )
check_outputb=$( echo "$check_outputb" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_outputa" ] || [ "$check" = "$check_outputb" ]; then
    if [ "$check2" = "$check_output2" ]; then
        echo -e "\e[32mNot a Finding\e[0m"
    else
        echo -e "\e[31mOpen\e[0m"
        echo $check
        echo $check2
        
    fi 
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-258803 ------------"
check=$(sshd -T|&grep -i Banner 2>/dev/null)
check2=$(cat /etc/issue 2>/dev/null)
check_output=$(cat << EOF
banner /etc/issue
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] && [[ "$check2" == *"You are accessing a U.S"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-258804 ------------"
check=$(grep "^[^#].*maxlogins.*" /etc/security/limits.conf 2>/dev/null)
check_output=$(cat << EOF
*       hard    maxlogins       10
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258805 ------------"
check=$(grep -E "(^auth.*|^authpriv.*|^daemon.*)" /etc/rsyslog.conf 2>/dev/null)
check_output=$(cat << EOF
auth.*;authpriv.*;daemon.* /var/log/audit/sshinfo.log
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$check" == "auth.*;authpriv.*;daemon.*"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258806 ------------"
check=$(rpm -qa | grep openssl-fips 2>/dev/null)
check_output=$(cat << EOF
openssl-fips-provider-3.0.3-1.ph4.x86_64
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$check" == "openssl-fips-provider"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258807 ------------"
check=$(grep '^write_logs' /etc/audit/auditd.conf 2>/dev/null)
check_output=$(cat << EOF
write_logs = yes
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
    
fi
echo " "
echo "------------ V-258808 ------------"
check=$(systemctl is-enabled auditd 2>/dev/null)
check2=$(systemctl is-active auditd 2>/dev/null)
check_output=$(cat << EOF
enabled
EOF
)
check_output2=$(cat << EOF
active
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-258809 ------------"
check=$(auditctl -l | grep execve 2>/dev/null)
check_output=$(cat << EOF
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258810 ------------"
check=$(grep -E "^disk_full_action|^disk_error_action|^admin_space_left_action" /etc/audit/auditd.conf 2>/dev/null)
check_output=$(cat << EOF
admin_space_left_action = SYSLOG
disk_full_action = SYSLOG
disk_error_action = SYSLOG
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258811 ------------"
check=$(grep -iw log_file /etc/audit/auditd.conf 2>/dev/null)
log_path=$(echo "$check" | awk -F '=' '{gsub(/ /,"",$2); print $2}')
if [ -z "$log_path" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "Log path not found."
    
else
    check2=$(stat -c "%n %U:%G %a" "$log_path" 2>/dev/null)
    owner=$(echo "$check2" | awk '{split($2,a,":"); print a[1]}')
    group=$(echo "$check2" | awk '{split($2,a,":"); print a[2]}')
    permissions=$(echo "$check2" | awk '{print $3}')
    check=$( echo "$check" | awk '{$1=$1};1' )

    if [[ "$owner" == "root" && "$group" == "root" && "$permissions" == 600 ]]; then
        echo -e "\e[32mNot a Finding\e[0m"
    else
        echo -e "\e[31mOpen\e[0m"
        echo "Owner: $owner, Group: $group, Permissions: $permissions"
        
    fi
fi
echo " "
echo "------------ V-258812 ------------"
audit_dir="/etc/audit"
open_files=()
check_file_status() {
    local file="$1"
    local owner="$2"
    local group="$3"
    local perms="$4"
    local has_issues=false
    if [[ "$owner" != "root" ]] || [[ "$group" != "root" ]]; then
        echo "  - $file: Incorrect ownership ($owner:$group)"
        has_issues=true
    fi
    if (( 10#$perms > 640 )); then
        echo "  - $file: Permissions are too permissive ($perms)"
        has_issues=true
    fi
    if $has_issues; then
        open_files+=("$file")
    fi
}

find "$audit_dir" -type f -print0 | while IFS= read -r -d $'\0' file; do
    stat_output=$(stat -c "%U:%G %a" "$file" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Error getting status for $file"
        continue 
    fi
    owner=$(echo "$stat_output" | cut -d ":" -f 1)
    group=$(echo "$stat_output" | cut -d ":" -f 2 | cut -d " " -f 1)
    perms=$(echo "$stat_output" | cut -d " " -f 2)
    check_file_status "$file" "$owner" "$group" "$perms"
done

if [ ${#open_files[@]} -gt 0 ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "The following files have security issues:"
    for file in "${open_files[@]}"; do
        stat -c "%n %U:%G %a" "$file"
    done
    =$(( + 1))
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-258813 ------------"
check=$(auditctl -l | grep chmod 2>/dev/null)
check_output=$(cat << EOF
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod
EOF
)
check_output2=$(cat << EOF
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod
EOF
)
check_output3=$(cat << EOF
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
check_output3=$( echo "$check_output3" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ] || [ "$check" = "$check_output3" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258814 ------------"
check=$(grep '^password.*pam_pwquality.so' /etc/pam.d/system-password 2>/dev/null)
ucredit=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^ucredit=/) {split($i, a, "="); print a[2]}}')
ucredit=$( echo "$ucredit" | awk '{$1=$1};1' )
if [[ "$ucredit" =~ ^-?[0-9]+$ ]] && [[ "$ucredit" -lt 0 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258815 ------------"
check=$(grep '^password.*pam_pwquality.so' /etc/pam.d/system-password 2>/dev/null)
lcredit=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^lcredit=/) {split($i, a, "="); print a[2]}}')
lcredit=$( echo "$lcredit" | awk '{$1=$1};1' )
if [[ "$lcredit" =~ ^-?[0-9]+$ ]] && [[ "$lcredit" -lt 0 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258816 ------------"
check=$(grep '^password.*pam_pwquality.so' /etc/pam.d/system-password 2>/dev/null)
dcredit=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^dcredit=/) {split($i, a, "="); print a[2]}}')
dcredit=$( echo "$dcredit" | awk '{$1=$1};1' )
if [[ "$dcredit" =~ ^-?[0-9]+$ ]] && [[ "$dcredit" -lt 0 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258817 ------------"
check=$(grep '^password.*pam_pwquality.so' /etc/pam.d/system-password 2>/dev/null)
difok=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^difok=/) {split($i, a, "="); print a[2]}}')
difok=$( echo "$difok" | awk '{$1=$1};1' )
if [[ "$difok" =~ ^-?[0-9]+$ ]] && [[ "$difok" -ge 8 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258818 ------------"
check=$(grep ^ENCRYPT_METHOD /etc/login.defs 2>/dev/null)
check_output=$(cat << EOF
ENCRYPT_METHOD SHA512
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258819 ------------"
check=$(rpm -qa | grep telnet 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258820 ------------"
check=$(grep '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null)
check_output=$(cat << EOF
PASS_MIN_DAYS   1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258821 ------------"
check=$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null)
check_output=$(cat << EOF
PASS_MAX_DAYS   90
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258822 ------------"
check=$(grep '^password.*pam_pwhistory.so' /etc/pam.d/system-password 2>/dev/null)
remember=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^remember=/) {split($i, a, "="); print a[2]}}')
remember=$( echo "$remember" | awk '{$1=$1};1' )
if [[ "$remember" =~ ^-?[0-9]+$ ]] && [[ "$remember" -ge 5 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258823 ------------"
check=$(grep '^password.*pam_pwquality.so' /etc/pam.d/system-password 2>/dev/null)
minlen=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^minlen=/) {split($i, a, "="); print a[2]}}')
minlen=$( echo "$minlen" | awk '{$1=$1};1' )
if [[ "$minlen" =~ ^-?[0-9]+$ ]] && [[ "$minlen" -ge 15 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258824 ------------"
check=$(grep -E "^set\s+superusers|^password_pbkdf2" /boot/grub2/grub.cfg 2>/dev/null)
check=$(echo "$check" | awk '{$1=$1};1')
superuser=$(echo "$check" | grep '^set\s\+superusers' | awk -F'"' '{print $2}')
password_line=$(echo "$check" | grep '^password_pbkdf2')
if [[ -z "$superuser" ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
elif [[ -z "$password_line" ]] || ! echo "$password_line" | grep -q "$superuser"; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-258825 ------------"
check=$(modprobe --showconfig | grep "^install" | grep "/bin" 2>/dev/null)
check_output=$(cat << EOF
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
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [[ "$check" == *"$check_output"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258826 ------------"
check=$(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258827 ------------"
check=$(grep 'pam_unix.so' /etc/pam.d/system-password 2>/dev/null)
check=$(echo "$check" | awk '{$1=$1};1')
if echo "$check" | grep -q 'sha512'; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258828 ------------"
check=$(/sbin/sysctl kernel.dmesg_restrict 2>/dev/null)
check_output=$(cat << EOF
kernel.dmesg_restrict = 1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258829 ------------"
check=$(/sbin/sysctl net.ipv4.tcp_syncookies 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.tcp_syncookies = 1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258830 ------------"
check=$(sshd -T|&grep -i ClientAliveInterval 2>/dev/null)
check_output=$(cat << EOF
ClientAliveInterval 900
EOF
)
check_output2=$(cat << EOF
clientaliveinterval 900
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258831 ------------"
check=$(stat -c "%n is owned by %U and group owned by %G with permissions of %a" /var/log 2>/dev/null)
check_output=$(cat << EOF
/var/log is owned by root and group owned by root with permissions of 755
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo "Check permissions"
    
fi
echo " "
echo "------------ V-258832 ------------"
umask_value=$(grep '^\$umask' /etc/rsyslog.conf | awk '{print $2}')
if [[ -z "$umask_value" ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $umask_value
    
else
    umask_value=$((8#$umask_value))
    min_restrictive=$((8#0037))
    if [[ $umask_value -ge $min_restrictive ]]; then
        echo -e "\e[32mNot a Finding\e[0m"
    else
        echo -e "\e[31mOpen\e[0m"
        echo $umask_value
        
    fi
fi
echo " "
echo "------------ V-258833 ------------"
check=$(auditctl -l | grep -E "(usermod|groupmod)" 2>/dev/null)
check_output=$(cat << EOF
-w /usr/sbin/usermod -p x -k usermod
-w /usr/sbin/groupmod -p x -k groupmod
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258834 ------------"
check=$(auditctl -l | grep -E "(userdel|groupdel)" 2>/dev/null)
check_output=$(cat << EOF
-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258835 ------------"
check=$(sshd -T|&grep -i Ciphers)
check_output=$(cat << EOF
ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
EOF
)
check_output_2=$(cat << EOF
ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com
EOF
)
check_output_3=$(cat << EOF
ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com
EOF
)
check_output_4=$(cat << EOF
ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output_2=$( echo "$check_output_2" | awk '{$1=$1};1' )
check_output_3=$( echo "$check_output_3" | awk '{$1=$1};1' )
check_output_4=$( echo "$check_4" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output_2" ] || [ "$check" = "$check_output_3" ] || [ "$check" = "$check_output_4" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
fi
echo " "
echo "------------ V-258836 ------------"
check=$(grep 'audit' /proc/cmdline 2>/dev/null)
audit=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^audit=/) {split($i, a, "="); print a[2]}}')
audit=$( echo "$audit" | awk '{$1=$1};1' )
if [[ "$audit" =~ ^-?[0-9]+$ ]] && [[ "$audit" -eq 1 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258837 ------------"
check=$(stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/audispd /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace /usr/sbin/augenrules 2>/dev/null)
check_output=$(cat << EOF
/usr/sbin/audispd is owned by root and group owned by root and permissions are 750
/usr/sbin/auditctl is owned by root and group owned by root and permissions are 755
/usr/sbin/auditd is owned by root and group owned by root and permissions are 755
/usr/sbin/aureport is owned by root and group owned by root and permissions are 755
/usr/sbin/ausearch is owned by root and group owned by root and permissions are 755
/usr/sbin/autrace is owned by root and group owned by root and permissions are 755
/usr/sbin/augenrules is owned by root and group owned by root and permissions are 750
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo "Check permissions"
    
fi
echo " "
echo "------------ V-258838 ------------"
check=$(grep '^password.*pam_pwquality.so' /etc/pam.d/system-password 2>/dev/null)
ocredit=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^ocredit=/) {split($i, a, "="); print a[2]}}')
ocredit=$( echo "$ocredit" | awk '{$1=$1};1' )
if [[ "$ocredit" =~ ^-?[0-9]+$ ]] && [[ "$ocredit" -lt 0 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258839 ------------"
check=$(rpm -V audit | grep "^..5" | grep -v '\.conf$' 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258840 ------------"
check=$(grep -E "TMOUT=900" /etc/bash.bashrc /etc/profile.d/* 2>/dev/null)
check_output=$(cat << EOF
/etc/profile.d/tmout.sh:TMOUT=900
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258841 ------------"
check=$(/sbin/sysctl fs.protected_symlinks 2>/dev/null)
check_output=$(cat << EOF
fs.protected_symlinks = 1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258842 ------------"
finding=0
while IFS= read -r file; do
  if ! auditctl -l | grep -qw -- "$file"; then
    finding=1
    break
  fi
done < <(find / -xdev \
  -path /var/lib/containerd -prune -o \
  -path /var/lib/docker -prune -o \
  \( -perm -4000 -o -perm -2000 \) -type f -print | sort)
if [ "$finding" -eq 1 ]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-258843 ------------"
check=$(grep '^unlock_time =' /etc/security/faillock.conf 2>/dev/null)
check_output=$(cat << EOF
unlock_time = 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258844 ------------"
check=$(grep -E "^num_logs|^max_log_file_action" /etc/audit/auditd.conf 2>/dev/null)
check_output=$(cat << EOF
num_logs = 5
max_log_file_action = ROTATE
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258845 ------------"
check=$(grep '^space_left' /etc/audit/auditd.conf 2>/dev/null)
check_output=$(cat << EOF
space_left = 25%
space_left_action = SYSLOG
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258846 ------------"
check=$(grep '^gpgcheck' /etc/tdnf/tdnf.conf 2>/dev/null)
check_output=$(cat << EOF
gpgcheck=1
EOF
)
check_output2=$(cat << EOF
gpgcheck=true
EOF
)
check_output3=$(cat << EOF
gpgcheck=yes
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
check_output3=$( echo "$check_output3" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ] || [ "$check" = "$check_output3" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258847 ------------"
_1=$(grep -ihs nopasswd /etc/sudoers /etc/sudoers.d/* | grep -v "^#" | grep -v "^%" | awk '{print $1}')
_2=$(awk -F: '($2 != "x" && $2 != "!") {print $1}' /etc/shadow)
_check=false

for user in $_1; do
    if [[ " $_2 " == *" $user "* ]]; then
        _check=true
    fi
done

if [ "$_check" = true ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "$_1"
    echo "$_2"
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-258848 ------------"
check=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
check_output=$(cat << EOF
2
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258849 ------------"
check=$(grep -i '^clean_requirements_on_remove' /etc/tdnf/tdnf.conf 2>/dev/null)
check_output=$(cat << EOF
clean_requirements_on_remove=1
EOF
)
check_output2=$(cat << EOF
clean_requirements_on_remove=true
EOF
)
check_output3=$(cat << EOF
clean_requirements_on_remove=yes
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
check_output3=$( echo "$check_output3" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ] || [ "$check" = "$check_output3" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258850 ------------"
check=$(auditctl -l | grep -E "faillog|lastlog|tallylog" 2>/dev/null)
check_output=$(cat << EOF
-w /var/log/faillog -p wa -k logons
-w /var/log/lastlog -p wa -k logons
-w /var/log/tallylog -p wa -k logons
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258851 ------------"
check=$(auditctl -l | grep init_module 2>/dev/null)
check_output=$(cat << EOF
-a always,exit -F arch=b32 -S init_module -F key=modules
-a always,exit -F arch=b64 -S init_module -F key=modules
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258852 ------------"
check=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)
check_output=$(cat << EOF
1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258853 ------------"
check=$(grep '^password.*pam_pwquality.so' /etc/pam.d/system-password 2>/dev/null)
dictcheck=$(echo "$check" | awk '{for (i=1; i<=NF; i++) if ($i ~ /^dictcheck=/) {split($i, a, "="); print a[2]}}')
dictcheck=$( echo "$dictcheck" | awk '{$1=$1};1' )
if [[ "$dictcheck" =~ ^-?[0-9]+$ ]] && [[ "$dictcheck" == 1 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258854 ------------"
check=$(grep '^FAIL_DELAY' /etc/login.defs 2>/dev/null)
check_output=$(cat << EOF
FAIL_DELAY 4
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258855 ------------"
check=$(grep -E "freq|flush" /etc/audit/auditd.conf 2>/dev/null)
check_output=$(cat << EOF
flush = INCREMENTAL_ASYNC
freq = 50
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258856 ------------"
check=$(grep '^UMASK' /etc/login.defs 2>/dev/null)
check_output=$(cat << EOF
UMASK 077
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258857 ------------"
check=$(sshd -T|&grep -i HostbasedAuthentication 2>/dev/null)
check_output=$(cat << EOF
hostbasedauthentication no
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258858 ------------"
check=$(grep '^auth' /etc/pam.d/system-auth 2>/dev/null)
check_output=$(cat << EOF
auth required pam_faillock.so preauth
auth required pam_unix.so
auth required pam_faillock.so authfail
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check2=$(grep '^ac' /etc/pam.d/system-ac 2>/dev/null)
check_output2=$(cat << EOF
ac required pam_faillock.so
ac required pam_unix.so
EOF
)
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258859 ------------"
check=$(grep '^silent' /etc/security/faillock.conf 2>/dev/null)
check_output=$(cat << EOF
silent
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258860 ------------"
check=$(grep '^audit' /etc/security/faillock.conf 2>/dev/null)
check_output=$(cat << EOF
audit
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258861 ------------"
check=$(grep '^even_deny_root' /etc/security/faillock.conf 2>/dev/null)
check_output=$(cat << EOF
even_deny_root
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258862 ------------"
check=$(grep '^dir' /etc/security/faillock.conf 2>/dev/null)
check_output=$(cat << EOF
dir = /var/log/faillock
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258863 ------------"
check=$(grep '^password' /etc/pam.d/system-password 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"pam_pwquality.so"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258864 ------------"
check=($(grep gpgcheck /etc/yum.repos.d/* | awk -F 'gpgcheck=' '{print $2}'))
check_check=false
for num in "${check[@]}"; do
    if [[ "$num" != 1 ]]; then
        check_check=true
        break
    fi
done
if $check_check; then
    echo -e "\e[31mOpen\e[0m"
    echo $(grep gpgcheck /etc/yum.repos.d/*)
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-258865 ------------"
check=$(sshd -T|&grep -i SyslogFacility 2>/dev/null)
check_output=$(cat << EOF
syslogfacility AUTHPRIV
EOF
)
check_output2=$(cat << EOF
syslogfacility AUTH
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258866 ------------"
check=$(sshd -T|&grep -i LogLevel 2>/dev/null)
check_output=$(cat << EOF
loglevel INFO
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258867 ------------"
check=$(sshd -T|&grep -i ClientAliveMax 2>/dev/null)
check_output=$(cat << EOF
clientalivemax 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258868 ------------"
check=$(auditctl -l | grep -E "(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)" 2>/dev/null)
check_output=$(cat << EOF
-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/group -p wa -k group
-w /etc/gshadow -p wa -k gshadow
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258869 ------------"
check=$(grep '^auth' /etc/pam.d/system-auth 2>/dev/null)
check_output=$(cat << EOF
auth required pam_faillock.so preauth
auth required pam_unix.so
auth required pam_faillock.so authfail
auth optional pam_faildelay.so delay=4000000
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258870 ------------"
check=$(sshd -T|&grep -i PermitEmptyPasswords 2>/dev/null)
check_output=$(cat << EOF
permitemptypasswords no
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258871 ------------"
check=$(sshd -T|&grep -i PermitUserEnvironment 2>/dev/null)
check_output=$(cat << EOF
permituserenvironment no
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258872 ------------"
check=$(grep '^CREATE_HOME' /etc/login.defs 2>/dev/null)
check_output=$(cat << EOF
CREATE_HOME yes
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258873 ------------"
check=$(systemctl is-enabled debug-shell.service 2>/dev/null)
check2=$(systemctl is-active debug-shell.service 2>/dev/null)
check_output=$(cat << EOF
disabled
EOF
)
check_output2=$(cat << EOF
inactive
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-258874 ------------"
check=$(sshd -T|&grep -i GSSAPIAuthentication 2>/dev/null)
check_output=$(cat << EOF
gssapiauthentication no
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258875 ------------"
check=$(sshd -T|&grep -i X11Forwarding 2>/dev/null)
check_output=$(cat << EOF
x11forwarding no
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258876 ------------"
check=$(sshd -T|&grep -i StrictModes 2>/dev/null)
check_output=$(cat << EOF
strictmodes yes
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258877 ------------"
check=$(sshd -T|&grep -i KerberosAuthentication 2>/dev/null)
check_output=$(cat << EOF
kerberosauthentication no
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258878 ------------"
check=$(sshd -T|&grep -i Compression 2>/dev/null)
check_output=$(cat << EOF
compression no
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258879 ------------"
check=$(sshd -T|&grep -i PrintLastLog 2>/dev/null)
check_output=$(cat << EOF
printlastlog yes
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258880 ------------"
check=$(sshd -T|&grep -i IgnoreRhosts 2>/dev/null)
check_output=$(cat << EOF
ignorerhosts yes
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258881 ------------"
check=$(sshd -T|&grep -i IgnoreUserKnownHosts 2>/dev/null)
check_output=$(cat << EOF
ignoreuserknownhosts yes
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258882 ------------"
check=$(sshd -T|&grep -i MaxAuthTries 2>/dev/null)
check_output=$(cat << EOF
maxauthtries 6
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258883 ------------"
check=$(sshd -T|&grep -i AllowTcpForwarding 2>/dev/null)
check_output=$(cat << EOF
allowtcpforwarding no
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258884 ------------"
check=$(sshd -T|&grep -i LoginGraceTime 2>/dev/null)
check_output=$(cat << EOF
logingracetime 30
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258885 ------------"
check=$(systemctl status ctrl-alt-del.target --no-pager 2>/dev/null)
check2=$(systemctl is-active ctrl-alt-del.target 2>/dev/null)
check_output2=$(cat << EOF
inactive
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [[ "$check" == *"masked"* ]] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-258886 ------------"
check=$(/sbin/sysctl -a --pattern "net.ipv[4|6].conf.(all|default).accept_source_route" 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258887 ------------"
check=$(/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258888 ------------"
check=$(/sbin/sysctl -a --pattern "net.ipv4.conf.(all|default).accept_redirects" 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258889 ------------"
check=$(/sbin/sysctl -a --pattern "net.ipv4.conf.(all|default).secure_redirects" 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258890 ------------"
check=$(/sbin/sysctl -a --pattern "net.ipv4.conf.(all|default).send_redirects" 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258891 ------------"
check=$(/sbin/sysctl -a --pattern "net.ipv4.conf.(all|default).log_martians" 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258892 ------------"
check=$(/sbin/sysctl -a --pattern "net.ipv4.conf.(all|default).rp_filter" 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258893 ------------"
echo "If IP forwarding is required, for example if Kubernetes is installed, this is Not Applicable, otherwise:"
check=$(/sbin/sysctl net.ipv4.ip_forward 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.ip_forward = 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258894 ------------"
check=$(/sbin/sysctl net.ipv4.tcp_timestamps 2>/dev/null)
check_output=$(cat << EOF
net.ipv4.tcp_timestamps = 1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258895 ------------"
check=$(stat -c "%n permissions are %a and owned by %U:%G" /etc/ssh/*key.pub 2>/dev/null)
check_output=$(cat << EOF
/etc/ssh/ssh_host_dsa_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_ecdsa_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_ed25519_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_rsa_key.pub permissions are 644 and owned by root:root
EOF
)
check_output2=$(cat << EOF
/etc/ssh/ssh_host_ecdsa_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_ed25519_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_rsa_key.pub permissions are 644 and owned by root:root
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258896 ------------"
check=$(stat -c "%n permissions are %a and owned by %U:%G" /etc/ssh/*key 2>/dev/null)
check_output=$(cat << EOF
/etc/ssh/ssh_host_dsa_key permissions are 600 and owned by root:root
/etc/ssh/ssh_host_ecdsa_key permissions are 600 and owned by root:root
/etc/ssh/ssh_host_ed25519_key permissions are 600 and owned by root:root
/etc/ssh/ssh_host_rsa_key permissions are 600 and owned by root:root
EOF
)
check_output2=$(cat << EOF
/etc/ssh/ssh_host_ecdsa_key permissions are 600 and owned by root:root
/etc/ssh/ssh_host_ed25519_key permissions are 600 and owned by root:root
/etc/ssh/ssh_host_rsa_key permissions are 600 and owned by root:root
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258897 ------------"
check=$(grep '^password.*pam_pwquality.so' /etc/pam.d/system-password 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"enforce_for_root"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258898 ------------"
check=$(resolvectl status | grep '^Fallback DNS' 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258899 ------------"
check=$(auditctl -l | grep -E /etc/security/opasswd 2>/dev/null)
check_output=$(cat << EOF
-w /etc/security/opasswd -p wa -k opasswd
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258900 ------------"
check=$(sshd -T|&grep -i MACs 2>/dev/null)
check_output=$(cat << EOF
macs hmac-sha2-512,hmac-sha2-256
EOF
)
check_output2=$(cat << EOF
hmac-sha2-256,macs hmac-sha2-512
EOF
)
check_output3=$(cat << EOF
hmac-sha2-256
EOF
)
check_output4=$(cat << EOF
macs hmac-sha2-512
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
check_output3=$( echo "$check_output3" | awk '{$1=$1};1' )
check_output4=$( echo "$check_output4" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ] || [ "$check" = "$check_output3" ] || [ "$check" = "$check_output4" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258901 ------------"
check=$(systemctl is-enabled rsyslog 2>/dev/null)
check2=$(systemctl is-active rsyslog 2>/dev/null)
check_output=$(cat << EOF
enabled
EOF
)
check_output2=$(cat << EOF
active
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-258902 ------------"
check=$(grep '^password' /etc/pam.d/system-password 2>/dev/null)
check_output=$(cat << EOF
password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1
password  required    pam_pwhistory.so  remember=5 retry=3 enforce_for_root use_authtok
password  required    pam_unix.so       sha512 use_authtok shadow try_first_pass
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258903 ------------"
check=$(/sbin/sysctl fs.protected_hardlinks 2>/dev/null)
check_output=$(cat << EOF
fs.protected_hardlinks = 1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258904 ------------"
check=$(/sbin/sysctl fs.suid_dumpable 2>/dev/null)
check_output=$(cat << EOF
fs.suid_dumpable = 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-266062 ------------"
check=$(grep -v '^#' /etc/aide.conf | grep -v '^$' 2>/dev/null)
check2=$(aide --check 2>/dev/null)
check_output=$(cat << EOF
STIG = p+i+n+u+g+s+m+S
LOGS = p+n+u+g
/boot   STIG
/opt    STIG
/usr    STIG
/etc    STIG
/var/log   LOGS
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ -z "$check2" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "aide --check failed"
    
elif [[ "$check" == *"$check_output"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-266063 ------------"
check=$(grep nullok /etc/pam.d/system-password /etc/pam.d/system-auth 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo ----------------------------------------------------------------------
echo ----------VMware vSphere 8.0 PostgreSQL Technical Implementation Guide
echo ----------------------------------------------------------------------
echo " "
echo "------------ V-259166 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW max_connections;" 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[31mOpen\e[0m"
    echo "PSQL can't connect to server; Postgresql may not be installed or this setting may not be configured"
elif [[ "$ucredit" =~ ^-?[0-9]+$ ]] && [[ "$check" -ge 100 ]] && [[ "$check" -le 1000 ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
fi
echo " "
echo "------------ V-259167 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW shared_preload_libraries;" 2>/dev/null)
check_output=$(cat << EOF
health_status_worker,pg_stat_statements,pgaudit
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [[ "$check" == *"pgaudit"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259168 ------------"
check=$(find /storage/db/vpostgres/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user vpostgres -o -not -group vpgmongrp ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259169 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW pgaudit.log_catalog;" 2>/dev/null)
check2=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW pgaudit.log;" 2>/dev/null)
check3=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW pgaudit.log_parameter;" 2>/dev/null)
check4=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW pgaudit.log_statement_once;" 2>/dev/null)
check5=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW pgaudit.log_level;" 2>/dev/null)
check_output=$(cat << EOF
on
EOF
)
check_output_2=$(cat << EOF
all, -misc
EOF
)
check_output_3=$(cat << EOF
on
EOF
)
check_output_4=$(cat << EOF
off
EOF
)
check_output_5=$(cat << EOF
log
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output_2=$( echo "$check_output_2" | awk '{$1=$1};1' )
check_output_3=$( echo "$check_output_3" | awk '{$1=$1};1' )
check_output_4=$( echo "$check_output_4" | awk '{$1=$1};1' )
check_output_5=$( echo "$check_output_5" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] && [ "$check" = "$check_output_2" ] && [ "$check" = "$check_output_3" ] && [ "$check" = "$check_output_4" ] && [ "$check" = "$check_output_5" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259170 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_destination;" 2>/dev/null)
check_output=$(cat << EOF
stderr
EOF
)
check_output_2=$(cat << EOF
syslog
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output_2=$( echo "$check_output_2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259171 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_line_prefix;" 2>/dev/null)
check_elements() {
  local input_string="$1"
  local elements=(%m %c %x %d %u %r %p %l)
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
%m %c %x %d %u %r %p %l
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
    
fi
echo " "
echo "------------ V-259172 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_file_mode;" 2>/dev/null)
check_output=$(cat << EOF
0600
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259173 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "select * from pg_extension where extname != 'plpgsql'" 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259174 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW port;" 2>/dev/null)
check_output=$(cat << EOF
5432
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259175 ------------"
check=$(grep -v "^#" /storage/db/vpostgres/pg_hba.conf |grep '\S' 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$check" == *"password"* ]] || [[ "$check" == *"trust"* ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259176 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW password_encryption;" 2>/dev/null)
check_output=$(cat << EOF
scram-sha-256
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259179 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SELECT name,setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');" 2>/dev/null)
check_output=$(cat << EOF
fsync              | on
full_page_writes   | on
synchronous_commit | on
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259180 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW client_min_messages;" 2>/dev/null)
check_output=$(cat << EOF
error
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259181 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW logging_collector;" 2>/dev/null)
check_output=$(cat << EOF
on
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259182 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_timezone;" 2>/dev/null)
check_output=$(cat << EOF
UTC
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259183 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_connections;" 2>/dev/null)
check_output=$(cat << EOF
on
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259184 ------------"
check=$(/opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_disconnections;" 2>/dev/null)
check_output=$(cat << EOF
on
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259185 ------------"
check=$(cat /etc/vmware-syslog/vmware-services-vmware-vpostgres.conf 2>/dev/null)
check2=$(cat /etc/vmware-syslog/vmware-services-vmware-postgres-archiver.conf 2>/dev/null)
check_output=$(cat << EOF
# vmware-vpostgres first logs stdout, before loading configuration
input(type="imfile"
      File="/var/log/vmware/vpostgres/serverlog.stdout"
      Tag="vpostgres-first"
      Severity="info"
      Facility="local0")
# vmware-vpostgres first logs stderr, before loading configuration
input(type="imfile"
      File="/var/log/vmware/vpostgres/serverlog.stderr"
      Tag="vpostgres-first"
      Severity="info"
      Facility="local0")
# vmware-vpostgres logs
input(type="imfile"
      File="/var/log/vmware/vpostgres/postgresql-*.log"
      Tag="vpostgres"
      Severity="info"
      Facility="local0")
EOF
)
check_output2=$(cat << EOF
# vmware-postgres-archiver stdout log
input(type="imfile"
      File="/var/log/vmware/vpostgres/pg_archiver.log.stdout"
      Tag="postgres-archiver"
      Severity="info"
      Facility="local0")
# vmware-postgres-archiver stderr log
input(type="imfile"
      File="/var/log/vmware/vpostgres/pg_archiver.log.stderr"
      Tag="postgres-archiver"
      Severity="info"
      Facility="local0")
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo --------------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 Secure Token Service Technical Implementation Guide
echo --------------------------------------------------------------------------------
echo " "
echo "------------ V-258970 ------------"
check=$(xmllint --xpath '/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads' /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
maxThreads="150"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258972 ------------"
check=$(xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' - 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-258973 ------------"
check=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/sts-lin.json 2>/dev/null)
check_output=$(cat << EOF
"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/sso/sts-runtime.log",
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
    
fi
echo " "
echo "------------ V-258974 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
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
pattern="%t %I [Request] &quot;%{User-Agent}i&quot; %{X-Forwarded-For}i/%h:%{remote}p %l %u to local %{local}p - &quot;%r&quot; %H %m %U%q [Response] %s - %b bytes [Perf] process %Dms / commit %Fms / conn [%X]"
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
    
fi
echo " "
echo "------------ V-258975 ------------"
check=$(find /var/log/vmware/sso/ -xdev ! -name lookupsvc-init.log ! -name sts-prestart.log -type f -a '(' -perm -o+w -o -not -user sts -o -not -group lwis ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258976 ------------"
check=$(xmllint --xpath '/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]' /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
<Listener className="org.apache.catalina.security.SecurityListener"/>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    umask_value=$(xmllint --xpath 'string(/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]/@minimumUmask)' /usr/lib/vmware-lookupsvc/conf/server.xml)
    if [ -z "$umask_value" ]; then
        echo -e "\e[32mNot a Finding\e[0m"
    elif [ "$umask_value" != "0007" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258977 ------------"
check=$(xmllint --xpath "//Connector[@allowTrace = 'true']" /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258978 ------------"
check=$(xmllint --xpath '//Connector[not(@port = "${bio-ssl-clientauth.https.port}") and (@port = "0" or not(@address))]' /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258979 ------------"
check=$(grep RECYCLE_FACADES /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-258980 ------------"
check=$(grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-258981 ------------"
check=$(xmllint --xpath "//Connector[@URIEncoding != 'UTF-8'] | //Connector[not[@URIEncoding]]" /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258982 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>
EOF
)
check_output_2=$(cat << EOF
<Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false"/>
EOF
)
check_output_2=$( echo "$check_output_2" | awk '{$1=$1};1' )
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output_2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258983 ------------"
check=$(xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/session-timeout' - 2>/dev/null)
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
    
else
    timeout=$(echo "$check" | sed -n 's:.*<session-timeout>\([0-9]\+\)</session-timeout>.*:\1:p')
    if [[ -n "$timeout" ]]; then 
        if (( timeout <= 30 )); then
            echo -e "\e[32mNot a Finding\e[0m"
        fi
    else
        echo -e "\e[31mOpen\e[0m"
        echo $check
        
    fi
fi
echo " "
echo "------------ V-258984 ------------"
check=$(cat /etc/vmware-syslog/vmware-services-sso-services.conf 2>/dev/null)
check_output=$(cat << EOF
#vmidentity logs
input(type="imfile"
      File="/var/log/vmware/sso/activedirectoryservice.log"
      Tag="activedirectoryservice"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/lookupsvc-init.log"
      Tag="ssolookupsvc-init"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/openidconnect.log"
      Tag="openidconnect"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/ssoAdminServer.log"
      Tag="ssoadminserver"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/svcaccountmgmt.log"
      Tag="svcaccountmgmt"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/tokenservice.log"
      Tag="tokenservice"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
#sts health log
input(type="imfile"
      File="/var/log/vmware/sso/sts-health-status.log"
      Tag="sts-health-status"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2} [[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2},[[:digit:]]{0,4}"
      Facility="local0")
#sts runtime log stdout
input(type="imfile"
      File="/var/log/vmware/sso/sts-runtime.log.stdout"
      Tag="sts-runtime-stdout"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#sts runtime log stderr
input(type="imfile"
      File="/var/log/vmware/sso/sts-runtime.log.stderr"
      Tag="sts-runtime-stderr"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#gclogFile.0.current log
input(type="imfile"
      File="/var/log/vmware/sso/gclogFile.*.current"
      Tag="gclog"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}+[[:digit:]]{0,4}"
      Facility="local0")
#identity sts default
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts-default.log"
      Tag="sso-identity-sts-default"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity sts
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts.log"
      Tag="sso-identity-sts"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity perf
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts-perf.log"
      Tag="sso-identity-perf"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity prestart
input(type="imfile"
      File="/var/log/vmware/sso/sts-prestart.log"
      Tag="sso-identity-prestart"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest idm
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-idm.log"
      Tag="sso-rest-idm"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest vmdir
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-vmdir.log"
      Tag="sso-rest-vmdir"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest afd
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-afd.log"
      Tag="sso-rest-afd"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#websso
input(type="imfile"
      File="/var/log/vmware/sso/websso.log"
      Tag="sso-websso"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat catalina
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/catalina.*.log"
      Tag="sso-tomcat-catalina"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat localhost
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/localhost.*.log"
      Tag="sso-tomcat-localhost"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat localhost access
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/localhost_access.log"
      Tag="sso-tomcat-localhost-access"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#vmdir log
input(type="imfile"
      File="/var/log/vmware/vmdir/*.log"
      Tag="vmdir"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#vmafd log
input(type="imfile"
      File="/var/log/vmware/vmafd/*.log"
      Tag="vmafd"
      PersistStateInterval="200"
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
fi
echo " "
echo "------------ V-258985 ------------"
check=$(xmllint --xpath "//Connector[@connectionTimeout = '-1']" /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258986 ------------"
check=$(xmllint --xpath "//Connector[@maxKeepAliveRequests = '-1']" /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258987 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'setCharacterEncodingFilter')]/parent::*" /usr/lib/vmware-sso/vmware-sts/conf/web.xml 2>/dev/null)
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
check_output2=$(cat << EOF
<filter-mapping>
        <filter-name>setCharacterEncodingFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
<filter>
        <filter-name>setCharacterEncodingFilter</filter-name>
        <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
        <init-param>
            <param-name>encoding</param-name>
            <param-value>UTF-8</param-value>
        </init-param>
        <init-param>
            <param-name>ignore</param-name>
            <param-value>true</param-value>
        </init-param>
        <async-supported>true</async-supported>
    </filter>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258988 ------------"
check=$(xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' - 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-258989 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'DefaultServlet')]/parent::*" /usr/lib/vmware-sso/vmware-sts/conf/web.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"readOnly"* ]]; then
    if [[ "$check" == *"false"* ]]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
         
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-258990 ------------"
check=$(xmllint --xpath "//Server/@port" /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check2=$(grep 'base.shutdown.port' /etc/vmware-eam/catalina.properties 2>/dev/null)
check_output1=$(cat << EOF
port="\${base.shutdown.port}"
EOF
)
check_output2=$(cat << EOF
base.shutdown.port=-1
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output1" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-258991 ------------"
check=$(xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="debug"]/parent::init-param' - 2>/dev/null)
check_output=$(cat << EOF
<init-param>
      <param-name>debug</param-name>
      <param-value>0</param-value>
</init-param>
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
    
fi
echo " "
echo "------------ V-258992 ------------"
check=$(xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' - 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258993 ------------"
check=$(xmllint --xpath "//Host/@autoDeploy" /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-258994 ------------"
check=$(xmllint --xpath "//Connector/@xpoweredBy" /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258995 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/examples 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258996 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/ROOT)
check_output=$(cat << EOF
total 0
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258997 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/docs 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258998 ------------"
check=$(find /usr/lib/vmware-sso/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-258999 ------------"
check=$(grep ALLOW_BACKSLASH /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259000 ------------"
check=$(grep ENFORCE_ENCODING_IN_GET_WRITER /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259001 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259002 ------------"
check=$(ls -l /var/opt/apache-tomcat/webapps/host-manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-266136 ------------"
check=$(xmllint --xpath "//Host/@deployXML" /usr/lib/vmware-sso/vmware-sts/conf/server.xml 2>/dev/null)
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
    
fi
echo " "
echo --------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 User Interface Technical Implementation Guide
echo --------------------------------------------------------------------------
echo " "
echo "------------ V-259104 ------------"
check=$(xmllint --xpath '/Server/Service/Connector[@port="${http.port}"]/@maxThreads' /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
maxThreads="800"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259105 ------------"
check=$(xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' - 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259106 ------------"
check=$(grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json 2>/dev/null)
check_output=$(cat << EOF
"StreamRedirectFile" : "%VMWARE_LOG_DIR%/vmware/vsphere-ui/logs/vsphere-ui-runtime.log",
EOF
)
check_output2=$(cat << EOF
"StreamRedirectFile": "%VMWARE_LOG_DIR%/vmware/vsphere-ui/logs/vsphere-ui-runtime.log",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check_output
    echo "Check if there is output behind "StremRedirectFile:" if there is this is NF"
    
fi
echo " "
echo "------------ V-259107 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
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
pattern="%h %{x-forwarded-for}i %l %u %t &quot;%r&quot; %s %b %{#hashedClientId#}s %{#hashedRequestId#}r %I %D"
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
    
fi
echo " "
echo "------------ V-259108 ------------"
check=$(find /var/log/vmware/vsphere-ui/ -xdev -type f -a '(' -perm -o+w -o -not -user vsphere-ui -o -not -group users -a -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259109 ------------"
check=$(xmllint --xpath '/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]' /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check_output=$(cat << EOF
<Listener className="org.apache.catalina.security.SecurityListener"/>
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    umask_value=$(xmllint --xpath 'string(/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]/@minimumUmask)' /usr/lib/vmware-lookupsvc/conf/server.xml)
    if [ -z "$umask_value" ]; then
        echo -e "\e[32mNot a Finding\e[0m"
    elif [ "$umask_value" != "0007" ]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
        
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259110 ------------"
check=$(xmllint --xpath "//Connector[@allowTrace = 'true']" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259111 ------------"
check=$(xmllint --xpath "//Connector[(@port = '0') or not(@address)]" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259112 ------------"
check=$(grep RECYCLE_FACADES /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259113 ------------"
check=$(grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259114 ------------"
check=$(xmllint --xpath "//Connector[@URIEncoding != 'UTF-8'] | //Connector[not[@URIEncoding]]" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259115 ------------"
check=$(xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259116 ------------"
check=$(xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/session-timeout' - 2>/dev/null)
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
    
else
    timeout=$(echo "$check" | sed -n 's:.*<session-timeout>\([0-9]\+\)</session-timeout>.*:\1:p')
    if [[ -n "$timeout" ]]; then 
        if (( timeout <= 30 )); then
            echo -e "\e[32mNot a Finding\e[0m"
        fi
    else
        echo -e "\e[31mOpen\e[0m"
        echo $check
        
    fi
fi
echo " "
echo "------------ V-259117 ------------"
check=$(cat /etc/vmware-syslog/vmware-services-vsphere-ui.conf 2>/dev/null)
check_output=$(cat << EOF
#vsphere-ui main log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/vsphere_client_virgo.log"
      Tag="ui-main"
      Severity="info"
      Facility="local0")
#vsphere-ui change log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/changelog.log"
      Tag="ui-changelog"
      Severity="info"
      Facility="local0")
#vsphere-ui dataservice log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/dataservice.log"
      Tag="ui-dataservice"
      Severity="info"
      Facility="local0")
#vsphere-ui apigw log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/apigw.log"
      Tag="ui-apigw"
      Severity="info"
      Facility="local0")
#vsphere-ui equinox log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/equinox.log"
      Tag="ui-equinox"
      Severity="info"
      Facility="local0")
#vsphere-ui event log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/eventlog.log"
      Tag="ui-eventlog"
      Severity="info"
      Facility="local0")
#vsphere-ui op id log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/opId.log"
      Tag="ui-opid"
      Severity="info"
      Facility="local0")
#vsphere-ui performance audit log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/performanceAudit.log"
      Tag="ui-performanceAudit"
      Severity="info"
      Facility="local0")
#vsphere-ui plugin-medic log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/plugin-medic.log"
      Tag="ui-plugin-medic"
      Severity="info"
      Facility="local0")
#vsphere-ui threadmonitor log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/threadmonitor.log"
      Tag="ui-threadmonitor"
      Severity="info"
      Facility="local0")
#vsphere-ui threadpools log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/threadpools.log"
      Tag="ui-threadpools"
      Severity="info"
      Facility="local0")
#vsphere-ui vspheremessaging log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/vspheremessaging.log"
      Tag="ui-vspheremessaging"
      Severity="info"
      Facility="local0")
#vsphere-ui rpm log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/vsphere-ui-rpm.log"
      Tag="ui-rpm"
      Severity="info"
      Facility="local0")
#vsphere-ui runtime log stdout
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime.log*"
      Tag="ui-runtime-stdout"
      Severity="info"
      Facility="local0")
#vsphere-ui runtime log stderr
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime.log*"
      Tag="ui-runtime-stderr"
      Severity="info"
      Facility="local0")
#vsphere-ui access log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/access/localhost_access_log.txt"
      Tag="ui-access"
      Severity="info"
      Facility="local0")
#vsphere-ui gc log
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/vsphere-ui-gc*"
      Tag="ui-gc"
      Severity="info"
      Facility="local0")
#vsphere-ui firstboot log
input(type="imfile"
      File="/var/log/firstboot/vsphere_ui_firstboot*"
      Tag="ui-firstboot"
      Severity="info"
      Facility="local0")
#vsphere-ui catalina
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/catalina.*.log"
      Tag="ui-runtime-catalina"
      Severity="info"
      Facility="local0")
#vsphere-ui endpoint
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/endpoint.log"
      Tag="ui-runtime-endpoint"
      Severity="info"
      Facility="local0")
#vsphere-ui localhost
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/localhost.*.log"
      Tag="ui-runtime-localhost"
      Severity="info"
      Facility="local0")
#vsphere-ui vsan
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/vsan-plugin.log"
      Tag="ui-runtime-vsan"
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
    
fi
echo " "
echo "------------ V-259118 ------------"
check=$(grep STRICT_SERVLET_COMPLIANCE /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties 2>/dev/null)
check_output=$(cat << EOF
org.apache.catalina.STRICT_SERVLET_COMPLIANCE=true
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259119 ------------"
check=$(xmllint --xpath "//Connector[@connectionTimeout = '-1']" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259120 ------------"
check=$(xmllint --xpath "//Connector[@maxKeepAliveRequests = '-1']" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259121 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'setCharacterEncodingFilter')]/parent::*" /usr/lib/vmware-vsphere-ui/server/conf/web.xml 2>/dev/null)
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
check_output2=$(cat << EOF
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
<filter-mapping>
        <filter-name>setCharacterEncodingFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259122 ------------"
check=$(xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' - 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259123 ------------"
check=$(xmllint --xpath "//*[contains(text(), 'DefaultServlet')]/parent::*" /usr/lib/vmware-vsphere-ui/server/conf/web.xml 2>/dev/null)
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
elif [[ "$check" == *"readOnly"* ]]; then
    if [[ "$check" == *"false"* ]]; then
        echo -e "\e[31mOpen\e[0m"
        echo $check
         
    else
        echo -e "\e[32mNot a Finding\e[0m"
    fi 
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259124 ------------"
check=$(xmllint --xpath "//Server/@port" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check2=$(grep shutdown.port /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json 2>/dev/null)
check_output1=$(cat << EOF
port="\${shutdown.port}"
EOF
)
check_output2=$(cat << EOF
"-Dshutdown.port=-1",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output1" ] && [ "$check2" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-259125 ------------"
check=$(xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="debug"]/parent::init-param' - 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259126 ------------"
check=$(xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' - 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259127 ------------"
check=$(xmllint --xpath "//Host/@deployXML" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259128 ------------"
check=$(xmllint --xpath "//Host/@autoDeploy" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259129 ------------"
check=$(xmllint --xpath "//Connector/@xpoweredBy" /usr/lib/vmware-vsphere-ui/server/conf/server.xml 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [[ "$check" == *"false"* ]]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259130 ------------"
check=$(ls -l /usr/lib/vmware-vsphere-ui/server/webapps/examples 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259131 ------------"
check=$(ls -l /usr/lib/vmware-vsphere-ui/server/webapps/ROOT 2>/dev/null)
check_output=$(cat << EOF
total 0
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
    
fi
echo " "
echo "------------ V-259132 ------------"
check=$(ls -l /usr/lib/vmware-vsphere-ui/server/webapps/docs 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259133 ------------"
check=$(grep ALLOW_BACKSLASH /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259134 ------------"
check=$(grep ENFORCE_ENCODING_IN_GET_WRITER /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties 2>/dev/null)
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
    
fi
echo " "
echo "------------ V-259135 ------------"
check=$(ls -l /usr/lib/vmware-vsphere-ui/server/webapps/manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259136 ------------"
check=$(ls -l /usr/lib/vmware-vsphere-ui/server/webapps/host-manager 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo ----------------------------------------------------------------
echo ----------VMware vSphere 8.0 VAMI Technical Implementation Guide
echo ----------------------------------------------------------------
echo " "
echo "------------ V-259137 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null |grep "server.max-connections" 2>/dev/null)
check_output=$(cat << EOF
server.max-connections = 1024
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259138 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "ssl.engine" 2>/dev/null)
check_output=$(cat << EOF
ssl.engine = "enable"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259139 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\)/'|grep mod_accesslog 2>/dev/null)
check_output=$(cat << EOF
"mod_accesslog",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259140 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "accesslog.format" 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259141 ------------"
check=$(find /var/log/vmware/applmgmt/ /var/log/vmware/applmgmt-audit/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \; 2>/dev/null)
check2=$(find /opt/vmware/var/log/lighttpd/ -xdev -type f -a '(' -perm -o+w -o -not -user lighttpd -o -not -group lighttpd ')' -exec ls -ld {} \; 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
check2=$( echo "$check2" | awk '{$1=$1};1' )
if [ -z "$check" ] && [ -z "$check2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    echo $check2
    
fi
echo " "
echo "------------ V-259142 ------------"
check=$(cat /etc/vmware-syslog/vmware-services-applmgmt.conf 2>/dev/null)
check_output=$(cat << EOF
#applmgmt.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/applmgmt.log"
      Tag="applmgmt"
      Severity="info"
      Facility="local0")
#applmgmt-audit.log
input(type="imfile"
      File="/var/log/vmware/applmgmt-audit/applmgmt-audit.log"
      Tag="applmgmt-audit"
      Severity="info"
      Facility="local0")
#applmgmt-backup-restore-audit.log
input(type="imfile"
      File="/var/log/vmware/applmgmt-audit/applmgmt-br-audit.log"
      Tag="applmgmt-br-audit"
      Severity="info"
      Facility="local0")
#vami-access.log
input(type="imfile"
      File="/opt/vmware/var/log/lighttpd/access.log"
      Tag="vami-access"
      Severity="info"
      Facility="local0")
#vami-error.log
input(type="imfile"
      File="/opt/vmware/var/log/lighttpd/error.log"
      Tag="vami-error"
      Severity="info"
      Facility="local0")
#dcui.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/dcui.log"
      Tag="dcui"
      Severity="info"
      Facility="local0")
#detwist.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/detwist.log"
      Tag="detwist"
      Severity="info"
      Facility="local0")
#firewall-reload.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/firewall-reload.log"
      Tag="firewall-reload"
      Severity="info"
      Facility="local0")
#applmgmt_vmonsvc.std*
input(type="imfile"
      File="/var/log/vmware/applmgmt/applmgmt_vmonsvc.std*"
      Tag="applmgmt_vmonsvc"
      Severity="info"
      Facility="local0")
#backupSchedulerCron
input(type="imfile"
      File="/var/log/vmware/applmgmt/backupSchedulerCron.log"
      Tag="backupSchedulerCron"
      Severity="info"
      Facility="local0")
#progress.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/progress.log"
      Tag="progress"
      Severity="info"
      Facility="local0")
#statsmoitor-alarms
input(type="imfile"
      File="/var/log/vmware/statsmon/statsmoitor-alarms.log"
      Tag="statsmoitor-alarms"
      Severity="info"
      Facility="local0")
#StatsMonitor
input(type="imfile"
      File="/var/log/vmware/statsmon/StatsMonitor.log"
      Tag="StatsMonitor"
      Severity="info"
      Facility="local0")
#StatsMonitorStartup.log.std*
input(type="imfile"
      File="/var/log/vmware/statsmon/StatsMonitorStartup.log.std*"
      Tag="StatsMonitor-Startup"
      Severity="info"
      Facility="local0")
#PatchRunner
input(type="imfile"
      File="/var/log/vmware/applmgmt/PatchRunner.log"
      Tag="PatchRunner"
      Severity="info"
      Facility="local0")
#update_microservice
input(type="imfile"
      File="/var/log/vmware/applmgmt/update_microservice.log"
      Tag="update_microservice"
      Severity="info"
      Facility="local0")
#vami
input(type="imfile"
      File="/var/log/vmware/applmgmt/vami.log"
      Tag="vami"
      Severity="info"
      Facility="local0")
#vcdb_pre_patch
input(type="imfile"
      File="/var/log/vmware/applmgmt/vcdb_pre_patch.*"
      Tag="vcdb_pre_patch"
      Severity="info"
      Facility="local0")
#dnsmasq.log
input(type="imfile"
      File="/var/log/vmware/dnsmasq.log"
      Tag="dnsmasq"
      Severity="info"
      Facility="local0")
#procstate
input(type="imfile"
      File="/var/log/vmware/procstate"
      Tag="procstate"
      Severity="info"
      Facility="local0")
#backup.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/backup.log"
      Tag="applmgmt-backup"
      Severity="info"
      Facility="local0")
#size.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/size.log"
      Tag="applmgmt-size"
      Severity="info"
      Facility="local0")
#restore.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/restore.log"
      Tag="applmgmt-restore"
      Severity="info"
      Facility="local0")
#reconciliation.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/reconciliation.log"
      Tag="applmgmt-reconciliation"
      Severity="info"
      Facility="local0")
#pnid_change.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/pnid_change.log"
      Tag="applmgmt-pnid-change"
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
    
fi
echo " "
echo "------------ V-259143 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "mimetype.use-xattr" 2>/dev/null)
check_output=$(cat << EOF
mimetype.use-xattr="disable"
EOF
)
check_output2=$(cat << EOF
mimetype.use-xattr = "disable"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259144 ------------"
check=$(grep "url.access-deny" /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null)
check_output=$(cat << EOF
url.access-deny = ( "~", ".inc" )
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259145 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\)/'|grep mod_webdav 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259146 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "server.max-keep-alive-idle" 2>/dev/null)
check_output=$(cat << EOF
server.max-keep-alive-idle=30
EOF
)
check_output2=$(cat << EOF
server.max-keep-alive-idle = 30
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259147 ------------"
check=$(stat -c "%n has %a permissions and is owned by %U:%G" /etc/applmgmt/appliance/server.pem 2>/dev/null)
check_output=$(cat << EOF
/etc/applmgmt/appliance/server.pem has 600 permissions and is owned by root:root
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259149 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "server.max-fds" 2>/dev/null)
check_output=$(cat << EOF
server.max-fds=2048
EOF
)
check_output2=$(cat << EOF
server.max-fds = 2048
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
check_output2=$( echo "$check_output2" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ] || [ "$check" = "$check_output2" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259150 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|awk '/mimetype\.assign/,/\)/'|grep "text/"|grep -v "charset=utf-8" 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259151 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "dir-listing.activate" 2>/dev/null)
check_output=$(cat << EOF
dir-listing.activate = "disable"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259152 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\)/'|grep mod_status 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259153 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "debug.log-request-handling" 2>/dev/null)
check_output=$(cat << EOF
debug.log-request-handling = "disable"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259155 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "ssl\.disable-client-renegotiation" 2>/dev/null)
check=$( echo "$check" | awk '{$1=$1};1' )
if [ -z "$check" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
elif [[ "$check" == *"disabled"* ]]; then
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
else
    echo -e "\e[32mNot a Finding\e[0m"
fi
echo " "
echo "------------ V-259156 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|grep "server.tag" 2>/dev/null)
check_output=$(cat << EOF
server.tag = "vami"
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259157 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|awk '/setenv\.add-response-header/,/\)/'|sed -e 's/^[ ]*//'|grep "Strict-Transport-Security" 2>/dev/null)
check_output=$(cat << EOF
"Strict-Transport-Security" => "max-age=31536000; includeSubDomains; preload",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259158 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|awk '/setenv\.add-response-header/,/\)/'|sed -e 's/^[ ]*//'|grep "X-Frame-Options" 2>/dev/null)
check_output=$(cat << EOF
"X-Frame-Options" => "Deny",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259159 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|awk '/setenv\.add-response-header/,/\)/'|sed -e 's/^[ ]*//'|grep "X-Content-Type-Options" 2>/dev/null)
check_output=$(cat << EOF
"X-Content-Type-Options" => "nosniff",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "------------ V-259160 ------------"
check=$(/opt/vmware/cap_lighttpd/sbin/lighttpd -p -f /var/lib/vmware/cap-lighttpd/lighttpd.conf 2>/dev/null|awk '/setenv\.add-response-header/,/\)/'|sed -e 's/^[ ]*//'|grep "Content-Security-Policy" 2>/dev/null)
check_output=$(cat << EOF
"Content-Security-Policy" => "default-src 'self'; img-src 'self' data: https://vcsa.vmware.com; font-src 'self' data:; object-src 'none'; style-src 'self' 'unsafe-inline'",
EOF
)
check=$( echo "$check" | awk '{$1=$1};1' )
check_output=$( echo "$check_output" | awk '{$1=$1};1' )
if [ "$check" = "$check_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $check
    
fi
echo " "
echo "There are $ open findings."
