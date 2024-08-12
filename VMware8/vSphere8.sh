#!/bin/bash

#****************************************************************
#*************Written By Mitchell Gibson USACPB CRIA*************
#*************Last Updated Aug 6, 2024 v1.0*********************
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
pattern="%h %{X-Forwarded-For}i %l %u %t [%I] &quot;%r&quot; %s %b [Processing time %D msec] &quot;%{User-Agent}i&quot;"
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
esx_limit_data=$(grep RECYCLE_FACADES /etc/vmware-eam/catalina.properties)
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
esx_safe=$(grep EXIT_ON_INIT_FAILURE /etc/vmware-eam/catalina.properties)
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
esx_showserver=$( echo "$esx_showserver" | awk '{$1=$1};1' )
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
esx_offload=$( echo "$esx_offload" | awk '{$1=$1};1' )
esx_offload_output=$( echo "$esx_offload_output" | awk '{$1=$1};1' )
if [ "$esx_offload" = "$esx_offload_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_offload
    ((count++))
fi
echo " "
echo "------------ V-259017 ------------"

echo " "
echo "------------ V-259018 ------------"

echo " "
echo "------------ V-259019 ------------"

echo " "
echo "------------ V-259020 ------------"

echo " "
echo "------------ V-259021 ------------"

echo " "
echo "------------ V-259022 ------------"

echo " "
echo "------------ V-259023 ------------"

echo " "
echo "------------ V-259024 ------------"

echo " "
echo "------------ V-259025 ------------"

echo " "
echo "------------ V-259026 ------------"

echo " "
echo "------------ V-259027 ------------"

echo " "
echo "------------ V-259028 ------------"

echo " "
echo "------------ V-259029 ------------"

echo " "
echo "------------ V-259030 ------------"

echo " "
echo "------------ V-259031 ------------"

echo " "
echo "------------ V-259032 ------------"

echo " "
echo "------------ V-259033 ------------"

echo " "
echo "------------ V-259034 ------------"

echo " "
echo "------------ V-259035 ------------"

echo " "
echo "------------ V-259036 ------------"

echo " "
echo -----------------------------------------------------------------
echo ----------VMware vSphere 8.0 Envoy Technical Implementation Guide
echo -----------------------------------------------------------------
echo " "
echo "------------ V-259161 ------------"

echo " "
echo "------------ V-259162 ------------"

echo " "
echo "------------ V-259163 ------------"

echo " "
echo "------------ V-259164 ------------"

echo " "
echo "------------ V-259165 ------------"

echo " "
echo --------------------------------------------------------------------------
echo ----------VMware vSphere 8.0 Lookup Service Technical Implementation Guide
echo --------------------------------------------------------------------------
echo " "
echo "------------ V-259037 ------------"

echo " "
echo "------------ V-259038 ------------"

echo " "
echo "------------ V-259039 ------------"

echo " "
echo "------------ V-259040 ------------"

echo " "
echo "------------ V-259041 ------------"

echo " "
echo "------------ V-259042 ------------"

echo " "
echo "------------ V-259043 ------------"

echo " "
echo "------------ V-259044 ------------"

echo " "
echo "------------ V-259045 ------------"

echo " "
echo "------------ V-259046 ------------"

echo " "
echo "------------ V-259047 ------------"

echo " "
echo "------------ V-259048 ------------"

echo " "
echo "------------ V-259049 ------------"

echo " "
echo "------------ V-259050 ------------"

echo " "
echo "------------ V-259051 ------------"

echo " "
echo "------------ V-259052 ------------"

echo " "
echo "------------ V-259053 ------------"

echo " "
echo "------------ V-259054 ------------"

echo " "
echo "------------ V-259055 ------------"

echo " "
echo "------------ V-259056 ------------"

echo " "
echo "------------ V-259057 ------------"

echo " "
echo "------------ V-259058 ------------"

echo " "
echo "------------ V-259059 ------------"

echo " "
echo "------------ V-259060 ------------"

echo " "
echo "------------ V-259061 ------------"

echo " "
echo "------------ V-259062 ------------"

echo " "
echo "------------ V-259063 ------------"

echo " "
echo "------------ V-259064 ------------"

echo " "
echo "------------ V-259065 ------------"

echo " "
echo "------------ V-259066 ------------"

echo " "
echo "------------ V-259067 ------------"

echo " "
echo "------------ V-259068 ------------"

echo " "
echo "------------ V-259069 ------------"

echo " "
echo "------------ V-259070 ------------"

echo " "
echo ----------------------------------------------------------------------
echo ----------VMware vSphere 8.0 Perfcharts Technical Implementation Guide
echo ----------------------------------------------------------------------
echo " "
echo "------------ V-259071 ------------"

echo " "
echo "------------ V-259072 ------------"

echo " "
echo "------------ V-259073 ------------"

echo " "
echo "------------ V-259074 ------------"

echo " "
echo "------------ V-259075 ------------"

echo " "
echo "------------ V-259076 ------------"

echo " "
echo "------------ V-259077 ------------"

echo " "
echo "------------ V-259078 ------------"

echo " "
echo "------------ V-259079 ------------"

echo " "
echo "------------ V-259080 ------------"

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