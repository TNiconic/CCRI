esx_servlet=$(grep STRICT_SERVLET_COMPLIANCE /etc/vmware-eam/catalina.properties)
esx_servlet_output=$(cat << EOF
org.apache.catalina.STRICT_SERVLET_COMPLIANCE=true
EOF
)
esx_servlet=$( echo "$esx_servlet" | awk '{$1=$1};1' )
esx_servlet_output=$( echo "$esx_servlet_output" | awk '{$1=$1};1' )
if [ -z "$esx_servlet" ]; then
    echo -e "\e[31mOpen\e[0m"
    ((count++))
    echo "Session timeout is missing"
elif [ "$esx_servlet" = "$esx_servlet_output" ]; then
    echo -e "\e[32mNot a Finding\e[0m"
else
    echo -e "\e[31mOpen\e[0m"
    echo $esx_servlet
    ((count++))
fi