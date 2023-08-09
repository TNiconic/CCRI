#Here are the steps in order to get the vSphere.sh STIG checking tool to work:


#First you must enable SSH to the vSphere client

#SSH as the local user (usually root) then you will see a prompt
  ssh root@<IPaddr>

#Create the file and paste in the contents of vSphere.sh
  vim vSphere.sh
  i
  <paste>

#Then change the permissions of the file to give yourself read/write/execute privilege
  chmod 700 vSphere.sh

#Lastly, run the script
  ./vSphere.sh



#Example
![alt text](https://github.com/TNiconic/CCRI/blob/main/VMware/vsphere_tutorial.png?raw=true)
