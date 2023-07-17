#At the top for output options, won't appear in script
write-host "------------ V-256413 ------------";
Write-host "If IP-Based storage is in use this is Not Applicable"
write-host "For each IP-Based storage VMkernel, make sure there are no services running except for the vSAN service"
Write-host "Also make sure all IP-Based storage are isolated from other Vlans"
foreach ($VMhost in (Get-VMHost)) {
    (Get-VirtualPortGroup -VMHost $vmhost -Standard)
    (Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop | Select-Object Name,PortGroupName,VsanTrafficEnabled,ProvisioningEnabled,VSphereReplicationEnabled,VSphereReplicationNFCEnabled,VSphereBackupNFCEnabled,ManagementTrafficEnabled,FaultToleranceLoggingEnabled,VMotionEnabled)
}
Clear-Host

#Get Host Information for individual ESXi host
Write-Host "Host Name = "(get-vmhost | Select-Object Name).Name
Write-Host "IP Address = "(get-vmhost | Get-VMHostNetworkAdapter | Where-Object {$_.Name -eq "vmk0"} | Select-Object IP).IP
Write-Host "MAC Address = "(get-vmhost | Get-VMHostNetworkAdapter | Where-Object {$_.Name -eq "vmk0"} | Select-Object Mac).Mac
Write-Host "FQDN = "(Get-VMHost | Select-Object @{N="FQDN";E={$_.NetworkInfo.HostName + "." + $_.NetworkInfo.DomainName}}).FQDN
Write-Host "Target Data = Member Server"
write-host ""

#Get Credentials to enable ssh into ESXi shell utilizing PuTTY's Plink protocol
Write-host "Provide root credentials for ESXi Shell; Remember to allow SSH"
$SSh_creds = Get-Credential -Credential root
$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($SSh_creds.Password)
$result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)

#Start of the Checks
write-host "------------ V-2256375 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $lockdown = (Get-VMHost | Select-Object Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}).Lockdown
    if ($lockdown -eq ("lockdownNormal" -or "lockdownStrict")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $lockdown
    }
}
write-host ""
write-host "------------ V-256376 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $DCUIaccess = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name DCUI.Access).value
    if ($DCUIaccess -eq "root") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $DCUIaccess
    }
}
write-host ""
write-host "------------ V-256377 ------------"
foreach ($vmhostes in (Get-VMHost)) {
    $vcenter_check3 = ((Get-VMHost |Select-Object Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).Name
    $other_vcenter_check3 = ((Get-VMHost |Select-Object Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).vCenter
    if ($vcenter_check3 -eq $other_vcenter_check3) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Vcenter being used"
    } else { 
        Write-host "Validate these are authorized lockdown users"
    $lockdown = Get-VMHost | Get-View
    $lockdown2 = Get-View $lockdown.ConfigManager.HostAccessManager
    $lockdown_output = $lockdown2.QueryLockdownExceptions()
    Write-Output $lockdown_output
    }
}
write-host ""
write-host "------------ V-256378 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $Syslog = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name Syslog.global.logHost).value
    if ($Syslog -eq "") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output "No output"
    } else {
        Write-Host "Validate that these are valid documented syslog servers"
        Write-Host $Syslog
    }
}
 write-host ""
 write-host "------------ V-256379 ------------"
 foreach ($VMhost in (Get-VMHost)) {
    $three_invalid = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name Security.AccountLockFailures).value
    if ($three_invalid -eq 3) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $three_invalid
    }
}
  write-host ""
  write-host "------------ V-256380 ------------"
  foreach ($VMhost in (Get-VMHost)) {
    $fifteen_min = (Get-VMHost | sort-object name| Get-AdvancedSetting -Name Security.AccountUnlockTime).value
    if ($fifteen_min -eq 900) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $fifteen_min
    }
}
write-host ""
write-host "------------ V-256381 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $banner = (Get-VMHost | sort-object name| Get-AdvancedSetting -Name Annotations.WelcomeMessage).value
    if ($banner -like "* You are accessing a U.S. Government*") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $banner
    }
}
 write-host ""
 write-host "------------ V-256382 ------------"
 foreach ($VMhost in (Get-VMHost)) {
    $ssh_banner = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name Config.Etc.issue).value
    if ($ssh_banner -like "*You are accessing a U.S. Government*") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
    }
}
  write-host ""
  write-host "------------ V-256383 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep banner")
    if ($plink_banner -eq "banner /etc/issue") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
  write-host "------------ V-256384 ------------"
  foreach ($VMhost in (Get-VMHost)) {
    $esxcli = Get-EsxCli -v2
    $fips = ($esxcli.system.security.fips140.ssh.get.invoke()).Enabled
    if ($fips -eq "True") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $fips
    }
}
   write-host ""
   write-host "------------ V-256385 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_rhost = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep ignorerhosts")
    if ($plink_rhost -eq "ignorerhosts yes") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_rhost
    }
}
write-host ""
write-host "------------ V-256386 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_hba = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep hostbasedauthentication")
    if ($plink_hba -eq "hostbasedauthentication no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_hba
    }
}
write-host ""
write-host "------------ V-256387 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_pep = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep permitemptypasswords")
    if ($plink_pep -eq "permitemptypasswords no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_pep
    }
}
write-host ""
write-host "------------ V-256388 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_pue = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep permituserenvironment")
    if ($plink_pue -eq "permituserenvironment no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_pue
    }
}
write-host ""
write-host "------------ V-256389 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_sm = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep strictmodes")
    if ($plink_sm -eq "strictmodes yes") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_sm
    }
}
write-host ""
write-host "------------ V-256390 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_com = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep compression")
    if ($plink_com -eq "compression no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_com
    }
}
write-host ""
write-host "------------ V-256391 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_gwp = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep gatewayports")
    if ($plink_gwp -eq "gatewayports no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_gwp
    }
}
write-host ""
write-host "------------ V-256392 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_x11 = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep x11forwarding")
    if ($plink_x11 -eq "x11forwarding no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_x11
    }
}
write-host ""
write-host "------------ V-256393 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_ptn = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep permittunnel")
    if ($plink_ptn -eq "permittunnel no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_ptn
    }
}
write-host ""
write-host "------------ V-256394 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_cam = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep clientalivecountmax")
    if ($plink_cam -eq "clientalivecountmax 3") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_cam
    }
}
write-host ""
write-host "------------ V-256395 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_cai = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/openssh/bin/sshd -T | grep clientaliveinterval")
    if ($plink_cai -eq "clientaliveinterval 200") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_cai
    }
}
write-host ""
   write-host "------------ V-256396 ------------"
 foreach ($VMhost in (Get-VMHost)) {
    $info = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name Config.HostAgent.log.level).value
    if ($info -eq "info") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $info
    }
}
  write-host ""
  write-host "------------ V-256397 ------------"
  foreach ($VMhost in (Get-VMHost)) {
     $complex_p = (Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl).value
     if ($complex_p -eq "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15") {
         Write-Host "Not a Finding" -ForegroundColor Green
     } else {
         Write-Host "Open" -ForegroundColor Red
         Write-Output $complex_p
     }
 }
write-host ""
write-host "------------ V-256398 ------------"
foreach ($VMhost in (Get-VMHost)) {
   $password_h = (Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory).value
   if ($password_h -eq 5) {
       Write-Host "Not a Finding" -ForegroundColor Green
   } else {
       Write-Host "Open" -ForegroundColor Red
       Write-Output $password_h
   }
}
write-host ""
write-host "------------ V-256399 ------------"
foreach ($VMhost in (Get-VMHost)) {
   $mob_disable = (Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob).value
   if ($mob_disable -eq "True") {
       Write-Host "Open" -ForegroundColor Red
       Write-Output $mob_disable
   } else {
       Write-Host "Not a Finding" -ForegroundColor Green
   }
}
write-host ""
write-host "------------ V-256400 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $ssh_stop = (Get-VMHost | Get-VMHostService | Where-Object{$_.Label -eq "SSH"}).Running
    if ($ssh_stop -eq "True") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $ssh_stop
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256401 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $shell_stop = (Get-VMHost | Get-VMHostService | Where-Object{$_.Label -eq "ESXi Shell"}).Running
    if ($shell_stop -eq "True") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_stop
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256402 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $AD_authentication = (Get-VMHost | Get-VMHostAuthentication).Domain;
    if ($AD_authentication -eq $null) {
        Write-Host "AD Authentication is not set"
        Write-Host "Only Root and service accounts should be listed"
        Write-Host "If any account listed isn't a local service or root account this will be open; otherwise this will be Not Applicable"
        $esxcli_other = Get-EsxCli -VMHost $VMhost -V2
        $user_output = ($esxcli_other.system.account.list.Invoke())
        Write-Host ""
        Write-Output $user_output | Format-Table -AutoSize
    }
    if ($AD_authentication -eq "Active Directory") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } if ($AD_authentication -like ".*") {
        Write-Host "Open" -ForegroundColor Red
    }
}
write-host ""
write-host "------------ V-256403 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $AD_authentication2 = (Get-VMHost | Get-VMHostAuthentication).Domain;
    if ($AD_authentication2 -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
    }
    $join_host_Enabled = ((Get-VMHost | sort-object name | Select-Object Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select-Object -ExpandProperty Policy | Where-Object {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}})).JoinADEnabled
    $join_domain_method = ((Get-VMHost | sort-object name | Select-Object Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select-Object -ExpandProperty Policy | Where-Object {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}})).JoinDomainMethod
    if (($join_host_Enabled -eq "True") -and ($join_domain_method -eq "FixedCAMConfigOption")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } if (($join_host_Enabled -eq "True") -and ($join_domain_method -ne "FixedCAMConfigOption")) {
        Write-Host "Open" -ForegroundColor Red
    }
}
write-host ""
write-host "------------ V-256404 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $AD_authentication3 = (Get-VMHost | Get-VMHostAuthentication).Domain;
    if ($AD_authentication3 -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
    }
    else {
        $esx_admins = ((Get-VMHost | sort-object name | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object @{N='VMHost';E={$_.Entity.Name}},Name,Value)).Value
        if ($esx_admins -eq "ESX Admins") {
            Write-Host "Open" -ForegroundColor Red
        } else {
            Write-Host "Not a Finding" -ForegroundColor Green }
    }
}
write-host ""
write-host "------------ V-256405 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $shell_time = (Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut).Value
    if ($shell_time -ne "120") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_time
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256406 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $shell_time2 = (Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut).Value
    if ($shell_time2 -ne "600") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_time2
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256407 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $dcui_time = (Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut).Value
    if ($dcui_time -ne "120") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $dcui_time
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256408 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $esxcli2 = Get-EsxCli -VMHost $VMhost -V2
    $local_log = $esxcli2.system.syslog.config.get.Invoke() | Select-Object LocalLogOutput,LocalLogOutputIsPersistent
    $local_logp = ($esxcli2.system.syslog.config.get.Invoke() | Select-Object LocalLogOutput,LocalLogOutputIsPersistent).LocalLogOutputIsPersistent
    if ($local_logp -ne "true") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $local_log
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256409 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $ntp = (Get-VMHost | Get-VMHostNtpServer)
    $ntp_policy = (Get-VMHost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"}).Policy
    $ntp_running = (Get-VMHost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"}).Running
    if ($ntp -eq $null) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "No NTP server configured"
    } 
    else {
        Write-Host "Validate these are DoD NTP servers"
        Write-Output $ntp
        if (($ntp_policy -eq "on") -and ($ntp_running -eq "True")) {
        Write-Host "Not a Finding" -ForegroundColor Green
        }
        if (($ntp_policy -ne "on") -or ($ntp_running -ne "True")) {
            Write-Host "Open" -ForegroundColor Red
            Write-Host $ntp_policy
        }
    }
}
write-host ""
write-host "------------ V-256410 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $esxi_host = (Get-EsxCli -V2)
    $esxi_host2 = $esxi_host.software.acceptance.get.Invoke()
    if ($esxi_host2 -eq "CommunitySupported") {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2
    } 
    else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256411 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $vcenter_check = ((Get-VMHost |Select-Object Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).Name
    $other_vcenter_check = ((Get-VMHost |Select-Object Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).vCenter
    if ($vcenter_check -eq $other_vcenter_check) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Vcenter being used"
    } 
    else {
            $vmks = Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop
            ForEach($vmk in $vmks){
                If(($vmk.VMotionEnabled -eq "True" -and $vmk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.ManagementTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VsanTrafficEnabled -eq "True")){
                    $Response = "VMKernel $($vmk.name) appears to have vMotion and another function enabled on the same VMKernel on $($vmhost.name)"
                }else{$Response =  "Not a Finding"}
            }
            write-host $Response
            (Get-VirtualPortGroup -VMHost $_ -Standard | Where-Object {(($_.Name).contains("vMotion")) -or (($_.Name).contains("VSAN")) -or (($_.Name).contains("Management")) -or (($_.Name).contains("mgmt"))} | Select-Object Name, VLanID)
            write-host ""
        }
    }
write-host ""
write-host "------------ V-256412 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $vcenter_check2 = ((Get-VMHost |Select-Object Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).Name
    $other_vcenter_check2 = ((Get-VMHost |Select-Object Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).vCenter
    if ($vcenter_check2 -eq $other_vcenter_check2) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Vcenter being used"
    } 
    else {
            $vmks2 = Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop
            ForEach($vmkk in $vmks2){
                If(($vmkk.ManagementTrafficEnabled -eq "True" -and $vmkk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmkk.VMotionEnabled -eq "True" -and $vmkk.ManagementTrafficEnabled -eq "True") -xor ($vmkk.ManagementTrafficEnabled -eq "True" -and $vmkk.VsanTrafficEnabled -eq "True")){
                    $Response = "VMKernel $($vmkk.name) appears to have vMotion and another function enabled on the same VMKernel on $($vmhost.name)"
                }else{$Response =  "Not a Finding"}
            }
            write-host $Response
            (Get-VirtualPortGroup -VMHost $vmhost -Standard | Where-Object {(($_.Name).contains("vMotion")) -or (($_.Name).contains("VSAN")) -or (($_.Name).contains("Management")) -or (($_.Name).contains("mgmt"))} | Select-Object Name, VLanID)
            write-host ""
        }
    }
write-host ""
write-host "------------ V-256413 ------------";
Write-host "If IP-Based storage is NOT in use this is Not Applicable"
write-host "For each IP-Based storage VMkernel, make sure there are no services running except for the vSAN service"
Write-host "Also make sure all IP-Based storage are isolated from other Vlans"
write-host ""
foreach ($VMhost in (Get-VMHost)) {
    (Get-VirtualPortGroup -VMHost $vmhost -Standard | Select-Object Name,VLanID | Format-Table -AutoSize)
    (Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop | Select-Object Name,PortGroupName,VsanTrafficEnabled,ProvisioningEnabled,VSphereReplicationEnabled,VSphereReplicationNFCEnabled,VSphereBackupNFCEnabled,ManagementTrafficEnabled,FaultToleranceLoggingEnabled,VMotionEnabled)
}
write-host ""
write-host "------------ V-256414 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_snmp_enable = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system snmp get | grep Enable:")
    if ($plink_snmp_enable -like "*Enable: false") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        $plink_snmp_comm = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system snmp get | grep Communities:")
        $plink_snmp_targets = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system snmp get | grep Targets:")    
        $plink_snmp_v3targets = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system snmp get | grep V3targets::")    
        if (($plink_snmp_enable -like "*Enable: true") -and ($plink_snmp_comm -like "*Communities: public")) {
            Write-Host "Open" -ForegroundColor Red
            Write-Output $plink_snmp_enable
            Write-Output $plink_snmp_comm
        }
        if (($plink_snmp_enable -like "*Enable: true") -and ($plink_snmp_targets -like "*Targets: .+")) {
            Write-Host "Open" -ForegroundColor Red
            Write-Output $plink_snmp_enable
            Write-Output $plink_snmp_targets
        }
        if (($plink_snmp_enable -like "*Enable: true") -and ($plink_snmp_v3targets -like "*V3targets: .+") -and ($plink_snmp_targets -notlike "*Targets: .+")) {
            Write-Host "Not a Finding" -ForegroundColor Green
        }
    }
}
write-host ""
write-host "------------ V-256415 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $iscsi = (Get-VMHost | sort-object name | Get-VMHostHba | Where-Object {$_.Type -like "*iscsi*"} | Select-Object AuthenticationProperties -ExpandProperty AuthenticationProperties)
    if ($iscsi -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
    }
    else { 
        if ($iscsi.ChapType -ne "required") {
            Write-Host "Open" -ForegroundColor Red
            Write-Output $iscsi
        if ($iscsi.ChapType -eq "required") { 
            Write-Host "Not a Finding" -ForegroundColor Green}}}
}
write-host ""
write-host "------------ V-256416 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $mem_share = (Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting).Value
    if ($mem_share -eq "2") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $mem_share
    }
}
write-host ""
write-host "------------ V-256417 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $firewall_allip = (Get-VMHost | Get-VMHostFirewallException | Where-Object {$_.Enabled -eq $true} | Select-Object Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}})
    $firewall_2 = (@(Get-VMHost | Get-VMHostFirewallException | Where-Object {$_.Enabled -eq $true}).ExtensionData.AllowedHosts.AllIP)
    if ("True" -in $firewall_2) {
        Write-Host "Open" -ForegroundColor Red
        echo ($firewall_allip | Format-Table -AutoSize)
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256418 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $default_block = (Get-VMHost | Get-VMHostFirewallDefaultPolicy)
    $default_block_i = (Get-VMHost | Get-VMHostFirewallDefaultPolicy).IncomingEnabled
    $default_block_o = (Get-VMHost | Get-VMHostFirewallDefaultPolicy).OutgoingEnabled
    if (($default_block_i -eq "True") -or ($default_block_o -eq "True")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $default_block
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256419 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $bdpu = (Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU).Value
    if ($bdpu -eq "1") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $bdpu
    }
}
write-host ""
write-host "------------ V-256420 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $vswitch_ft = (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($vswitch_ft -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } 
    else {
        $vswitch_ft_array = (@(Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy).ForgedTransmits)
        $vportgroup_ft_array = (@(Get-VMHost | Get-VirtualPortGroup -Standard | Get-SecurityPolicy).ForgedTransmits)       
        if ("True" -in $vswitch_ft_array){
            Write-Host "Open" -ForegroundColor Red
            echo (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy | Format-Table -AutoSize)
        }
        if ("True" -in $vportgroup_ft_array) {
            Write-Host "Open" -ForegroundColor Red
            echo (Get-VMHost | Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Format-Table -AutoSize)
        } 
        else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }
    }
}
write-host ""
write-host "------------ V-256421 ------------"
foreach ($vmhosts in (Get-VMHost)) {
    $vswitch_ft2 = (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($vswitch_ft2 -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } else {
        $vswitch_ft_array2 = (@(Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy).MacChanges)
        $vportgroup_ft_array2 = (@(Get-VMHost | Get-VirtualPortGroup -Standard | Get-SecurityPolicy).MacChanges)       
        if ("True" -in $vswitch_ft_array2){
            Write-Host "Open" -ForegroundColor Red
            echo (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy | Format-Table -AutoSize)
        }
        if ("True" -in $vportgroup_ft_array2) {
            Write-Host "Open" -ForegroundColor Red
            echo (Get-VMHost | Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Format-Table -AutoSize)
        } else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }
    }
}
write-host ""
write-host "------------ V-256422 ------------"
foreach ($vmhosts in (Get-VMHost)) {
    $vswitch_ft3 = (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($vswitch_ft3 -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } else {
        $vswitch_ft_array3 = (@(Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy).AllowPromiscuous)
        $vportgroup_ft_array3 = (@(Get-VMHost | Get-VirtualPortGroup -Standard | Get-SecurityPolicy).AllowPromiscuous)       
        if ("True" -in $vswitch_ft_array3){
            Write-Host "Open" -ForegroundColor Red
            echo (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy | Format-Table -AutoSize)
        }
        if ("True" -in $vportgroup_ft_array3) {
            Write-Host "Open" -ForegroundColor Red
            echo (Get-VMHost | Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Format-Table -AutoSize)
        } else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }
    }
}
write-host ""
write-host "------------ V-256423 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $dvfilter = (Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress).Value
    if ($dvfilter -eq "") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Validate the IP address and ensure it's tied to a Security Appliance, otherwise this is Open"
        Write-Output $dvfilter
    }
}
write-host ""
write-host "------------ V-256424 ------------"
foreach ($vmhosts in (Get-VMHost)) {
    $vswitch_ft4 = (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($vswitch_ft4 -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } else {
        $vportgroup_2 = (@(Get-VirtualPortGroup -Standard | Select-Object Name,VLanId).VLanID)
        if (("1" -in $vportgroup_2) -or ("0" -in $vportgroup_2)) {
            Write-Host "Open" -ForegroundColor Red
            Write-Output $vportgroup_2
        }
        else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }        }
}
write-host ""
write-host "------------ V-256425 ------------"
foreach ($vmhosts in (Get-VMHost)) {
    $vswitch_ft5 = (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($vswitch_ft5 -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } else {
        $vportgroup_3 = (@(Get-VirtualPortGroup -Standard | Select-Object Name,VLanId).VLanID)
        if ("4095" -in $vportgroup_3) {
            Write-Host "Open" -ForegroundColor Red
            Write-Output $vportgroup_3
        }
        else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }        }
}
write-host ""
