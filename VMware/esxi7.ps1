write-host "------------ V-256413 ------------";
Write-host "If IP-Based storage is in use this is Not Applicable"
write-host "For each IP-Based storage VMkernel, make sure there are no services running except for the vSAN service"
Write-host "Also make sure all IP-Based storage are isolated from other Vlans"
foreach ($VMhost in (Get-VMHost)) {
    (Get-VirtualPortGroup -VMHost $vmhost -Standard)
    (Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop | Select Name,PortGroupName,VsanTrafficEnabled,ProvisioningEnabled,VSphereReplicationEnabled,VSphereReplicationNFCEnabled,VSphereBackupNFCEnabled,ManagementTrafficEnabled,FaultToleranceLoggingEnabled,VMotionEnabled)
}
cls
write-host ""
write-host "------------ V-2256375 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $lockdown = (Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}).Lockdown
    if ($lockdown -eq ("lockdownNormal" -or "lockdownStrict")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        echo $lockdown
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
        echo $DCUIaccess
    }
}
write-host ""
write-host "------------ V-256377 ------------"
Write-host "Validate these are authorized lockdown users"
Get-VMHost | sort-object name | %{ write-host `n$_; $vmhost = $_  | Get-View; $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager; $lockdown.QueryLockdownExceptions() }
write-host ""
write-host "------------ V-256378 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $Syslog = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name Syslog.global.logHost).value
    if ($Syslog -eq "") {
        Write-Host "Open" -ForegroundColor Red
        echo "No output"
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
        echo $three_invalid
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
        echo $fifteen_min
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
        echo $banner
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
  write-host "------------ V-256384 ------------"
  foreach ($VMhost in (Get-VMHost)) {
    $esxcli = Get-EsxCli -v2
    $fips = ($esxcli.system.security.fips140.ssh.get.invoke()).Enabled
    if ($fips -eq "True") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        echo $fips
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
        echo $info
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
         echo $complex_p
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
       echo $password_h
   }
}
write-host ""
write-host "------------ V-256399 ------------"
foreach ($VMhost in (Get-VMHost)) {
   $mob_disable = (Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob).value
   if ($mob_disable -eq "True") {
       Write-Host "Open" -ForegroundColor Red
       echo $mob_disable
   } else {
       Write-Host "Not a Finding" -ForegroundColor Green
   }
}
write-host ""
write-host "------------ V-256400 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $ssh_stop = (Get-VMHost | Get-VMHostService | Where{$_.Label -eq "SSH"}).Running
    if ($ssh_stop -eq "True") {
        Write-Host "Open" -ForegroundColor Red
        echo $ssh_stop
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256401 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $shell_stop = (Get-VMHost | Get-VMHostService | Where{$_.Label -eq "ESXi Shell"}).Running
    if ($shell_stop -eq "True") {
        Write-Host "Open" -ForegroundColor Red
        echo $shell_stop
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
        echo $user_output
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
    $join_host_Enabled = ((Get-VMHost | sort-object name | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}})).JoinADEnabled
    $join_domain_method = ((Get-VMHost | sort-object name | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}})).JoinDomainMethod
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
        $esx_admins = ((Get-VMHost | sort-object name | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select @{N='VMHost';E={$_.Entity.Name}},Name,Value)).Value
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
        echo $shell_time
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
        echo $shell_time2
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
        echo $dcui_time
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256408 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $esxcli2 = Get-EsxCli -VMHost $VMhost -V2
    $local_log = $esxcli2.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent
    $local_logp = ($esxcli2.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent).LocalLogOutputIsPersistent
    if ($local_logp -ne "true") {
        Write-Host "Open" -ForegroundColor Red
        echo $local_log
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-256409 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $ntp = (Get-VMHost | Get-VMHostNtpServer)
    $ntp_policy = (Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}).Policy
    $ntp_running = (Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}).Running
    if ($ntp -eq $null) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "No NTP server configured"
    } 
    else {
        Write-Host "Validate these are DoD NTP servers"
        echo $ntp
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
    $vcenter_check = ((Get-VMHost |Select Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).Name
    $other_vcenter_check = ((Get-VMHost |Select Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).vCenter
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
            (Get-VirtualPortGroup -VMHost $_ -Standard | where-object {(($_.Name).contains("vMotion")) -or (($_.Name).contains("VSAN")) -or (($_.Name).contains("Management")) -or (($_.Name).contains("mgmt"))} | Select Name, VLanID)
            write-host ""
        }
    }
write-host ""
write-host "------------ V-256412 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $vcenter_check2 = ((Get-VMHost |Select Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).Name
    $other_vcenter_check2 = ((Get-VMHost |Select Name,@{N='vCenter';E={([uri]$_.ExtensionData.Client.ServiceUrl).host}})).vCenter
    if ($vcenter_check2 -eq $other_vcenter_check) {
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
            (Get-VirtualPortGroup -VMHost $vmhost -Standard | where-object {(($_.Name).contains("vMotion")) -or (($_.Name).contains("VSAN")) -or (($_.Name).contains("Management")) -or (($_.Name).contains("mgmt"))} | Select Name, VLanID)
            write-host ""
        }
    }
write-host ""
write-host "------------ V-256413 ------------";
Write-host "If IP-Based storage is in use this is Not Applicable"
write-host "For each IP-Based storage VMkernel, make sure there are no services running except for the vSAN service"
Write-host "Also make sure all IP-Based storage are isolated from other Vlans"
foreach ($VMhost in (Get-VMHost)) {
    (Get-VirtualPortGroup -VMHost $vmhost -Standard)
    (Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop | Select Name,PortGroupName,VsanTrafficEnabled,ProvisioningEnabled,VSphereReplicationEnabled,VSphereReplicationNFCEnabled,VSphereBackupNFCEnabled,ManagementTrafficEnabled,FaultToleranceLoggingEnabled,VMotionEnabled)
}
write-host ""

write-host "------------ V-256415 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $iscsi = (Get-VMHost | sort-object name | Get-VMHostHba | Where {$_.Type -like "*iscsi*"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties)
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
