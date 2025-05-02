#****************************************************************
#*************Written By Mitchell Gibson USACPB CRIA*************
#*************Last Updated May 02, 2025 v1.0*********************
#****************************************************************

Write-Host "This script relies on PuTTY to be installed to perform the shell checks, if PuTTY is not installed those checks will error out but the script will continue to run"
Write-Host ""
#Start of Script

#Get Host Information for individual ESXi host
Write-Host "Host Name = "(Get-VMHost| Select-Object Name).Name
Write-Host "IP Address = "(Get-VMHost| Get-VMHostNetworkAdapter | Where-Object {$_.Name -eq "vmk0"} | Select-Object IP).IP
Write-Host "MAC Address = "(Get-VMHost| Get-VMHostNetworkAdapter | Where-Object {$_.Name -eq "vmk0"} | Select-Object Mac).Mac
Write-Host "FQDN = "(Get-VMHost| Select-Object @{N="FQDN";E={$_.NetworkInfo.HostName + "." + $_.NetworkInfo.DomainName}}).FQDN
Write-Host "Target Data = Member Server"
Write-Host "Technology Area = Other Review"
write-host ""

# Check if plink.exe command can be found
$plinkCommand = Get-Command plink.exe -ErrorAction SilentlyContinue

$ssh_cabability = $false
if ($plinkCommand) {
    Write-Host "plink.exe detected at: $($plinkCommand.Source)"
    $ssh_cabability = $true
} else {
    Write-Host "plink.exe not found in the system PATH." -ForegroundColor Yellow
    Write-Host "Skipping SSH checks, will have to be performed manually."
    $ssh_cabability = $false
}

if ($ssh_cabability -eq $true) {
    #Get Credentials to enable ssh into ESXi shell utilizing PuTTY's Plink protocol
    Write-host "Provide root credentials for ESXi Shell; Remember to allow SSH"
    $SSh_creds = Get-Credential -Credential root
    $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($SSh_creds.Password)
    $result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)    
}

#Start of the Checks
$VMhosts = Get-VMHost

$ssh_reachable = $false
if ($ssh_cabability -eq $true) {
    foreach ($VMhost in $VMhosts) {
        $output = & plink.exe $VMhost -batch exit 2>&1
        if ($output -match "Connection refused") {
            Write-Host "SSH Connection seems unreachable, check if the service is enabled or username/password" -ForegroundColor Yellow
            $ssh_reachable = $false
        } else {
            $ssh_reachable = $true
        }
    }
} else {
    $ssh_reachable = $false
}

write-host "------------ V-258728 ------------"
foreach ($VMhost in $VMhosts) {
    $three_invalid = ($VMhost| sort-object name | Get-AdvancedSetting -Name Security.AccountLockFailures).value
    if ($three_invalid -eq 3) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $three_invalid | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258729 ------------"
foreach ($VMhost in $VMhosts) {
    $banner = ($VMhost| sort-object name| Get-AdvancedSetting -Name Annotations.WelcomeMessage).value
    if ($banner -like "* You are accessing a U.S. Government*") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $banner | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258730 ------------"
foreach ($VMhost in $VMhosts) {
    $lockdown = ($VMhost| Select-Object Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}).Lockdown
    if ($lockdown -eq ("lockdownNormal" -or "lockdownStrict")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $lockdown | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258731 ------------"
foreach ($VMhost in $VMhosts) {
    $fifteen_min = ($VMhost| sort-object name| Get-AdvancedSetting -Name Security.AccountUnlockTime).value
    if ($fifteen_min -eq 900) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $fifteen_min | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "----------- V-258732 -------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.security.fips140.ssh.get.invoke()).Enabled
    if ($esxi_host2 -eq "true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258733 ------------"
foreach ($VMhost in $VMhosts) {
    $info = ($VMhost| sort-object name | Get-AdvancedSetting -Name Config.HostAgent.log.level).value
    if ($info -eq "info") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $info | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258734 ------------"
foreach ($VMhost in $VMhosts) {
    $complex_p = ($VMhost| Get-AdvancedSetting -Name Security.PasswordQualityControl).value
    if ($complex_p -eq "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $complex_p | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258735 ------------"
foreach ($VMhost in $VMhosts) {
    $password_h = ($VMhost| Get-AdvancedSetting -Name Security.PasswordHistory).value
    if ($password_h -eq 5) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $password_h | Format-Table -AutoSize | Out-String | Write-Host
    }
 }
write-host ""
write-host "------------ V-258736 ------------"
foreach ($VMhost in $VMhosts) {
    $mob_disable = ($VMhost| Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob).value
    if ($mob_disable -eq "True") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $mob_disable | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
 }
write-host ""
write-host "------------ V-258737 ------------"
foreach ($VMhost in $VMhosts) {
    $AD_authentication = ($VMhost| Get-VMHostAuthentication).Domain;
    if ($null -eq $AD_authentication) {
        Write-Host "AD Authentication is not set"
        Write-Host "Only Root and service accounts should be listed"
        Write-Host "If any account listed isn't a local service or root account this will be open; otherwise this will be Not Applicable"
        $esxcli_other = Get-EsxCli -VMHost $VMhost -V2
        $user_output = ($esxcli_other.system.account.list.Invoke())
        Write-Host ""
        Write-Output $user_output | Format-Table -AutoSize | Out-String | Write-Host
    }
    if ($AD_authentication -eq "Active Directory") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } if ($AD_authentication -like ".*") {
        Write-Host "Open" -ForegroundColor Red
    }
}
write-host ""
write-host "------------ V-258738 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ignorerhosts'}).Value
    if ($esxi_host2 -eq "yes") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258739 ------------"
foreach ($VMhost in $VMhosts) {
    $shell_time = ($VMhost| Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut).Value
    if ($shell_time -le 900 -and $shell_time -ne 0) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_time | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258740 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.settings.encryption.get.invoke() | Select RequireSecureBoot).RequireSecureBoot
    if ($esxi_host2 -eq "true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258741 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (((Get-VMHost).ExtensionData.Capability).UefiSecureBoot)
    if ($esxi_host2 -eq "true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258742 ------------"
foreach ($VMhost in $VMhosts) {
    $shell_time = ($VMhost| Get-AdvancedSetting -Name Security.AccountUnlockTime).Value
    if ($shell_time -le 900 -and $shell_time -ne 0) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_time | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258743 ------------"
foreach ($VMhost in $VMhosts) {
    $shell_time = ($VMhost| Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity).Value
    if ($shell_time -eq 100) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_time | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258744 ------------"
foreach ($VMhost in $VMhosts) {
    $central_logging = (Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost).value
    if ([string]::IsNullOrEmpty($central_logging)) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $central_logging | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "No Syslog destination specified"
    } else {
        Write-Host "Not a Finding after validation logs are being sent to listed remote server(s)" -ForegroundColor Green
        Write-Output $central_logging | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258745 ------------"
foreach ($VMhost in $VMhosts) {
    $ntp = ($VMhost | Get-VMHostNtpServer)
    $ntp_policy = ($VMhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"}).Policy
    $ntp_running = ($VMhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"}).Running
    if ($ntp -eq $null) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "No NTP server configured"
    } 
    else {
        Write-Host "Validate these are DoD NTP servers"
        Write-Output $ntp | Format-Table -AutoSize | Out-String | Write-Host
        if (($ntp_policy -eq "on") -and ($ntp_running -eq "True")) {
        Write-Host "Not a Finding" -ForegroundColor Green
        }
        if (($ntp_policy -ne "on") -or ($ntp_running -ne "True")) {
            Write-Host "Open" -ForegroundColor Red
            Write-Host $ntp_policy | Format-Table -AutoSize | Out-String | Write-Host
        }
    }
}
write-host ""
write-host "------------ V-258746 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -V2)
    $esxi_host2 = $esxi_host.software.acceptance.get.Invoke()
    if ($esxi_host2 -eq "CommunitySupported") {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    } 
    else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258747 ------------"
foreach ($VMhost in $VMhosts) {
    $iscsi = ($VMhost| sort-object name | Get-VMHostHba | Where-Object {$_.Type -like "*iscsi*"} | Select-Object AuthenticationProperties -ExpandProperty AuthenticationProperties)
    if ($iscsi -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "iSCSI not detected"
    }
    else { 
        if ($iscsi.ChapType -ne "required") {
            Write-Host "Open" -ForegroundColor Red
            Write-Output $iscsi | Format-Table -AutoSize | Out-String | Write-Host
        if ($iscsi.ChapType -eq "required") { 
            Write-Host "Not a Finding" -ForegroundColor Green}}}
}
write-host ""
write-host "------------ V-258748 ------------"
foreach ($VMhost in $VMhosts) {
    $vCenterIp = $VMhost.ExtensionData.Summary.ManagementServerIp
    if ([string]::IsNullOrEmpty($vCenterIp)) {
        Write-Host "Not Applicable, No Vcenter being used" -ForegroundColor Gray
    }
    else {
        $vmks = Get-VMHostNetworkAdapter -VMHost $VMhost -VMKernel
        if (-not $vmks) {
             Write-Host "Warning: Could not retrieve VMkernel adapters, will have to perform manually." -ForegroundColor Yellow
             continue 
        }
        $foundCombinedService = $false
        foreach ($vmk in $vmks) {
            if ($vmk.VMotionEnabled -eq $true -and
               ($vmk.FaultToleranceLoggingEnabled -eq $true -or
                $vmk.ManagementTrafficEnabled -eq $true -or
                $vmk.VSphereBackupNFCEnabled -eq $true -or
                $vmk.VSphereReplicationEnabled -eq $true -or
                $vmk.VSphereReplicationNFCEnabled -eq $true -or
                $vmk.ProvisioningEnabled -eq $true -or
                $vmk.VsanTrafficEnabled -eq $true)) {
                Write-Host "Open: VMkernel adapter '$($vmk.DeviceName)' has vMotion enabled with other services"  -ForegroundColor Red
                Write-Output $vmk | Format-Table -AutoSize | Out-String | Write-Host
                $foundCombinedService = $true
            }
        }
        if (-not $foundCombinedService) {
             Write-Host "Not a Finding" -ForegroundColor Green
        }
        $vmotionVlanId = $null
        foreach ($vmkAdapter in $vmks) {
            if ($vmkAdapter.VMotionEnabled -eq $true) {
                try {
                    $portGroup = Get-VirtualPortGroup -VMHost $VMhost -Name $vmkAdapter.PortGroupName 
                    $vmotionVlanId = $portGroup.VLanId
                    Write-Host "Found vMotion enabled on '$($vmkAdapter.DeviceName)' in PortGroup '$($vmkAdapter.PortGroupName)' with VLAN ID: $vmotionVlanId"
                    if ($globalVmotionVlanId -eq $null) {
                        $globalVmotionVlanId = $vmotionVlanId
                    } elseif ($globalVmotionVlanId -ne $vmotionVlanId) {
                         Write-Warning "Multiple different vMotion VLAN IDs detected ($globalVmotionVlanId, $vmotionVlanId). Review configuration."
                    }
                } catch {
                    Write-Warning "Could not retrieve PortGroup '$($vmkAdapter.PortGroupName)' or its VLAN ID for VMkernel '$($vmkAdapter.DeviceName)'. Error: $($_.Exception.Message)"
                }
            }
        }
    }
}
Write-Host ""
write-host "------------ V-258750 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ciphers'}).Value
    if ($esxi_host2 -eq "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "This could still be NF if it is just out of order, if there are extra ciphers it will be a finding"
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258751 ------------"
foreach ($VMhost in Get-VMHost) {
    $vCenterIp = $VMhost.ExtensionData.Summary.ManagementServerIp
    if ([string]::IsNullOrEmpty($vCenterIp)) {
        Write-Host "Not Applicable, No Vcenter being used" -ForegroundColor Gray
    }
    else {
    $vcenter_check = ([uri]$VMhost.ExtensionData.Client.ServiceUrl).Host
    $vcenterIpAddress2 = $VMhost.ExtensionData.Summary.ManagementServerIp
    $DCUIaccess = (Get-AdvancedSetting -Entity $VMhost -Name "DCUI.Access").Value
    if ($vcenter_check -eq $vcenterIpAddress2) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No VCenter being used"
    } 
    else {
        if ($DCUIaccess -eq "root") {
            Write-Host "Not a Finding" -ForegroundColor Green
        } 
        else {
            Write-Host "Open" -ForegroundColor Red
            Write-Output $DCUIaccess | Format-Table -AutoSize | Out-String | Write-Host
        }
    }
}
}
write-host ""
write-host "------------ V-258752 ------------"
foreach ($VMhost in $VMhosts) {
    $ssh_banner = ($VMhost| sort-object name | Get-AdvancedSetting -Name Config.Etc.issue).value
    if ($ssh_banner -like "*You are accessing a U.S. Government*") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $ssh_banner | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258753 ------------"
foreach ($VMhost in $VMhosts) {
    $esxcli2 = Get-EsxCli -v2
    $ssh_banner = ($esxcli2.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'banner'}).value
    if ($ssh_banner -ne "/etc/issue") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $ssh_banner | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258754 ------------"
foreach ($VMhost in $VMhosts) {
    $ssh_stop = ($VMhost| Get-VMHostService | Where-Object{$_.Label -eq "SSH"}).Running
    if ($ssh_stop -eq "True") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $ssh_stop | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "If SSH was enabled for the completion of this script change to Not a Finding"
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258755 ------------"
foreach ($VMhost in $VMhosts) {
    $shell_stop = ($VMhost| Get-VMHostService | Where-Object{$_.Label -eq "ESXi Shell"}).Running
    if ($shell_stop -eq "True") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_stop | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258756 ------------"
foreach ($VMhost in $VMhosts) {
    $shell_time2 = ($VMhost| Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut).Value
    if ($shell_time2 -ne "600") {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_time2 | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258757 ------------"
foreach ($VMhost in $VMhosts) {
    $dcui_time = ($VMhost| Get-AdvancedSetting -Name UserVars.DcuiTimeOut).Value
    if (($dcui_time -gt "600") -or ($dcui_time -eq "0")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $dcui_time | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258758 ------------"
foreach ($VMhost in $VMhosts) {
    $vmks = Get-VMHostNetworkAdapter -VMHost $VMhost -VMKernel
    $foundCombinedService = $false
    foreach ($vmk in $vmks) {
        if ($vmk.ManagementTrafficEnabled -eq $true -and
           ($vmk.FaultToleranceLoggingEnabled -eq $true -or
            $vmk.VMotionEnabled -eq $true -or
            $vmk.VSphereBackupNFCEnabled -eq $true -or
            $vmk.VSphereReplicationEnabled -eq $true -or
            $vmk.VSphereReplicationNFCEnabled -eq $true -or
            $vmk.ProvisioningEnabled -eq $true -or
            $vmk.VsanTrafficEnabled -eq $true)) {
            Write-Host "Open: VMkernel adapter '$($vmk.DeviceName)' has Management enabled with other services" -ForegroundColor Red
            Write-Output $vmk | Format-Table -AutoSize | Out-String | Write-Host
            $foundCombinedService = $true
        }
        }
    if (-not $foundCombinedService) {
         Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258759 ------------"
Write-host "If IP-Based storage is NOT in use this is Not Applicable"
write-host "For each IP-Based storage VMkernel, make sure there are no services running except for the vSAN service"
Write-host "Also make sure all IP-Based storage are isolated from other Vlans"
write-host ""
foreach ($VMhost in $VMhosts) {
    (Get-VirtualPortGroup -VMHost $vmhost -Standard | Select-Object Name,VLanID | Format-Table -AutoSize) | Format-Table -AutoSize | Out-String | Write-Host
    (Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop | Select-Object Name,PortGroupName,VsanTrafficEnabled,ProvisioningEnabled,VSphereReplicationEnabled,VSphereReplicationNFCEnabled,VSphereBackupNFCEnabled,ManagementTrafficEnabled,FaultToleranceLoggingEnabled,VMotionEnabled) | Format-Table -AutoSize | Out-String | Write-Host
}
write-host ""
write-host "------------ V-258760 ------------"
foreach ($VMhost in $VMhosts) {
    $vCenterIp = $VMhost.ExtensionData.Summary.ManagementServerIp
    if ([string]::IsNullOrEmpty($vCenterIp)) {
        Write-Host "Not Applicable, No Vcenter being used" -ForegroundColor Gray
    } else { 
        Write-host "Validate these are authorized lockdown users with documentation (if none; Not a Finding)"
        $lockdown = $VMhost| Get-View
        $lockdown2 = Get-View $lockdown.ConfigManager.HostAccessManager
        $lockdown_output = $lockdown2.QueryLockdownExceptions()
        Write-Output $lockdown_output | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258761 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'hostbasedauthentication'}).Value
    if ($esxi_host2 -eq "no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258762 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permituserenvironment'}).Value
    if ($esxi_host2 -eq "no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258763 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'gatewayports'}).Value
    if ($esxi_host2 -eq "no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258764 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permittunnel'}).Value
    if ($esxi_host2 -eq "no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258765 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientalivecountmax'}).Value
    if ($esxi_host2 -eq "3") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258766 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientaliveinterval'}).Value
    if ($esxi_host2 -eq "200") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258767 ------------"
foreach ($VMhost in $VMhosts) {
    $snmp_enabled = (Get-VMHostSnmp).enabled
    if ($snmp_enabled -eq $False) {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Manual Check, ask how they are utilizing SNMP via Documentation" -ForegroundColor Yellow
        Write-Host $snmp_enabled | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258768 ------------"
foreach ($VMhost in $VMhosts) {
    $mem_share = ($VMhost| Get-AdvancedSetting -Name Mem.ShareForceSalting).Value
    if ($mem_share -eq "2") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $mem_share | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258769 ------------"
foreach ($VMhost in $VMhosts) {
    $default_block = ($VMhost| Get-VMHostFirewallDefaultPolicy)
    $default_block_i = ($VMhost| Get-VMHostFirewallDefaultPolicy).IncomingEnabled
    $default_block_o = ($VMhost| Get-VMHostFirewallDefaultPolicy).OutgoingEnabled
    if (($default_block_i -eq "True") -or ($default_block_o -eq "True")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $default_block | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258770 ------------"
foreach ($VMhost in $VMhosts) {
    $bdpu = ($VMhost| Get-AdvancedSetting -Name Net.BlockGuestBPDU).Value
    if ($bdpu -eq "1") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $bdpu | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258771 ------------"
foreach ($VMhost in $VMhosts) {
    $vswitch_ft = ($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($vswitch_ft -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } 
    else {
        $vswitch_ft_array = (@($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy).ForgedTransmits)
        $vportgroup_ft_array = (@($VMhost| Get-VirtualPortGroup -Standard | Get-SecurityPolicy).ForgedTransmits)       
        if ("True" -in $vswitch_ft_array){
            Write-Host "Open" -ForegroundColor Red
            Write-Output ($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy | Format-Table -AutoSize) | Format-Table -AutoSize | Out-String | Write-Host
        }
        if ("True" -in $vportgroup_ft_array) {
            Write-Host "Open" -ForegroundColor Red
            Write-Output ($VMhost| Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Format-Table -AutoSize) | Format-Table -AutoSize | Out-String | Write-Host
        } 
        else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }
    }
}
write-host ""
write-host "------------ V-258772 ------------"
foreach ($VMhost in $VMhosts) {
    $vswitch_ft2 = ($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($vswitch_ft2 -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } else {
        $vswitch_ft_array2 = (@($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy).MacChanges)
        $vportgroup_ft_array2 = (@($VMhost| Get-VirtualPortGroup -Standard | Get-SecurityPolicy).MacChanges)       
        if ("True" -in $vswitch_ft_array2){
            Write-Host "Open" -ForegroundColor Red
            Write-Output ($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy | Format-Table -AutoSize) | Format-Table -AutoSize | Out-String | Write-Host
        }
        if ("True" -in $vportgroup_ft_array2) {
            Write-Host "Open" -ForegroundColor Red
            Write-Output ($VMhost| Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Format-Table -AutoSize) | Format-Table -AutoSize | Out-String | Write-Host
        } else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }
    }
}
write-host ""
write-host "------------ V-258773 ------------"
foreach ($VMhost in $VMhosts) {
    $vswitch_ft3 = ($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($vswitch_ft3 -eq $null) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } else {
        $vswitch_ft_array3 = (@($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy).AllowPromiscuous)
        $vportgroup_ft_array3 = (@($VMhost| Get-VirtualPortGroup -Standard | Get-SecurityPolicy).AllowPromiscuous)       
        if ("True" -in $vswitch_ft_array3){
            Write-Host "Open" -ForegroundColor Red
            Write-Output ($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy | Format-Table -AutoSize) | Format-Table -AutoSize | Out-String | Write-Host
        }
        if ("True" -in $vportgroup_ft_array3) {
            Write-Host "Open" -ForegroundColor Red
            Write-Output ($VMhost| Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Format-Table -AutoSize) | Format-Table -AutoSize | Out-String | Write-Host
        } else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }
    }
}
write-host ""
write-host "------------ V-258774 ------------"
foreach ($VMhost in $VMhosts) {
    $dvfilter = ($VMhost| Get-AdvancedSetting -Name Net.DVFilterBindIpAddress).Value
    if ($dvfilter -eq "") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Validate the IP address and ensure it's tied to a Security Appliance, otherwise this is Open"
        Write-Output $dvfilter | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258775 ------------"
foreach ($VMhost in $VMhosts) {
    $vswitch_ft5 = ($VMhost| Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($null -eq $vswitch_ft5) {
        Write-Host "Not Applicable" -ForegroundColor Gray
        Write-Host "No Standard VSwitches are in Use"
    } else {
        $vportgroup_3 = (@(Get-VirtualPortGroup -Standard | Select-Object Name,VLanId).VLanID)
        if ("4095" -in $vportgroup_3) {
            Write-Host "Open" -ForegroundColor Red
            Write-Output $vportgroup_3 | Format-Table -AutoSize | Out-String | Write-Host
        }
        else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }        }
}
write-host ""
write-host "------------ V-258776 ------------"
if ($ssh_cabability -eq $false) {
    Write-Host "Putty not installed, will have to perform manually" -ForegroundColor Yellow
}
elseif ($ssh_reachable -eq $false) {
    Write-Host "SSH not reachable (turn on service), will have to perform manually" -ForegroundColor Yellow
}
else {
    foreach ($VMHost in $VMhosts) {
        $plink_output_array = plink.exe "$VMHost" -l root -pw "$result" -batch "vmware -v" 2>&1
            $filtered_lines = $plink_output_array | Where-Object {
                ($_ -notmatch "Keyboard-interactive authentication prompts") -and
                ($_ -notmatch "End of keyboard-interactive prompts") -and
                ($_ -notmatch "Warning: Permanently added")
            }
            $final_output_line = ""
            if ($filtered_lines -ne $null -and $filtered_lines.Count -gt 0) {
                $relevant_line_object = $filtered_lines | Where-Object { $_.Trim() -ne '' } | Select-Object -Last 1
                if ($relevant_line_object -ne $null) {
                    $final_output_line = $relevant_line_object.ToString().Trim()
                }
            }
        Write-Host $final_output_line | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "Compare to listed website:"
        Write-Host "https://kb.vmware.com/s/article/2143832"   
    }
}
write-host "------------ V-258777 ------------"
foreach ($VMhost in $VMhosts) {
    $shell_warning = (($VMhost| Get-AdvancedSetting -Name UserVars.SuppressShellWarning).value)
    if ($shell_warning -eq "0") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $shell_warning | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258778 ------------"
foreach ($VMhost in $VMhosts) {
    $hyperthread_warning = (($VMhost| Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning).value)
    if ($hyperthread_warning -eq "0") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $hyperthread_warning | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258779 ------------"
foreach ($VMhost in $VMhosts) {
    $logHostSetting = $VMhost | Get-AdvancedSetting -Name Syslog.global.logHost -ErrorAction SilentlyContinue
    $syslogssl_check = $logHostSetting.Value 
    if ($syslogssl_check -notlike "ssl://*") {
        Write-Host "Not Applicable" -ForegroundColor Gray
    }
    else {
        $ssl_syslog_value = ($VMhost | Get-AdvancedSetting -Name Syslog.global.certificate.checkSSLCerts).value
        if ($ssl_syslog_value -eq 'true') {
             Write-Host "Not a Finding" -ForegroundColor Green
        }
        else {
            Write-Host "Open" -ForegroundColor Red
            Write-Host $ssl_syslog_value | Format-Table -AutoSize | Out-String | Write-Host
        }
    }
}
write-host ""
write-host "------------ V-258780 ------------"
foreach ($VMhost in $VMhosts) {
    $mem_mem = ($VMhost| Get-AdvancedSetting -Name Mem.MemEagerZero).value
    if ($mem_mem -eq "1") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $mem_mem | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258781 ------------"
foreach ($VMhost in $VMhosts) {
    $vsphere_api = ($VMhost| Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout).value
    if ($vsphere_api -eq "30") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $vsphere_api | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258782 ------------"
foreach ($VMhost in $VMhosts) {
    $max_pass = ($VMhost| Get-AdvancedSetting -Name Security.PasswordMaxDays).value
    if ($max_pass -eq "90") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $max_pass | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258783 ------------"
foreach ($VMhost in $VMhosts) {
    $disable_cim_policy = (($VMhost| Get-VMHostService | Where-Object {$_.Label -eq "CIM Server"}).Policy)
    $disable_cim_running = (($VMhost| Get-VMHostService | Where-Object {$_.Label -eq "CIM Server"}).Running)
    if (($disable_cim_policy -eq "on") -or ($disable_cim_running -eq "True")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host (($VMhost| Get-VMHostService | Where-Object {$_.Label -eq "CIM Server"})) | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host $disable_cim_policy | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host $disable_cim_running | Format-Table -AutoSize | Out-String | Write-Host  
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258784 ------------"
foreach ($VMHost in Get-VMHost) {
    $certMgr = Get-View -Id $VMHost.ExtensionData.ConfigManager.CertificateManager
    $CertIssuer = $certMgr.CertificateInfo.Issuer
    $CertExpiration = $certMgr.CertificateInfo.NotAfter
    if ($CertExpiration -lt (Get-Date)) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "Certificate has Expired"
        Write-Host $CertExpiration | Format-Table -AutoSize | Out-String | Write-Host
    }   
    if ($CertIssuer -notlike "*Government*") {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "Not a valid certificate"
        Write-Output $CertMgr.certificateInfo | Format-Table -AutoSize | Out-String | Write-Host
    }
    else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258785 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'allowtcpforwarding'}).Value
    if ($esxi_host2 -eq "no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258786 ------------"
foreach ($VMhost in $VMhosts) {
    $slpd = ($VMhost| Get-VMHostService | Where-Object {$_.Label -eq "slpd"})
    $slpd_policy = (($VMhost| Get-VMHostService | Where-Object {$_.Label -eq "slpd"}).Policy)
    $slpd_running = (($VMhost| Get-VMHostService | Where-Object {$_.Label -eq "slpd"}).Running)
    if (($slpd_policy -match "on") -or ($slpd_running -match "True")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $slpd | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258787 ------------"
foreach ($VMhost in $VMhosts) {
    $audit_logging = ($VMhost| Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable).value
    if ($audit_logging -eq "true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $audit_logging | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258788 ------------"
foreach ($VMhost in $VMhosts) {
    $remote_audit = ($VMhost| Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable).value
    if ($remote_audit -eq "true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $remote_audit | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258789 ------------"
foreach ($VMhost in $VMhosts) {
    $logHostSetting = $VMhost | Get-AdvancedSetting -Name Syslog.global.logHost -ErrorAction SilentlyContinue
    $syslogssl_check = $logHostSetting.Value 
    if ($syslogssl_check -notlike "ssl://*") {
        Write-Host "Not Applicable, syslog enpoint is not being used." -ForegroundColor Gray
    }
    else {
        $ssl_syslog_value = ($VMhost | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance -ErrorAction SilentlyContinue).value
        if ($ssl_syslog_value -eq 'True') {
             Write-Host "Not a Finding" -ForegroundColor Green
        }
        else {
            Write-Host "Open" -ForegroundColor Red
            Write-Host $ssl_syslog_value | Format-Table -AutoSize | Out-String | Write-Host
        }
    }
}
write-host ""
write-host "------------ V-258790 ------------"
foreach ($VMhost in $VMhosts) {
    $info = ($VMhost| Get-AdvancedSetting -Name Syslog.global.logLevel).value
    if ($info -eq "info") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $info | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258791 ------------"
if ($ssh_cabability -eq $false) {
    Write-Host "Putty not installed, will have to perform manually" -ForegroundColor Yellow
}
elseif ($ssh_reachable -eq $false) {
    Write-Host "SSH not reachable (turn on service), will have to perform manually" -ForegroundColor Yellow
}
else {
    foreach ($VMhost in $VMhosts) {
            $plink_output_array = plink.exe "$VMHost" -l root -pw "$result" -batch "stat -c "%s" /etc/vmware/settings" 2>&1
            $filtered_lines = $plink_output_array | Where-Object {
                ($_ -notmatch "Keyboard-interactive authentication prompts") -and
                ($_ -notmatch "End of keyboard-interactive prompts") -and
                ($_ -notmatch "Warning: Permanently added")
            }
            $final_output_line = ""
            if ($filtered_lines -ne $null -and $filtered_lines.Count -gt 0) {
                $relevant_line_object = $filtered_lines | Where-Object { $_.Trim() -ne '' } | Select-Object -Last 1
                if ($relevant_line_object -ne $null) {
                    $final_output_line = $relevant_line_object.ToString().Trim()
                }
            }
            if ($final_output_line -eq "0") {
                Write-Host "Not a Finding" -ForegroundColor Green
            } else {
                Write-Host "Open" -ForegroundColor Red
                Write-Host $final_output_line | Format-Table -AutoSize | Out-String | Write-Host
            }
        }
}
write-host ""
write-host "------------ V-258792 ------------"
if ($ssh_cabability -eq $false) {
    Write-Host "Putty not installed, will have to perform manually" -ForegroundColor Yellow
}
elseif ($ssh_reachable -eq $false) {
    Write-Host "SSH not reachable (turn on service), will have to perform manually" -ForegroundColor Yellow
}
else {
    foreach ($VMhost in $VMhosts) {
            $plink_output_array = plink.exe "$VMHost" -l root -pw "$result" -batch "grep "^vmx\.log" /etc/vmware/config" 2>&1
            $filtered_lines = $plink_output_array | Where-Object {
                ($_ -notmatch "Keyboard-interactive authentication prompts") -and
                ($_ -notmatch "End of keyboard-interactive prompts") -and
                ($_ -notmatch "Warning: Permanently added")
            }
            $final_output_line = ""
            if ($filtered_lines -ne $null -and $filtered_lines.Count -gt 0) {
                $relevant_line_object = $filtered_lines | Where-Object { $_.Trim() -ne '' } | Select-Object -Last 1
                if ($relevant_line_object -ne $null) {
                    $final_output_line = $relevant_line_object.ToString().Trim()
                }
            }
            if ($final_output_line -eq $null) {
                Write-Host "Not a Finding" -ForegroundColor Green
            } else {
                Write-Host "Open" -ForegroundColor Red
                Write-Host $final_output_line | Format-Table -AutoSize | Out-String | Write-Host
            }
        }
    }
write-host ""
write-host "------------ V-258793 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.settings.encryption.get.invoke() | Select Mode).Value
    if ($esxi_host2 -eq "TPM") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host " If the ESXi host does not have a compatible TPM, this finding is downgraded to a CAT III."
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258794 ------------"
foreach ($VMhost in $VMhosts) {
    $firewall_array = @(($VMhost | Get-VMHostFirewallException | Where {($_.Enabled -eq $true) -and ($_.ExtensionData.IpListUserConfigurable -eq $true)} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}},@{N="AllIPUserConfigurable";E={$_.ExtensionData.IpListUserConfigurable}}).AllIPEnabled)
    $firewall_stig = ($VMhost | Get-VMHostFirewallException | Where {($_.Enabled -eq $true) -and ($_.ExtensionData.IpListUserConfigurable -eq $true)} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}},@{N="AllIPUserConfigurable";E={$_.ExtensionData.IpListUserConfigurable}})
    $isopen = $false
    foreach ($rule in $firewall_array) {
        if ($rule -eq $true) {
            $isopen = $true 
            break
        }
    }
    if ($isopen -eq 1) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output (Get-VMHost | Get-VMHostFirewallException | Where {($_.Enabled -eq $true) -and ($_.ExtensionData.IpListUserConfigurable -eq $true)} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}},@{N="AllIPUserConfigurable";E={$_.ExtensionData.IpListUserConfigurable}}) | Format-Table -AutoSize | Out-String | Write-Host
        }
    else {
        Write-Host "Not a Finding" -ForegroundColor Green
        }
}
write-host ""
write-host "------------ V-258795 ------------"
foreach ($VMhost in $VMhosts) {
    $vCenterIp = $VMhost.ExtensionData.Summary.ManagementServerIp
    if ([string]::IsNullOrEmpty($vCenterIp)) {
        Write-Host "Not Applicable, No vCenter is being used" -ForegroundColor Gray
        break
    }
    else {
        $AD_authentication_info = $VMhost | Get-VMHostAuthentication
        if ($AD_authentication_info -and ![string]::IsNullOrEmpty($AD_authentication_info.Domain)) {
            Write-Host "Not Applicable, AD Authentication Domain found" -ForegroundColor Gray
            break
        }
        else {
            $joinad_enabled = (Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}).JoinADEnabled
            if ($joinad_enabled -eq $true) {
                $joinad_method = (Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}).JoinDomainMethod
                if ($joinad_method -eq "FixedCAMConfigOption") {
                    Write-Host "Open" -ForegroundColor Red
                    Write-Host $joinad_method | Format-Table -AutoSize | Out-String | Write-Host
                    Write-Host $joinad_enabled | Format-Table -AutoSize | Out-String | Write-Host
                    break
                else {
                    Write-Host "Not a Finding" -ForegroundColor Green
                    break
                }
            else {
                Write-Host "Not a Finding" -ForegroundColor Green
                    break
                    }
                }
            }
        }
    }
}
write-host ""
write-host "------------ V-258796 ------------"
foreach ($VMhost in $VMhosts) {
    $AD_authentication = ($VMhost| Get-VMHostAuthentication).Domain;
    if ($null -eq $AD_authentication) {
        Write-Host "Not Applicable, AD Authentication is not set" -ForegroundColor Gray
    }
    else {
        $default_ad = ($VMhost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup).Value
        if ($default_ad -eq "ESX Admins") {
            Write-Host "Open" -ForegroundColor Red
            break
        }
        else {
            Write-Host "Not a Finding" -ForegroundColor Green
        }
    }
}
write-host ""
write-host "------------ V-258797 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $esxi_host2 = ($esxi_host.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent).LocalLogOutputIsPersistent
    if ($esxi_host2 -eq "true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host2 | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258798 ------------"
foreach ($VMhost in $VMhosts) {
    $info = ($VMhost| Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly).value
    if ($info -eq "true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $info | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-258799 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $disable_hwrgn = ($esxi_host.system.settings.kernel.list.invoke() | Where {$_.Name -eq "disableHwrng" }).Runtime
    $entropy = ($esxi_host.system.settings.kernel.list.invoke() | Where {$_.Name -eq "entropysources" }).Runtime
    if (($disable_hwrgn -eq "false") -and ($entropy -eq "0")) {  
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $esxi_host.system.settings.kernel.list.invoke() | Where {$_.Name -eq "disableHwrng" -or $_.Name -eq "entropySources"} | Format-Table -AutoSize | Out-String | Write-Host

    }
}
write-host ""
write-host "------------ V-258800 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $log_filtering = ($esxi_host.system.syslog.config.logfilter.get.invoke()).logfilteringenabled
    if ($log_filtering -eq "false") {  
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $log_filtering | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-265974 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $arguments = $esxi_host.system.tls.server.get.CreateArgs()
    $arguments.showprofiledefaults = $true
    $arguments.showcurrentbootprofile = $true
    $nist = ($esxi_host.system.tls.server.get.invoke($arguments)).Profile
    if ($nist -eq "NIST_2024") {  
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $nist | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-265975 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $tpmm = ($esxi_host.system.security.keypersistence.get.invoke()).Enabled
    if ($tpmm -eq "true") {  
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $tpmm | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "If the ESXi host does not have a compatible TPM, this is not applicable."
    }
}
write-host ""
write-host "------------ V-265976 ------------"
foreach ($VMhost in $VMhosts) {
    $esxi_host = (Get-EsxCli -v2)
    $dcuishell = ($esxi_host.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'}).ShellAccess
    if ($dcuishell -eq "false") {  
        Write-Host "Not a Finding" -ForegroundColor Green
    } 
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $dcuishell | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
write-host "------------ V-265977 ------------"
foreach ($VMhost in $VMhosts) {
    $info = ($VMhost| Get-AdvancedSetting -Name Net.BMCNetworkEnable).value
    if ($info -eq "0") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $info | Format-Table -AutoSize | Out-String | Write-Host
    }
}
write-host ""
