#****************************************************************
#*************Written By Mitchell Gibson USACPB CRIA*************
#*************Last Updated Apr 14, 2025 v1.0*********************
#****************************************************************


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

Write-Host "This script relies on PuTTY to be installed to perform the shell checks, if PuTTY is not installed those checks will error out but the script will continue to run"

#Start of Script

#Get Host Information for individual ESXi host
Write-Host "Host Name = "(get-vmhost | Select-Object Name).Name
Write-Host "IP Address = "(get-vmhost | Get-VMHostNetworkAdapter | Where-Object {$_.Name -eq "vmk0"} | Select-Object IP).IP
Write-Host "MAC Address = "(get-vmhost | Get-VMHostNetworkAdapter | Where-Object {$_.Name -eq "vmk0"} | Select-Object Mac).Mac
Write-Host "FQDN = "(Get-VMHost | Select-Object @{N="FQDN";E={$_.NetworkInfo.HostName + "." + $_.NetworkInfo.DomainName}}).FQDN
Write-Host "Target Data = Member Server"
Write-Host "Technology Area = Other Review"
write-host ""

#Get Credentials to enable ssh into ESXi shell utilizing PuTTY's Plink protocol
Write-host "Provide root credentials for ESXi Shell; Remember to allow SSH"
$SSh_creds = Get-Credential -Credential root
$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($SSh_creds.Password)
$result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)

#Start of the Checks

write-host "------------ V-258728 ------------"

write-host ""
write-host "------------ V-258729 ------------"

write-host ""
write-host "------------ V-258730 ------------"

write-host ""
write-host "------------ V-258731 ------------"

write-host ""
write-host "----------- V-258732 -------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system security fips140 ssh get")
    if ($plink_banner -eq "Enabled: true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258733 ------------"

write-host ""
write-host "------------ V-258734 ------------"

write-host ""
write-host "------------ V-258735 ------------"

write-host ""
write-host "------------ V-258736 ------------"

write-host ""
write-host "------------ V-258737 ------------"

write-host ""
write-host "------------ V-258738 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k ignorerhosts")
    if ($plink_banner -eq "ignorerhosts yes") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258739 ------------"

write-host ""
write-host "------------ V-258740 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system settings encryption get")
    if ($plink_banner -eq "Require Secure Boot: true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "If the ESXi host does not have a compatible TPM, this finding is downgraded to a CAT III."
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258741 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "/usr/lib/vmware/secureboot/bin/secureBoot.py -s")
    if ($plink_banner -eq "Enabled") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258742 ------------"

write-host ""
write-host "------------ V-258743 ------------"

write-host ""
write-host "------------ V-258744 ------------"

write-host ""
write-host "------------ V-258745 ------------"

write-host ""
write-host "------------ V-258746 ------------"

write-host ""
write-host "------------ V-258747 ------------"

write-host ""
write-host "------------ V-258748 ------------"

write-host ""
write-host "------------ V-258750 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k ciphers")
    if ($plink_banner -eq "ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "This could still be NF if it is just out of order, if there are extra ciphers it will be:"
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258751 ------------"

write-host ""
write-host "------------ V-258752 ------------"

write-host ""
write-host "------------ V-258753 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k banner")
    if ($plink_banner -eq "banner /etc/issue") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258754 ------------"

write-host ""
write-host "------------ V-258755 ------------"

write-host ""
write-host "------------ V-258756 ------------"

write-host ""
write-host "------------ V-258757 ------------"

write-host ""
write-host "------------ V-258758 ------------"

write-host ""
write-host "------------ V-258759 ------------"

write-host ""
write-host "------------ V-258760 ------------"

write-host ""
write-host "------------ V-258761 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k hostbasedauthentication")
    if ($plink_banner -eq "hostbasedauthentication no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258762 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k permituserenvironment")
    if ($plink_banner -eq "permituserenvironment no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258763 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k gatewayports")
    if ($plink_banner -eq "gatewayports no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258764 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k permittunnel")
    if ($plink_banner -eq "permittunnel no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258765 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k clientalivecountmax")
    if ($plink_banner -eq "clientalivecountmax 3") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258766 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k clientaliveinterval")
    if ($plink_banner -eq "clientaliveinterval 200") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258767 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_snmp_enable = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system snmp get | grep Enable:")
    if ($plink_snmp_enable -like "*Enable: false") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        $plink_snmp_targets = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system snmp get | grep Targets:")    
        $plink_snmp_v3targets = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system snmp get | grep V3targets::")    
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
write-host "------------ V-258768 ------------"

write-host ""
write-host "------------ V-258769 ------------"
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
write-host "------------ V-258770 ------------"

write-host ""
write-host "------------ V-258771 ------------"

write-host ""
write-host "------------ V-258772 ------------"

write-host ""
write-host "------------ V-258773 ------------"

write-host ""
write-host "------------ V-258774 ------------"

write-host ""
write-host "------------ V-258775 ------------"
foreach ($vmhosts in (Get-VMHost)) {
    $vswitch_ft5 = (Get-VMHost | Get-VirtualSwitch -Standard | Get-SecurityPolicy)
    if ($null -eq $vswitch_ft5) {
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
write-host "------------ V-258776 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_version = (plink "$VMHosts" -l root -pw "$result" -batch "vmware -v")
    Write-Host $plink_version
    Write-Host "Compare to listed website:"
    Write-Host "https://kb.vmware.com/s/article/2143832"   
}
write-host ""
write-host ""
write-host "------------ V-258777 ------------"

write-host ""
write-host "------------ V-258778 ------------"

write-host ""
write-host "------------ V-258779 ------------"
Write-host "If SSL is not used for a syslog target, this is not applicable. Otherwise:"
foreach ($VMhost in (Get-VMHost)) {
    $ssl_syslog = (Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logCheckSSLCerts).value
    if ($ssl_syslog -eq "true") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $ssl_syslog
    }
}
write-host ""
write-host "------------ V-258780 ------------"

write-host ""
write-host "------------ V-258781 ------------"

write-host ""
write-host "------------ V-258782 ------------"

write-host ""
write-host "------------ V-258783 ------------"

write-host ""
write-host "------------ V-258784 ------------"
foreach ($VMHost in Get-VMHost) {
    $certMgr = Get-View -Id $VMHost.ExtensionData.ConfigManager.CertificateManager
    $CertIssuer = $certMgr.CertificateInfo.Issuer
    $CertExpiration = $certMgr.CertificateInfo.NotAfter

    Write-Host "Checking host: $($VMHost.Name)"

    if ($CertExpiration -lt (Get-Date)) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "Certificate has Expired"
        Write-Output $CertExpiration
    }   
    if ($CertIssuer -notlike "*Government*") {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "Not a valid certificate"
        Write-Output $CertIssuer
    }
    else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258785 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system ssh server config list -k allowtcpforwarding")
    if ($plink_banner -eq "allowtcpforwarding no") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258786 ------------"

write-host ""
write-host "------------ V-258787 ------------"

write-host ""
write-host "------------ V-258788 ------------"

write-host ""
write-host "------------ V-258789 ------------"

write-host ""
write-host "------------ V-258790 ------------"

write-host ""
write-host "------------ V-258791 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $plink_banner = (plink "$VMHosts" -l root -pw "$result" -batch "stat -c "%s" /etc/vmware/settings")
    if ($plink_banner -eq "0") {
        Write-Host "Not a Finding" -ForegroundColor Green
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $plink_banner
    }
}
write-host ""
write-host "------------ V-258792 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $ovveride_vm_logger = (plink "$VMHosts" -l root -pw "$result" -batch "grep "^vmx\.log" /etc/vmware/config")
    if ($null -eq $ovveride_vm_logger) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }   
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $ovveride_vm_logger
    }
}
write-host ""
write-host "------------ V-258793 ------------"
foreach ($VMHosts in (Get-VMHost)) {
    $ovveride_vm_logger = (plink "$VMHosts" -l root -pw "$result" -batch "esxcli system settings encryption get")
    if ($ovveride_vm_logger -eq "Mode: TPM") {
        Write-Host "Not a Finding" -ForegroundColor Green
    }   
    else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "If the ESXi host does not have a compatible TPM, this finding is downgraded to a CAT III."
        Write-Output $ovveride_vm_logger
    }
}
write-host ""
write-host "------------ V-258794 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $firewall_allip = (Get-VMHost | Get-VMHostFirewallException | Where-Object {$_.Enabled -eq $true} -and ($_.ExtensionData.IpListUserConfigurable -eq $true) | Select-Object Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}})
    $firewall_2 = (@(Get-VMHost | Get-VMHostFirewallException | Where-Object {$_.Enabled -eq $true}.ExtensionData.AllowedHosts.AllIP -and {$_.Enabled -eq $true}).ExtensionData.IpListUserConfigurable)
    if ("True" -in $firewall_2) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output ($firewall_allip | Format-Table -AutoSize)
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
}
write-host ""
write-host "------------ V-258795 ------------"

write-host ""
write-host "------------ V-258796 ------------"

write-host ""
write-host "------------ V-258797 ------------"

write-host ""
write-host "------------ V-258798 ------------"

write-host ""
write-host "------------ V-258799 ------------"

write-host ""
write-host "------------ V-258800 ------------"

write-host ""
write-host "------------ V-265974 ------------"

write-host ""
write-host "------------ V-265975 ------------"

write-host ""
write-host "------------ V-265976 ------------"

write-host ""
write-host "------------ V-265977 ------------"

write-host ""