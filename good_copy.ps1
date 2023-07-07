write-host "------------ V-2256375 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $lockdown = (Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}).Lockdown
    if ($lockdown -eq ("lockdownNormal" -or "lockdownStrict")) {
        Write-Host "Not a Finding"
    } else {
        Write-Host "Open"
    }
}
write-host ""
write-host "------------ V-256376 ------------";
foreach ($VMhost in (Get-VMHost)) {
    $DCUIaccess = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name DCUI.Access).value
    if ($DCUIaccess -eq "root") {
        Write-Host "Not a Finding"
    } else {
        Write-Host "Open"
    }
}
write-host ""
write-host "------------ V-256377 ------------"
Get-VMHost | sort-object name | %{ write-host `n$_.Name; $vmhost = $_  | Get-View; $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager; $lockdown.QueryLockdownExceptions() }
Write-host "^Validate these are authorized lockdown users^"
write-host ""
write-host "------------ V-256378 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $Syslog = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name Syslog.global.logHost).value
    if ($Syslog -eq "") {
        Write-Host "Open"
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
        Write-Host "Not a Finding"
    } else {
        Write-Host "Open"
    }
}
  write-host ""
  write-host "------------ V-256380 ------------"
  foreach ($VMhost in (Get-VMHost)) {
    $fifteen_min = (Get-VMHost | sort-object name| Get-AdvancedSetting -Name Security.AccountUnlockTime).value
    if ($fifteen_min -eq 900) {
        Write-Host "Not a Finding"
    } else {
        Write-Host "Open"
    }
}
write-host ""
write-host "------------ V-256381 ------------"
foreach ($VMhost in (Get-VMHost)) {
    $banner = (Get-VMHost | sort-object name| Get-AdvancedSetting -Name Annotations.WelcomeMessage).value
    if ($banner -like "* You are accessing a U.S. Government*") {
        Write-Host "Not a Finding"
    } else {
        Write-Host "Open"
    }
}
 write-host ""
 write-host "------------ V-256382 ------------"
 foreach ($VMhost in (Get-VMHost)) {
    $ssh_banner = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name Config.Etc.issue).value
    if ($ssh_banner -like "*You are accessing a U.S. Government*") {
        Write-Host "Not a Finding"
    } else {
        Write-Host "Open"
    }
}
  write-host ""
  write-host "------------ V-256384 ------------"
  foreach ($VMhost in (Get-VMHost)) {
    $esxcli = Get-EsxCli -v2
    $fips = ($esxcli.system.security.fips140.ssh.get.invoke()).Enabled
    if ($fips -eq "True") {
        Write-Host "Not a Finding"
    } else {
        Write-Host "Open"
    }
}
   write-host ""
   write-host "------------ V-256396 ------------"
 foreach ($VMhost in (Get-VMHost)) {
    $info = (Get-VMHost | sort-object name | Get-AdvancedSetting -Name Config.HostAgent.log.level).value
    if ($info -eq "info") {
        Write-Host "Not a Finding"
    } else {
        Write-Host "Open"
    }
}
  write-host ""
  write-host "------------ V-256397 ------------"
  foreach ($VMhost in (Get-VMHost)) {
     $complex_p = (Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl).value
     if ($complex_p -eq "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15") {
         Write-Host "Not a Finding"
     } else {
         Write-Host "Open"
     }
 }
write-host ""
write-host "------------ V-256398 ------------"
foreach ($VMhost in (Get-VMHost)) {
   $password_h = (Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory).value
   if ($password_h -eq 5) {
       Write-Host "Not a Finding"
   } else {
       Write-Host "Open"
   }
}
write-host ""
write-host "------------ V-256399 ------------"
foreach ($VMhost in (Get-VMHost)) {
   $mob_disable = (Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob).value
   if ($mob_disable -eq "True") {
       Write-Host "Open"
   } else {
       Write-Host "Not a Finding"
   }
}
write-host ""
