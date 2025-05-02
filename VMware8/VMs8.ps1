#****************************************************************
#*************Written By Mitchell Gibson USACPB CRIA*************
#*************Last Updated May 02, 2025 v1.1*********************
#****************************************************************


Clear-Host

$numberOfVMs = Read-Host "Enter the number of VMs you want to check"

# Validate user input to ensure it's a positive integer
if (-not [int]::TryParse($numberOfVMs, [ref]$null) -or $numberOfVMs -le 0) {
    Write-Output "Invalid input. Please enter a positive integer."
    Disconnect-VIServer -Confirm:$false
    exit
}

#Start of loop
for ($i = 1; $i -le $numberOfVMs; $i++) {
    $vmName = Read-Host "Enter the name of VM$i to check"

    # Get the VM object from the provided name
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    $networkAdapters = $vm | Get-NetworkAdapter
    
    Write-Host "Hostname:" $vm.Name
    Write-Host "IP Address:" $vm.Guest.IPAddress
    Write-Host "MAC Address:" $networkAdapters.MacAddress
    Write-Host "FQDN:" $vm.Guest.HostName
    Write-Host "Role: Member Server"
    Write-Host "Technology Area: Other Review"
    write-host "------------ V-258703 ------------";
    $example1 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.copy.disable).Value
    if(($example1 -eq $null) -or ($example1 -eq "true")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example1
    }
    write-host ""
    write-host "------------ V-258704 ------------";
    $example2 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.dnd.disable).Value
    if(($example2 -eq $null) -or ($example2 -eq "true")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example2
    }
    write-host ""
    write-host "------------ V-258705 ------------";
    $example3 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.paste.disable).Value
    if(($example3 -eq $null) -or ($example3 -eq "true")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example3
    }
    write-host ""
    write-host "------------ V-258706 ------------";
    $example4 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.diskShrink.disable).Value
    if(($example4 -eq $null) -or ($example4 -eq "true")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example4
    }
    write-host ""
    write-host "------------ V-258707 ------------";
    $example5 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.diskWiper.disable).Value
    if(($example5 -eq $null) -or ($example5 -eq "true")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example5
    }
    write-host ""
    write-host "------------ V-258708 ------------";
    $example6 = (Get-VM $vmName | Get-AdvancedSetting -Name RemoteDisplay.maxConnections).Value
    if(($example6 -eq $null) -or ($example6 -ne "1")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example6
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-258709 ------------";
    $example7 = (Get-VM $vmName | Get-AdvancedSetting -Name tools.setinfo.sizeLimit).Value
    if(($example7 -eq $null) -or ($example7 -eq "1048576")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example7
    }
    write-host ""
    write-host "------------ V-258710 ------------";
    $example8 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.device.connectable.disable).Value
    if(($example8 -eq $null) -or ($example8 -eq "true")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example8
    }
    write-host ""
    write-host "------------ V-258711 ------------";
    $example9 = (Get-VM $vmName | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo).Value
    if(($example9 -eq $null) -or ($example9 -eq "false")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example9
    }
    write-host ""
    write-host "------------ V-258712 ------------";
    $example10 = (Get-VM $vmName | Get-AdvancedSetting -Name sched.mem.pshare.salt).Value
    if($example10 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example10
    }
    write-host ""
    write-host "------------ V-258713 ------------";
    $example11 = (Get-VM $vmName | Get-AdvancedSetting "ethernet*.filter*.name*")
    $dvFiltersInUse = ($vm.ExtensionData.Config.DefaultPortConfig.DistributedVirtualSwitch.DistributedVirtualPort.DvFilterConfig)
    if($example11 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    elseif ($dvFiltersInUse -eq $null) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "DVFilters aren't in use"
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
        Write-Output $example11
    }
    write-host ""
    write-host "------------ V-258714 ------------";
    $example12 = (Get-VM $vmName | Get-AdvancedSetting -Name tools.guest.desktop.autolock).Value
    if(($example12 -eq $null) -or ($example12 -eq "true")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example12
    }
    write-host ""
    write-host "------------ V-258715 ------------";
    $example13 = (Get-VM $vmName | Get-AdvancedSetting -Name mks.enable3d).Value
    if(($example13 -eq $null) -or ($example13 -eq "false")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example13
    }
    write-host ""
    write-host "------------ V-258716 ------------";
    $example14 = (Get-VM | Where-Object {($_.ExtensionData.Config.MigrateEncryption -eq "disabled")})
    if(($example14 -eq "Opportunistic") -or ($example14 -eq "Required")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example14
    }
    write-host ""
    write-host "------------ V-258717 ------------";
    $example15 = (Get-VM | Where-Object {($_.ExtensionData.Config.FtEncryptionMode -ne "ftEncryptionOpportunistic") -and ($_.ExtensionData.Config.FtEncryptionMode -ne "ftEncryptionRequired")})
    if(($example15 -eq "Opportunistic") -or ($example15 -eq "Required")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example15
    }
    write-host ""
    write-host "------------ V-258718 ------------";
    $example16 = (Get-VM $vmName | Get-AdvancedSetting -Name log.rotateSize).Value
    if(($example16 -eq $null) -or ($example16 -eq "2048000")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example16
    }
    write-host ""
    write-host "------------ V-258719 ------------";
    $example17 = (Get-VM $vmName | Get-AdvancedSetting -Name log.keepOld).Value
    if(($example17 -eq $null) -or ($example17 -eq "10")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example17
    }
    write-host ""
    write-host "------------ V-258720 ------------";
    $example18 = (Get-VM $vmName | Get-AdvancedSetting -Name log.keepOld).Value
    if(($example18 -eq "enabled")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
           Write-Output $example18
    }
    write-host ""
    write-host "------------ V-258721 ------------";
    $nonPersistentFound = $false
    $example19_2 = ($vm | Get-HardDisk | Select-object Parent, Name, Filename, DiskType, Persistence | Format-Table -AutoSize)
    $example19 = @($vm | Get-HardDisk | Select-object Parent, Name, Filename, DiskType, Persistence)
    foreach ($diskInfo in $example19) {
        if ($diskInfo.Persistence -ne "Persistent") {
            $nonPersistentFound = $true
        }
    }
    if ($nonPersistentFound -eq $true) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host $example19_2
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host "------------ V-258722 ------------";
    $example20 = (Get-VM $vmName | Get-FloppyDrive | Select Parent, Name, ConnectionState)
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example20 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "Floppy Detected"
        Write-Host $example20
    }
    write-host ""
    write-host "------------ V-258723 ------------";
    $example21 = (Get-VM $vmName | Get-CDDrive | Where-Object {$_.extensiondata.connectable.connected -eq $true} | Select Parent,Name)
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example21 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "CD/DVD Detected"
        Write-Host $example21
    }
    write-host ""
    write-host "------------ V-258724 ------------";
    $example22 = (Get-VM $vmName | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "parallel"})
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example22 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "Parallel Device Detected"
        Write-Host $example22
    }
    write-host ""
    write-host "------------ V-258725 ------------";
    $example23 = (Get-VM $vmName | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "serial"})
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example23 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "Serial Device Detected"
        Write-Host $example23
    }
    write-host ""
    write-host "------------ V-258726 ------------";
    $example24 = (Get-VM $vmName | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "usb"} | FT -AutoSize)
    $example24_2 = (Get-UsbDevice -VM $vmName | FT -AutoSize)
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example24 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "USB Device Detected"
        Write-Host "If this is used for a Smart Card, this will be Not a Finding"
        Write-Host "USB Controller:" $example24
        Write-Host "USB Device:" $example24_2 
    }
    write-host ""
    write-host "------------ V-258727 ------------";
    $example25 = (Get-VM $vmName | Get-AdvancedSetting -Name "pciPassthru*.present" | Select-Object Entity, Name, Value)
    if($example25 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Will need to provide documentation supporting the need for the following devices"
        Write-Host "If no documentation is provided; Open"
        Write-Output $example25
    }
    write-host ""
}