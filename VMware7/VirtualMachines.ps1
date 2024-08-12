#****************************************************************
#*************Written By Mitchell Gibson USACPB CRIA*************
#*************Last Updated Jul 27, 2023 v1.1*********************
#****************************************************************

#20230727
#Changed V-256471 in accordance with the new STIG released

Clear-Host

#Start of Script

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
    write-host "------------ V-256450 ------------";
    $example1 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.copy.disable).Value
    if(($example1 -eq $null) -or ($example1 -ne "true")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example1
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256451 ------------";
    $example2 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.dnd.disable).Value
    if(($example2 -eq $null) -or ($example2 -ne "true")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example2
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256452 ------------";
    $example3 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.paste.disable).Value
    if(($example3 -eq $null) -or ($example3 -ne "true")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example3
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256453 ------------";
    $example4 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.diskShrink.disable).Value
    if(($example4 -eq $null) -or ($example4 -ne "true")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example4
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256454 ------------";
    $example5 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.diskWiper.disable).Value
    if(($example5 -eq $null) -or ($example5 -ne "true")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example5
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256455 ------------";
    $nonPersistentFound = $false
    $example6_2 = ($vm | Get-HardDisk | Select Parent, Name, Filename, DiskType, Persistence | Format-Table -AutoSize)
    $example6 = @($vm | Get-HardDisk | Select Parent, Name, Filename, DiskType, Persistence)
    foreach ($diskInfo in $example6) {
        if ($diskInfo.Persistence -ne "Persistent") {
            $nonPersistentFound = $true
        }
    }
    if ($nonPersistentFound -eq $true) {
        Write-Host "Open" -ForegroundColor Red
        echo $example6_2
    } else {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host "------------ V-256456 ------------";
    $example7 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable).Value
    if(($example7 -eq $null) -or ($example7 -ne "true")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example7
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256457 ------------";
    $example8 = (Get-VM $vmName | Get-FloppyDrive | Select Parent, Name, ConnectionState)
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example8 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "Floppy Detected"
        Write-Host $example8
    }
    write-host ""
    write-host "------------ V-256458 ------------";
    $example9 = (Get-VM $vmName | Get-CDDrive | Where {$_.extensiondata.connectable.connected -eq $true} | Select Parent,Name)
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example9 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "CD/DVD Detected"
        Write-Host $example9
    }
    write-host ""
    write-host "------------ V-256459 ------------";
    $example10 = (Get-VM $vmName | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "parallel"})
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example10 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "Parallel Device Detected"
        Write-Host $example10
    }
    write-host ""
    write-host "------------ V-256460 ------------";
    $example11 = (Get-VM $vmName | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "serial"})
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example11 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "Serial Device Detected"
        Write-Host $example11
    }
    write-host ""
    write-host "------------ V-256461 ------------";
    $example12 = (Get-VM $vmName | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "usb"} | FT -AutoSize)
    $example12_2 = (Get-UsbDevice -VM $vmName | FT -AutoSize)
    if ($vm.PowerState -ne 'PoweredOn') {
        Write-Output "$($vm.Name) is powered off this check won't work"
    }
    elseif($example12 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Host "USB Device Detected"
        Write-Host "If this is used for a Smart Card, this will be Not a Finding"
        echo "USB Controller:" $example12
        echo "USB Device:" $example12_2 
    }
    write-host ""
    write-host "------------ V-256462 ------------";
    $example13 = (Get-VM $vmName | Get-AdvancedSetting -Name RemoteDisplay.maxConnections).Value
    if(($example13 -eq $null) -or ($example13 -ne "1")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example13
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256463 ------------";
    $example14 = (Get-VM $vmName | Get-AdvancedSetting -Name tools.setinfo.sizeLimit).Value
    if(($example14 -eq $null) -or ($example14 -ne "1048576")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example14
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256464 ------------";
    $example15 = (Get-VM $vmName | Get-AdvancedSetting -Name isolation.device.connectable.disable).Value
    if(($example15 -eq $null) -or ($example15 -ne "true")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example15
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256465 ------------";
    $example16 = (Get-VM $vmName | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo).Value
    if(($example16 -eq $null) -or ($example16 -ne "false")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example16
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256466 ------------";
    $example17 = (Get-VM $vmName | Get-AdvancedSetting -Name sched.mem.pshare.salt).Value
    if($example17 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Open
        Write-Output $example17
    }
    write-host ""
    write-host "------------ V-256467 ------------";
    $example18 = (Get-VM $vmName | Get-AdvancedSetting "ethernet*.filter*.name*")
    $dvFiltersInUse = ($vm.ExtensionData.Config.DefaultPortConfig.DistributedVirtualSwitch.DistributedVirtualPort.DvFilterConfig)
    if($example18 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    elseif ($dvFiltersInUse -eq $null) {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "DVFilters aren't in use"
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
        Write-Output $example18
    }
    write-host ""
    write-host "------------ V-256468 ------------";
    $templates = (Get-VM | Where-Object { $_.ExtensionData.Config.Template -eq $true })
    if ($templates) {
        Write-Output "Validate a template exists for this VM:"
        $templates | Select-Object Name, PowerState, NumCpu, MemoryGB
    } else {
        Write-Host "Open" -ForegroundColor Red
        Write-Host "No Templates are being used"
    }
    write-host ""
    write-host "------------ V-256469 ------------";
    Write-Host "Documentation Check to validate that they only use VM console access when troubleshooting"
    Write-Host ""
    write-host "------------ V-256470 ------------";
    $windows_check = $vm.ExtensionData.Config.GuestFullName
    $example19 = (Get-VM $vmname | Get-AdvancedSetting -Name tools.guest.desktop.autolock).Value
    if ($windows_check -notlike "*Windows*") {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    elseif(($example19 -eq $null) -or ($example19 -ne "true")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example19
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256471 ------------";
    $example20 = (Get-VM $vmname | Get-AdvancedSetting -Name mks.enable3d).Value
    if($example20 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
        Write-Output $example20
    }
    elseif ($example20 -eq "false") {
        Write-Host "Not a finding" -ForegroundColor Green
    }
    else { Write-Host "Red" -ForegroundColor Open
    }
    write-host ""
    write-host "------------ V-256472 ------------";
    $example21 = ($vm.ExtensionData.Config.MigrateEncryption)
    if(($example21 -eq "opportunistic") -or ($example21 -eq "required")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Output $example21
    }
    write-host ""
    write-host "------------ V-256473 ------------";
    $example22 = ($vm.ExtensionData.Config.Flags.EnableLogging)
    if($example22 -eq "True") {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Output $example22
    }
    write-host ""
    write-host "------------ V-256474 ------------";
    $example23 = (Get-VM $vmName | Get-AdvancedSetting -Name log.rotateSize).Value
    if(($example23 -eq $null) -or ($example23 -ne "2048000")) {
        Write-Host "Open" -ForegroundColor Red
        Write-Output $example23
    }
    else { Write-Host "Not a Finding" -ForegroundColor Green
    }
    write-host ""
    write-host "------------ V-256475 ------------";
    $example24 = (Get-VM $vmName | Get-AdvancedSetting -Name log.keepOld).Value
    if($example24 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    elseif($example24 -eq "10"){
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Output $example24
    }
    write-host ""
    write-host "------------ V-256476 ------------";
    $example25 = (Get-VM $vmName | Get-AdvancedSetting -Name "pciPassthru*.present" | Select Entity, Name, Value)
    if($example25 -eq $null) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Will need to provide documentation supporting the need for the following devices"
        Write-Host "If no documentation is provided; Open"
        Write-Output $example25
    }
    write-host ""
    write-host "------------ V-256477 ------------";
    $example26 = ($vm.ExtensionData.Config.FtEncryptionMode)
    if(($example26 -like "*opportunistic") -or ($example26 -like "*required")) {
        Write-Host "Not a Finding" -ForegroundColor Green
    }
    else { Write-Host "Open" -ForegroundColor Red
        Write-Output $example26
    }
    write-host ""
}
