#There are 3 requirements in order to get the VM scan to work.

#1. They must have powercli installed on the system 
# Instructions on installing PowerCLI with an internet connection:      
    From a computer with an internet connection open powershell (preferrably as an administrator)
    Find-Module -Name VMware.PowerCLI
    Install-Module -Name VMware.PowerCLI -Scope CurrentUser
    Get-Command -Module *VMWare*

#2. Must enable the ability to run powershell scripts from unsigned sources
# Instructions on enabled unsigned powershell scripting
    Open up Powershell as administrator
    set-executionpolicy remotesigned
    Press Y to only apply to the local user

