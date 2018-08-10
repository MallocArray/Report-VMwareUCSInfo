#========================================================================
# Report-VMwareUCSInfo
# Created by: Joshua Post
#
# Based on http://www.vmspot.com/collecting-esxi-host-hardware-information-with-powershell/
# Better UCS Profile matching based on https://timsvirtualworld.com/2014/02/report-the-running-ucs-firmware-versions-by-esxi-host-with-powerclipowertool/

# UCS PowerTool install
# Install-Module Cisco.UCSManager

# VMware PowerCLI install
# Install-Module VMware.PowerCLI

# Version 3 with UCS integration for firmware versions and model identification
# Version 5 with rebuilt output object for easier manipulation
# Version 6 with get-ESXCLI to retrieve data without needing plink
# Version 7 with change to import modules for PowerCLI 6.5 R1
# Version 8 with CPU model information
# Version 9 with nenic change for ESXi 6.5
# Version 10 with support for 2 VIC adapters and firmware
# Version 11 with more dynamic UCS profile matching
# Version 14 with boot device detection for storage HBA
# Improved detection 
# http://pubs.vmware.com/vsphere-55/index.jsp#com.vmware.vcli.ref.doc/vcli-right.html

#========================================================================
# Edit the following section. Enter your vCenter server and the desired location of the output CSV.
$vcenters = @("vCenter.mydomain.com")
$UCSManagers= @("192.168.1.2","ucs.mydomain.com")
$csvfile = "C:\Temp\hostinfo.csv"
#========================================================================


Write-Host "Enter your vCenter Credentials"
$vCenterAccount = Get-Credential
Write-Host "Enter your UCS Credentials. If using AD authentication, must prefix with 'ucs-DOMAINNAME\' and it is case sensitive"
$UCSAccount = Get-Credential

# Connect to vCenter
Write-Host "Connecting to vCenter..."
Connect-VIServer $vcenters -Credential $vCenterAccount -AllLinked
Write-Host " "

Write-host "Connecting to UCS"
Import-Module Cisco.UCSManager
Set-UcsPowerToolConfiguration -supportmultipledefaultucs $true 
connect-ucs $UCSManagers -Credential $UCSAccount

# Check to see if the CSV file exists, if it does then overwrite it.
if (Test-Path $csvfile) {
Write-Host "Overwriting $csvfile"
del $csvfile
}
# Create the CSV title header
Add-Content $csvfile "Host Name,Cluster,Host Model,Bios Version,Bios Date,Processor,OS Version,Storage Adapter,Storage Driver,Adapter 1,Adapter 1 Package, Adapter 1 Firmware,Adapter 2,Adapter 2 Package, Adapter 2 Firmware,(N)ENIC Driver,FNIC Driver,CIMC Firmware,Board Controller Firmware,Service Profile Firmware Policy"

# Get the host inventory from vCenter
$vmhosts = Get-VMHost | where-object {$_.manufacturer -like "Cisco*"} | Sort Parent, Name
# $vmhosts = get-vmhost "wdc-besxhstp62.smrcy.com"
foreach ($vmhost in $vmhosts){
    #Cleaning up variables
    #These should be overwritten in each pass, but sometimes that doesn't work and this is the fastest solution for now
    $nicmodule=$fnicmodule=$bootdevice=$boothba=$esxcli=$hosthardware=$hostview=$biosfwd=$esxiversion=$hbadevice=$hbadetails=$hbamoduleformatted=$hbadrvfull=$hbadrv=$nicadapter=$nicver=$fnicdevice=$fnicver=$MacAddr=$ServiceProfile=$UCSHardware=$UCSfirmware=$cimcfw=$biosfw=$boardcontrollerfw=$spfwpolicy=$UCSStorageAdapter=$UCSAdapter=$UCSAdapter2Model=$UCSAdapterFirmware=$HostOutput=$null

    #Configures an EsxCli session for the host to retrieve additional information
    $esxcli = Get-VMHost $vmhost | Get-EsxCli

    #########################
    # VMware Host Information
    #########################
    $hosthardware = Get-VMHostHardware -VMHost $vmhost
    $hostview = Get-View -ViewType HostSystem -Filter @{"Name" = $vmhost.Name} #| Select @{N="BIOSDate";E={$_.Hardware.BiosInfo.releaseDate}}, @{N="OS";E={$_.Config.Product.FullName}}
    $biosfwd = $hostview.Hardware.biosinfo.ReleaseDate.ToShortDateString()
    $esxiversion = $hostview.Config.Product.FullName



    #########################
    # Storage Controller
    #########################
    # Get the booting Storage controller model and device ID
    $bootdevice = $esxcli.storage.core.device.list() | where { $_.isbootdevice -eq "True"}
    #$boothba = (get-scsilun -vmhost $vmhost -CanonicalName $bootdevice.device | select -ExpandProperty RuntimeName).split(":")[0] #Significantly slower method
    $boothba = ($esxcli.storage.core.path.list() | where {$_.device -eq $bootdevice.device} | select -ExpandProperty RuntimeName).split(":")[0]
    $boothbamodule = $esxcli.hardware.pci.list() | where {$_.VMkernelName -eq $boothba} | select -expandproperty ModuleName -first 1
    #$hbadetails = $esxcli.storage.core.adapter.list() | Where {$_.HBAName -eq $boothba}
    $hbadevice = Get-VMHostHba -vmhost $vmhost -device $boothba
    
    if ($boothbamodule) {$hbadrv = $esxcli.system.module.get($boothbamodule).version.split(",")[0].split("OEM")[0].split("-")[0].replace("Version ", "").replace("OEM","") }
    if (!$hbadrv) {$hbadrv="Unknown Driver"}

    #########################
    # Network NIC
    #########################
    $nicadapter = Get-VMHostpcidevice -vmhost $vmhost -DeviceClass NetworkController | select *
    #$nicadapter = Get-VMHostpcidevice -vmhost $vmhost -DeviceClass SerialBusController | select *
    $nicmodule = $esxcli.hardware.pci.list() | where {$_.DeviceName -eq $nicadapter[0].devicename} | select -expandproperty ModuleName -first 1
    #$nicver = $esxcli.system.module.get($nicmodule).version.split("-")[0]
    $nicver = $esxcli.system.module.get($nicmodule).version.split(",")[0].split("OEM")[0].split("-")[0].replace("Version ", "").replace("OEM","")
    
    #########################
    # Fibre NIC
    #########################
    # Determining version of fnic for Cisco UCS
    # http://gooddatacenter.blogspot.com/2014/04/ucs-and-vmware-how-to-determine-fnic.html
    # Assuming first FibreChannel adapter is the fnic
    $fnicadapter= Get-VMHostHba -vmhost $vmhost -type FibreChannel | select -first 1
    If ($fnicadapter) { #If a FiberChannel adapter is detected
        $fnicmodule = $esxcli.hardware.pci.list() | where {$_.DeviceName -eq $fnicadapter.model} | select -expandproperty ModuleName -first 1 
        $fnicver = $esxcli.system.module.get($fnicmodule).version.split(",")[0].split("OEM")[0].split("-")[0].replace("Version ", "").replace("OEM","") 
        }

    #########################
    # Collect UCS Info
    #########################
    #$MacAddr = $vmhost.NetworkInfo.PhysicalNic | where { $_.name -ieq "vmnic0" }
	$MacAddr = Get-VMHostNetworkAdapter -vmhost $vmhost -Physical | where {$_.BitRatePerSec -gt 0} | select -first 1 #Select first connected physical NIC
    $ServiceProfile =  Get-UcsServiceProfile | Get-UcsVnic |  where { $_.addr -ieq  $MacAddr.Mac } | Get-UcsParent
	# Find the physical hardware the service profile is running on:
	$UCSHardware = $ServiceProfile.PnDn
    # Collect UCS Firmware versions for different components
    $UCSfirmware = Get-UcsFirmwareRunning | Where{$_.dn -ilike "$UCSHardware/*" -and $_.Ucs -eq $ServiceProfile.Ucs}
    $cimcfw = $UCSfirmware | Where{$_.Type -eq "blade-controller" -and $_.Deployment -eq "system" -and $_.dn -ilike "$UCSHardware/*" -and $_.Ucs -eq $ServiceProfile.Ucs} | Select-Object -ExpandProperty Version
	$biosfw = $UCSfirmware | ?{$_.Type -eq "blade-bios" -and $_.dn -ilike "$UCSHardware/*"  -and $_.Ucs -eq $ServiceProfile.Ucs} | Select-Object -ExpandProperty Version
	$boardcontrollerfw = $UCSfirmware | ?{$_.Type -eq "board-controller" -and $_.dn -ilike "$UCSHardware/*"  -and $_.Ucs -eq $ServiceProfile.Ucs} | Select-Object -ExpandProperty Version
	$spfwpolicy = $ServiceProfile | Select-Object -ExpandProperty OperHostFwPolicyName


    #########################
    # UCS Storage Adapter
    #########################
    if($bootdevice.vendor -eq "Cypress" -or $bootdevice.vendor -eq "CiscoVD") {$UCSStorageAdapter = Get-UcsStorageFlexFlashController | Where{$_.dn -ilike "$UCSHardware/*" -and $_.Ucs -eq $ServiceProfile.Ucs}}
    else {$UCSStorageAdapter = Get-UcsStorageController | Where{$_.dn -ilike "$UCSHardware/*" -and $_.Ucs -eq $ServiceProfile.Ucs}}
    
    Switch ($UCSStorageAdapter[0].model) {
        "MegaRAID SAS 9240"  {$UCSStorageAdapterModel="LSI MegaRAID SAS 9240 "; break}
        "SAS1064E PCI-Express Fusion-MPT SAS" {$UCSStorageAdapterModel="LSI SAS1064E"; break}
        "FX3S" {$UCSStorageAdapterModel="FlexFlash FX3S"; break}
        $Null {$UCSStorageAdapterModel=$hbadevice.Model; break}
        default {$UCSStorageAdapterModel=$UCSStorageAdapter[0].model; break}
        }

    #########################
    # UCS Adapter
    #########################
    #Get information about the adapter in the UCS Server
    $UCSAdapter = Get-UcsServer |  Where{$_.dn -eq "$UCSHardware" -and $_.Ucs -eq $ServiceProfile.Ucs} | Get-UcsAdaptorUnit
    $UCSAdapterFirmware = $UCSfirmware | ?{$_.Type -eq "adaptor" -and $_.Deployment -eq "system" -and $_.Ucs -eq $ServiceProfile.Ucs}
    $UCSAdapterModel=$UCSAdapter[0] | Get-UCSCapability | select -expandproperty name
    $UCSAdapter2 = $UCSAdapter[1] | Get-UCSCapability
    if ($UCSAdapter2.count -gt 1) { $UCSAdapter2Model = $fnicadapter.Model } #Cisco Unknown device detected
    elseif($UCSAdapter2.OemPartNumber -ne "") {$UCSAdapter2Model=$UCSAdapter2.OemPartNumber} #3rd party adapters put the model in OemPartNumber
        else {$UCSAdapter2Model=$UCSAdapter2.name}
    

    #Build output
    $HostOutput = New-Object PSObject -Property @{
        HostName = $vmhost.Name
        Cluster = $vmhost.Parent.Name
        HostModel = $hosthardware.Model
        BiosVersion = $hosthardware.BiosVersion
        BiosDate = $biosfwd
        ProcessorType = $vmhost.ProcessorType
        OSVersion = $esxiversion
        StorageAdapter = $UCSStorageAdapterModel
        StorageDriver = $hbadrv
        UCSAdapterModel = $UCSAdapterModel
        UCSAdapterPackage = $UCSAdapterFirmware[0].PackageVersion
        UCSAdapterFirmware = $UCSAdapterFirmware[0].Version
        UCSAdapter2Model = $UCSAdapter2Model
        UCSAdapter2Package = $UCSAdapterFirmware[1].PackageVersion
        UCSAdapter2Firmware = $UCSAdapterFirmware[1].Version
        UCSenicDriver = $nicver
        UCSfnicDriver = $fnicver
        UCScimcFirmware = $cimcfw
        UCSboardcontrollerFirmware = $boardcontrollerfw
        UCSserviceprofileFirmwarePolicy = $spfwpolicy
        }

    #########################
    # Output
    #########################


    # Assemble the information into CSV format and append it to the CSV file.
    $csvline = $HostOutput.Hostname + "," + $HostOutput.Cluster + "," + $HostOutput.HostModel + "," + $HostOutput.BiosVersion + "," + $HostOutput.BiosDate + "," + $HostOutput.processortype + "," + $HostOutput.OSVersion + "," + $HostOutput.StorageAdapter + "," + $HostOutput.StorageDriver + "," + $HostOutput.UCSAdapterModel + "," + $HostOutput.UCSAdapterPackage + "," + $HostOutput.UCSAdapterFirmware + "," + $HostOutput.UCSAdapter2Model + "," + $HostOutput.UCSAdapter2Package + "," + $HostOutput.UCSAdapter2Firmware + "," + $HostOutput.UCSenicDriver + "," + $HostOutput.UCSfnicDriver + "," + $HostOutput.UCScimcFirmware + "," + $HostOutput.UCSboardcontrollerFirmware + "," + $HostOutput.UCSserviceprofileFirmwarePolicy
    Add-Content $csvfile $csvline

    # Display all the information we collected in a readable format
    Write-Host ""
    Write-Host "Hostname:" $HostOutput.Hostname -ForegroundColor "Green"
    Write-Host "Cluster:" $HostOutput.Cluster
    Write-Host "Host Model:" $HostOutput.HostModel
    Write-Host "BIOS Firmware:" $HostOutput.BiosVersion $HostOutput.BiosDate
    Write-Host "Processor Type:" $HostOutput.ProcessorType
    Write-Host "OS Version:" $HostOutput.OSVersion
    Write-Host ""
    Write-Host "Storage Adapter:" $HostOutput.StorageAdapter
    Write-Host "Storage Driver:" $HostOutput.StorageDriver
    Write-Host ""
    Write-Host "Adapter:" $HostOutput.UCSAdapterModel
    Write-Host "Adapter Package:" $HostOutput.UCSAdapterPackage
    Write-Host "Adapter Firmware:" $HostOutput.UCSAdapterFirmware
    Write-Host "Adapter2:" $HostOutput.UCSAdapter2Model
    Write-Host "Adapter2 Package:" $HostOutput.UCSAdapter2Package
    Write-Host "Adapter2 Firmware:" $HostOutput.UCSAdapter2Firmware
    Write-Host "(N)ENIC Driver:" $HostOutput.UCSenicDriver
    Write-Host "FNIC Driver:" $HostOutput.UCSfnicDriver
    Write-Host ""
    Write-Host "CIMC Firmware:" $HostOutput.UCScimcFirmware
    Write-Host "Board Controller Firmware:" $HostOutput.UCSboardcontrollerFirmware
    Write-Host "Service Profile Firmware Policy:" $HostOutput.UCSserviceprofileFirmwarePolicy
    Write-Host "----------------------------------"


}
<# Disconnect when finished
Disconnect-VIServer * -Confirm:$False
Disconnect-Ucs
#>