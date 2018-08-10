#requires -version 2
<#
.SYNOPSIS
  Script to collect information about VMware drivers and Cisco UCS firmware.

.DESCRIPTION
  Script goes through all linked vCenters provided and finds Cisco hosts.
  Then collects basic host information, the current VMware drivers versions for the booting storage controller and
  the first two adapters.  
  Then correlates the host to the UCS Service Profile and collects firmware versions for various components
  and reports the Cisco name of the device, as they often appear with generic names in ESXi
  No plink or SSH access required
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  Script assumes the user has previously installed the VMware PowerCLI and Cisco PowerTool modules into Powershell
    # VMware PowerCLI install
    # Install-Module VMware.PowerCLI

    # UCS PowerTool install
    # Install-Module Cisco.UCSManager

    Variable section at top of script should be filled out with vCenter names and UCS Managers.  Script will prompt
    for credentials as it runs
.OUTPUTS
  Variable section at top of script has option for the output location of the CSV for the final report
.NOTES
  Version:        2.14
  Author:         Joshua Post
  Creation Date:  8/10/2018
  Purpose/Change: Modifying HostOutput for cleaner code
  Based on http://www.vmspot.com/collecting-esxi-host-hardware-information-with-powershell/
  Better UCS Profile matching based on https://timsvirtualworld.com/2014/02/report-the-running-ucs-firmware-versions-by-esxi-host-with-powerclipowertool/
.EXAMPLE
  Modify variables then run script from ISE or from Powershell prompt
#>


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

$Report = @() #Final Output array

# Get the host inventory from vCenter
$vmhosts = Get-VMHost | where-object {$_.manufacturer -like "Cisco*"} | Sort Parent, Name
foreach ($vmhost in $vmhosts){
    Write-Progress -Activity 'Collecting Information' -CurrentOperation $vmhost.name -PercentComplete (($Report.count / $vmhosts.count) * 100)
    $HostOutput = New-Object PSObject -Property @{
        HostName = $Null
        Cluster = $Null
        HostModel = $Null
        BiosVersion = $Null
        BiosDate = $Null
        ProcessorType = $Null
        OSVersion = $Null
        StorageAdapter = $Null
        StorageDriver = $Null
        UCSAdapterModel = $Null
        UCSAdapterPackage = $Null
        UCSAdapterFirmware = $Null
        UCSAdapter2Model = $Null
        UCSAdapter2Package = $Null
        UCSAdapter2Firmware = $Null
        UCSnenicDriver = $Null
        UCSfnicDriver = $Null
        UCScimcFirmware = $Null
        UCSBoardControllerFirmware = $Null
        UCSserviceprofileFirmwarePolicy = $Null
        HostView = $Null
        BootDevice = $Null
        BootHBA = $Null
        BootHBAModule = $Null
        HBADevice = $Null
        NICAdapter = $Null
        NICModule = $Null
        FNICAdapter = $Null
        FNICModule = $Null
        NICMAC = $Null
        UCSServiceProfile = $Null
        UCSHardware = $Null
        UCSFirmware = $Null
        UCSAdapters = $Null
        UCSAdaptersFirmware = $Null
        UCSAdapter2 = $Null
    }
    
    if ((Get-VMHost $VMHost).ConnectionState -eq "NotResponding") {
        Write-Host "$($vmhost.name) is unresponsive.  Skipping."
        Continue
        }

    #Configures an EsxCli session for the host to retrieve additional information
    $esxcli = Get-VMHost $vmhost | Get-EsxCli

    #########################
    # VMware Host Information
    #########################
    $HostOutput.HostName = $vmhost.Name
    $HostOutput.Cluster = $vmhost.Parent.Name
    $HostOutput.HostModel = Get-VMHostHardware -VMHost $vmhost | select -expandproperty model
    $HostOutput.BiosVersion = Get-VMHostHardware -VMHost $vmhost | select -expandproperty BiosVersion
    $HostOutput.HostView = Get-View -ViewType HostSystem -Filter @{"Name" = $vmhost.Name}
    $HostOutput.BiosDate = $HostOutput.HostView.Hardware.biosinfo.ReleaseDate.ToShortDateString()
    $HostOutput.OSVersion = $HostOutput.HostView.Config.Product.FullName
    $HostOutput.ProcessorType = $vmhost.ProcessorType


    #########################
    # Storage Controller
    #########################
    # Get the booting Storage controller model and device ID
    $HostOutput.BootDevice = $esxcli.storage.core.device.list() | where { $_.isbootdevice -eq "True"}
    $HostOutput.BootHBA = ($esxcli.storage.core.path.list() | where {$_.device -eq $HostOutput.BootDevice.device} | select -ExpandProperty RuntimeName).split(":")[0]
    $HostOutput.BootHBAModule = $esxcli.hardware.pci.list() | where {$_.VMkernelName -eq $HostOutput.BootHBA} | select -expandproperty ModuleName -first 1
    $HostOutput.HBADevice = Get-VMHostHba -vmhost $vmhost -device $HostOutput.BootHBA
    
    if ($HostOutput.BootHBAModule) {$HostOutput.StorageDriver = $esxcli.system.module.get($HostOutput.BootHBAModule).version.split(",")[0].split("OEM")[0].split("-")[0].replace("Version ", "").replace("OEM","") }
    if (!$HostOutput.StorageDriver) {$HostOutput.StorageDriver="Unknown Driver"}

    #########################
    # Network NIC
    #########################
    $HostOutput.NICAdapter = Get-VMHostpcidevice -vmhost $vmhost -DeviceClass NetworkController | select -expandproperty DeviceName -first 1
    $HostOutput.NICModule = $esxcli.hardware.pci.list() | where {$_.DeviceName -eq $HostOutput.NICAdapter} | select -expandproperty ModuleName -first 1
    $HostOutput.UCSnenicDriver = $esxcli.system.module.get($HostOutput.NICmodule).version.split(",")[0].split("OEM")[0].split("-")[0].replace("Version ", "").replace("OEM","")
    
    #########################
    # Fibre NIC
    #########################
    # Determining version of fnic for Cisco UCS
    # http://gooddatacenter.blogspot.com/2014/04/ucs-and-vmware-how-to-determine-fnic.html
    # Assuming first FibreChannel adapter is the fnic
    $HostOutput.FNICAdapter= Get-VMHostHba -vmhost $vmhost -type FibreChannel | select -first 1
    If ($HostOutput.FNICAdapter) { #If a FiberChannel adapter is detected
        $HostOutput.FNICModule = $esxcli.hardware.pci.list() | where {$_.DeviceName -eq $HostOutput.FNICAdapter.model} | select -expandproperty ModuleName -first 1 
        $HostOutput.UCSfnicDriver = $esxcli.system.module.get($HostOutput.FNICModule).version.split(",")[0].split("OEM")[0].split("-")[0].replace("Version ", "").replace("OEM","") 
        }

    #########################
    # Collect UCS Info
    #########################
    $HostOutput.NICMAC = Get-VMHostNetworkAdapter -vmhost $vmhost -Physical | where {$_.BitRatePerSec -gt 0} | select -expandproperty Mac -first 1 #Select first connected physical NIC
    $HostOutput.UCSServiceProfile =  Get-UcsServiceProfile | Get-UcsVnic |  where { $_.addr -ieq  $HostOutput.NICMAC } | Get-UcsParent
	if (!$HostOutput.UCSServiceProfile) {
        Write-Host "Unable to retrieve UCS information for $($HostOutput.HostName)"
        #$Report += $HostOutput
        Continue
        }
    # Find the physical hardware the service profile is running on:
	$HostOutput.UCSHardware = $HostOutput.UCSServiceProfile.PnDn
    # Collect UCS Firmware versions for different components
    $HostOutput.UCSFirmware = Get-UcsFirmwareRunning | Where{$_.dn -ilike "$($HostOutput.UCSHardware)/*" -and $_.Ucs -eq $HostOutput.UCSServiceProfile.Ucs}
    $HostOutput.UCScimcFirmware = $HostOutput.UCSFirmware | Where{$_.Type -eq "blade-controller" -and $_.Deployment -eq "system" -and $_.dn -ilike "$($HostOutput.UCSHardware)/*" -and $_.Ucs -eq $HostOutput.UCSServiceProfile.Ucs} | Select-Object -ExpandProperty Version
	If (!$HostOutput.BiosVersion) {$HostOutput.BiosVersion = $HostOutput.UCSFirmware | ?{$_.Type -eq "blade-bios" -and $_.dn -ilike "$($HostOutput.UCSHardware)/*"  -and $_.Ucs -eq $HostOutput.UCSServiceProfile.Ucs} | Select-Object -ExpandProperty Version}
	$HostOutput.UCSBoardControllerFirmware = $HostOutput.UCSFirmware | ?{$_.Type -eq "board-controller" -and $_.dn -ilike "$($HostOutput.UCSHardware)/*"  -and $_.Ucs -eq $HostOutput.UCSServiceProfile.Ucs} | Select-Object -ExpandProperty Version
	$HostOutput.UCSserviceprofileFirmwarePolicy = $HostOutput.UCSServiceProfile | Select-Object -ExpandProperty OperHostFwPolicyName


    #########################
    # UCS Storage Adapter
    #########################
    if($HostOutput.BootDevice.vendor -eq "Cypress" -or $bootdevice.vendor -eq "CiscoVD") {$HostOutput.StorageAdapter = Get-UcsStorageFlexFlashController | Where{$_.dn -ilike "$($HostOutput.UCSHardware)/*" -and $_.Ucs -eq $HostOutput.UCSServiceProfile.Ucs} | select -expandproperty Model -first 1}
    else {$HostOutput.StorageAdapter = Get-UcsStorageController | Where{$_.dn -ilike "$($HostOutput.UCSHardware)/*" -and $_.Ucs -eq $HostOutput.UCSServiceProfile.Ucs} | select -expandproperty Model -first 1}
    
    Switch ($HostOutput.StorageAdapter) {
        "MegaRAID SAS 9240"  {$HostOutput.StorageAdapter="LSI MegaRAID SAS 9240 "; break}
        "SAS1064E PCI-Express Fusion-MPT SAS" {$HostOutput.StorageAdapter="LSI SAS1064E"; break}
        "FX3S" {$HostOutput.StorageAdapter="FlexFlash FX3S"; break}
        $Null {$HostOutput.StorageAdapter=$HostOutput.BootDevice.model; break}
        default {$HostOutput.StorageAdapter=$HostOutput.StorageAdapter; break}
        }

    #########################
    # UCS Adapter
    #########################
    #Get information about the adapter in the UCS Server
    $HostOutput.UCSAdapters = Get-UcsServer |  Where{$_.dn -eq $HostOutput.UCSHardware -and $_.Ucs -eq $HostOutput.UCSServiceProfile.Ucs} | Get-UcsAdaptorUnit
    $HostOutput.UCSAdaptersFirmware = $HostOutput.UCSFirmware | ?{$_.Type -eq "adaptor" -and $_.Deployment -eq "system" -and $_.Ucs -eq $HostOutput.UCSServiceProfile.Ucs}
    $HostOutput.UCSAdapterModel=$HostOutput.UCSAdapters[0] | Get-UCSCapability | select -expandproperty name
    $HostOutput.UCSAdapterPackage = $HostOutput.UCSAdaptersFirmware[0].PackageVersion
    $HostOutput.UCSAdapterFirmware = $HostOutput.UCSAdaptersFirmware[0].Version
    #Adapter 2, if present
    $HostOutput.UCSAdapter2Package = $HostOutput.UCSAdaptersFirmware[1].PackageVersion
    $HostOutput.UCSAdapter2Firmware = $HostOutput.UCSAdaptersFirmware[1].Version
    $HostOutput.UCSAdapter2 = $HostOutput.UCSAdapters[1] | Get-UCSCapability
    if (($HostOutput.UCSAdapter2).count -gt 1) { $HostOutput.UCSAdapter2Model = $HostOutput.FNICAdapter.Model } #Cisco Unknown device detected
    elseif($HostOutput.UCSAdapter2.OEMPartNumber -ne "") {$HostOutput.UCSAdapter2Model=$HostOutput.UCSAdapter2.OemPartNumber} #3rd party adapters put the model in OemPartNumber
        else {$HostOutput.UCSAdapter2Model=$HostOutput.UCSAdapter2.name}
    
    #########################
    # Output
    #########################

    $Report += $HostOutput #Add this host to the output array
        
    # Display information collected in a readable format
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
    Write-Host "(N)ENIC Driver:" $HostOutput.UCSnenicDriver
    Write-Host "FNIC Driver:" $HostOutput.UCSfnicDriver
    Write-Host ""
    Write-Host "Adapter:" $HostOutput.UCSAdapterModel
    Write-Host "Adapter Package:" $HostOutput.UCSAdapterPackage
    Write-Host "Adapter Firmware:" $HostOutput.UCSAdapterFirmware
    Write-Host "Adapter2:" $HostOutput.UCSAdapter2Model
    Write-Host "Adapter2 Package:" $HostOutput.UCSAdapter2Package
    Write-Host "Adapter2 Firmware:" $HostOutput.UCSAdapter2Firmware

    Write-Host ""
    Write-Host "CIMC Firmware:" $HostOutput.UCScimcFirmware
    Write-Host "Board Controller Firmware:" $HostOutput.UCSboardcontrollerFirmware
    Write-Host "Service Profile Firmware Policy:" $HostOutput.UCSserviceprofileFirmwarePolicy
    Write-Host "----------------------------------"


}

#Write to Output file
$Report | select Hostname, Cluster, HostModel, BIOSVersion, ProcessorType, OSVersion, `
    StorageAdapter, StorageDriver, UCSnenicDriver, UCSfnicDriver, `
    UCSAdapterModel, UCSAdapterPackage, UCSAdapterFirmware, UCSAdapter2Model, UCSAdapter2Package, UCSAdapter2Firmware, `
    UCScimcFirmware, UCSBoardControllerFirmware, UCSServiceProfileFirmwarePolicy `
    | Export-Csv -Path $CSVfile -NoTypeInformation

<# Disconnect when finished
Disconnect-VIServer * -Confirm:$False
Disconnect-Ucs
#>