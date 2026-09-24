# Runs pc_mcp/windows_probe.ps1 against mocked Windows cmdlets so its logic can be tested on any OS with pwsh.
# PowerShell resolves functions before cmdlets, so these definitions shadow the real ones.
# The mocked machine is deliberately unhealthy: power saver + throttled CPU, HDD system disk, disk and WHEA
# errors, low-memory events, two active antivirus products, many startup apps (one disabled), pending reboot.
$ErrorActionPreference = 'Stop'
$env:SystemDrive = 'C:'

function New-FakeEvent($provider, $id, $level, $props = @(), $data = @{}) {
    $xmlData = ($data.GetEnumerator() | ForEach-Object { "<Data Name=`"$($_.Key)`">$($_.Value)</Data>" }) -join ''
    $e = [pscustomobject]@{
        ProviderName = $provider; Id = $id; Level = $level; TimeCreated = (Get-Date).AddHours(-3)
        Message = "Fake $provider event $id with   extra   whitespace"
        Properties = @($props | ForEach-Object { [pscustomobject]@{ Value = $_ } })
        XmlText = "<Event><EventData>$xmlData</EventData></Event>"
    }
    $e | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.XmlText }
    $e
}

function Get-CimInstance {
    [CmdletBinding()]
    param([Parameter(Position = 0)]$ClassName, $Filter, $Namespace)
    switch ($ClassName) {
        'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Microsoft Windows 11 Home'; BuildNumber = '22631'; TotalVirtualMemorySize = 16GB / 1KB; FreeVirtualMemory = 1GB / 1KB } }
        'Win32_ComputerSystem' { [pscustomobject]@{ Manufacturer = 'Contoso'; Model = 'Laptop 5000' } }
        'Win32_PerfFormattedData_Counters_ProcessorInformation' { [pscustomobject]@{ PercentProcessorPerformance = 42; PercentProcessorUtility = 88 } }
        'Win32_Processor' { [pscustomobject]@{ MaxClockSpeed = 2800 } }
        'Win32_StartupCommand' {
            1..13 | ForEach-Object { [pscustomobject]@{ Name = "App$_"; Command = "C:\Apps\app$_.exe --tray"; Location = 'HKU\S-1-5-21\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' } }
            [pscustomobject]@{ Name = 'DisabledThing'; Command = 'C:\x.exe'; Location = 'HKU\...\Run' }
        }
        'AntiVirusProduct' {
            [pscustomobject]@{ displayName = 'Windows Defender'; productState = 397568 }  # 0x061100: on
            [pscustomobject]@{ displayName = 'Norton 360'; productState = 266240 }        # 0x041000: on
            [pscustomobject]@{ displayName = 'Old AV'; productState = 393472 }            # 0x060100: off
        }
        'Win32_VideoController' { [pscustomobject]@{ Name = 'Intel UHD'; DriverVersion = '27.20.100.8681'; DriverDate = [datetime]'2020-09-01' } }
        'MSAcpi_ThermalZoneTemperature' { [pscustomobject]@{ CurrentTemperature = 3682 } }  # 95.05 C
        default { throw "unmocked class $ClassName" }
    }
}

function Get-WinEvent {
    [CmdletBinding()]
    param($FilterHashtable, $MaxEvents)
    $log = $FilterHashtable.LogName
    if ($log -eq 'System') {
        1..4 | ForEach-Object { New-FakeEvent 'disk' 153 3 }
        New-FakeEvent 'Ntfs' 98 4
        1..2 | ForEach-Object { New-FakeEvent 'Microsoft-Windows-WHEA-Logger' 17 3 }
        New-FakeEvent 'Microsoft-Windows-Kernel-Power' 41 1
        1..3 | ForEach-Object { New-FakeEvent 'Microsoft-Windows-Resource-Exhaustion-Detector' 2004 3 }
        1..5 | ForEach-Object { New-FakeEvent 'Service Control Manager' 7031 2 }
    }
    elseif ($log -eq 'Application') {
        1..3 | ForEach-Object { New-FakeEvent 'Application Hang' 1002 2 @('chrome.exe') }
        New-FakeEvent 'Application Error' 1000 2 @('Teams.exe')
    }
    elseif ($log -like '*Diagnostics-Performance*') {
        if ($FilterHashtable.Id -eq 100) { New-FakeEvent 'Diag' 100 4 @() @{ BootTime = '123456' } }
        else { New-FakeEvent 'Diag' 101 3 @() @{ FriendlyName = 'SlowUpdater' }; New-FakeEvent 'Diag' 101 3 @() @{ Name = 'bloat.exe' } }
    }
}

function Get-PhysicalDisk {
    [pscustomobject]@{ FriendlyName = 'WDC WD10SPZX'; MediaType = 'HDD'; BusType = 'SATA'; HealthStatus = 'Healthy'; Size = 1TB; DeviceId = '0' }
    [pscustomobject]@{ FriendlyName = 'USB Stick'; MediaType = 'Unspecified'; BusType = 'USB'; HealthStatus = 'Warning'; Size = 32GB; DeviceId = '1' }
}
function Get-Partition { param($DriveLetter) [pscustomobject]@{ DiskNumber = 0 } }
function Get-Disk { param([Parameter(ValueFromPipeline = $true)]$InputObject) process { [pscustomobject]@{ Number = 0 } } }
function powercfg { 'Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)' }

function Test-Path {
    param([Parameter(Position = 0)]$Path)
    return ($Path -like '*StartupApproved\Run' -or $Path -like '*RebootPending')
}
function Get-Item {
    param([Parameter(Position = 0)]$Path)
    $o = [pscustomobject]@{}
    $o | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @('DisabledThing', 'App1') }
    $o | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param($n)
        # The unary comma stops PowerShell unrolling the array, mimicking RegistryKey.GetValue's byte[]
        if ($n -eq 'DisabledThing') { return , ([byte[]](3, 0, 0, 0)) }
        return , ([byte[]](2, 0, 0, 0))
    }
    $o
}
function Get-ItemProperty {
    [CmdletBinding()]
    param([Parameter(Position = 0)]$Path, $Name)
    if ($Path -like '*PowerSchemes') { return [pscustomobject]@{ ActiveOverlayAcPowerScheme = '961CC777-2547-4F9D-8174-7D86181B8A7A'; ActiveOverlayDcPowerScheme = '' } }
    if ($Path -like '*Session Manager\Power') { return [pscustomobject]@{ HiberbootEnabled = 1 } }
}

. (Join-Path $PSScriptRoot '..' 'pc_mcp' 'windows_probe.ps1')
