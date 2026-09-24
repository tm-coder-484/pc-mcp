# Windows performance evidence for pc-mcp's diagnose_performance tool.
# Read-only. Compatible with Windows PowerShell 5.1. Prints one JSON object on stdout.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$out = [ordered]@{}
$errs = New-Object System.Collections.Generic.List[string]

function Invoke-Section([string]$Name, [scriptblock]$Block, [switch]$NeedsAdmin) {
    try { & $Block }
    catch {
        $msg = $_.Exception.Message
        if ($NeedsAdmin -and -not $script:isAdmin) { $msg = "needs an elevated (Run as administrator) server: $msg" }
        $errs.Add("${Name}: $msg")
    }
}

function Get-EventData($evt, [string]$field) {
    $xml = [xml]$evt.ToXml()
    $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $field } | Select-Object -First 1
    if ($node) { return $node.'#text' }
    return $null
}

$script:isAdmin = $false
try {
    $script:isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch { $errs.Add("is_admin: $($_.Exception.Message)") }
$out['is_admin'] = $script:isAdmin

Invoke-Section 'system' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $out['os_caption'] = $os.Caption
    $out['os_build'] = $os.BuildNumber
    $out['manufacturer'] = $cs.Manufacturer
    $out['model'] = $cs.Model
    $limit = [double]$os.TotalVirtualMemorySize * 1KB
    $free = [double]$os.FreeVirtualMemory * 1KB
    if ($limit -gt 0) {
        $out['commit'] = [ordered]@{
            used_gb      = [math]::Round(($limit - $free) / 1GB, 1)
            limit_gb     = [math]::Round($limit / 1GB, 1)
            used_percent = [math]::Round(100 * ($limit - $free) / $limit, 1)
        }
    }
}

Invoke-Section 'cpu_performance' {
    # Formatted perf counters need two reads to produce a rate; the second one is meaningful.
    $q = "Name='_Total'"
    $null = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter $q
    Start-Sleep -Milliseconds 1200
    $pi = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter $q
    if ([int]$pi.PercentProcessorPerformance -gt 0) {
        $out['processor_performance_percent'] = [int]$pi.PercentProcessorPerformance
    }
    $out['processor_utility_percent'] = [int]$pi.PercentProcessorUtility
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $out['cpu_max_clock_mhz'] = $cpu.MaxClockSpeed
}

Invoke-Section 'power' {
    $txt = (powercfg /getactivescheme) -join ' '
    $m = [regex]::Match($txt, '([0-9a-fA-F]{8}-[0-9a-fA-F-]{27})\s*\((.+)\)')
    $plan = [ordered]@{ guid = $m.Groups[1].Value.ToLower(); name = $m.Groups[2].Value.Trim() }
    $modes = @{
        '961cc777-2547-4f9d-8174-7d86181b8a7a' = 'Best power efficiency'
        '00000000-0000-0000-0000-000000000000' = 'Balanced'
        '3af9b8d9-7c97-431d-ad78-34a8bfea439f' = 'Better performance'
        'ded574b5-45a0-4f42-8737-46345c09c238' = 'Best performance'
    }
    $ps = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' -ErrorAction SilentlyContinue
    if ($ps) {
        foreach ($pair in @(@('ActiveOverlayAcPowerScheme', 'power_mode_ac'), @('ActiveOverlayDcPowerScheme', 'power_mode_dc'))) {
            $g = [string]$ps.($pair[0])
            if ($g) {
                $name = $modes[$g.ToLower()]
                if (-not $name) { $name = $g }
                $plan[$pair[1]] = $name
            }
        }
    }
    $out['power_plan'] = $plan
}

Invoke-Section 'physical_disks' {
    $sysDisk = $null
    try { $sysDisk = (Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) | Get-Disk).Number } catch { }
    $out['physical_disks'] = @(Get-PhysicalDisk | ForEach-Object {
            [ordered]@{
                name       = $_.FriendlyName
                media_type = [string]$_.MediaType
                bus_type   = [string]$_.BusType
                health     = [string]$_.HealthStatus
                size_gb    = [math]::Round($_.Size / 1GB, 0)
                is_system  = ($null -ne $sysDisk -and [string]$_.DeviceId -eq [string]$sysDisk)
            }
        })
}

Invoke-Section 'event_log' {
    $since = (Get-Date).AddDays(-7)
    $sys = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $since } -MaxEvents 5000 -ErrorAction SilentlyContinue)
    $storage = '^(disk|Ntfs|Microsoft-Windows-Ntfs|storahci|stornvme|iaStor.*|nvme.*|volmgr|Microsoft-Windows-StorPort)$'
    $out['disk_errors_7d'] = @($sys | Where-Object { $_.ProviderName -match $storage -and $_.Id -ne 98 }).Count
    $out['hardware_errors_7d'] = @($sys | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WHEA-Logger' }).Count
    $out['unexpected_shutdowns_7d'] = @($sys | Where-Object {
            ($_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41) -or
            ($_.ProviderName -eq 'Microsoft-Windows-WER-SystemErrorReporting' -and $_.Id -eq 1001) }).Count
    $out['low_memory_events_7d'] = @($sys | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Resource-Exhaustion-Detector' }).Count
    $out['system_errors_7d_top'] = @($sys | Where-Object { $_.Level -le 2 } | Group-Object ProviderName, Id |
        Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
            $first = $_.Group[0]
            $msg = ''
            try { $msg = ($first.Message -replace '\s+', ' ') } catch { }
            if ($msg.Length -gt 180) { $msg = $msg.Substring(0, 180) }
            [ordered]@{ source = $first.ProviderName; id = $first.Id; count = $_.Count; last = $first.TimeCreated.ToString('s'); example = $msg }
        })
    $app = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error', 'Application Hang'; StartTime = $since } -MaxEvents 500 -ErrorAction SilentlyContinue)
    $hangs = [ordered]@{}
    $app | ForEach-Object { [string]$_.Properties[0].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 |
        ForEach-Object { $hangs[$_.Name] = $_.Count }
    $out['app_hangs_7d'] = $hangs
}

Invoke-Section 'boot_performance' -NeedsAdmin {
    $log = 'Microsoft-Windows-Diagnostics-Performance/Operational'
    $boot = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 100 } -MaxEvents 1
    $out['last_boot_duration_ms'] = [int](Get-EventData $boot 'BootTime')
    $out['last_boot_at'] = $boot.TimeCreated.ToString('s')
    $slow = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 101, 102, 103, 106, 109; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 60 -ErrorAction SilentlyContinue)
    $out['slow_boot_culprits'] = @($slow | ForEach-Object {
            $n = Get-EventData $_ 'FriendlyName'
            if (-not $n) { $n = Get-EventData $_ 'Name' }
            $n
        } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { $_.Name })
}

Invoke-Section 'startup_apps' {
    $approved = @{}
    foreach ($root in 'HKCU:', 'HKLM:') {
        foreach ($sub in 'Run', 'Run32', 'StartupFolder') {
            $k = "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sub"
            if (Test-Path $k) {
                $item = Get-Item $k
                foreach ($v in $item.GetValueNames()) {
                    # REG_BINARY; first byte 0x02/0x06 = enabled, odd values (0x03/0x07) = disabled in Task Manager
                    $bytes = @($item.GetValue($v))
                    if ($bytes.Count -gt 0) { $approved[$v.ToLower()] = (([int]$bytes[0] -band 1) -eq 0) }
                }
            }
        }
    }
    $enabled = New-Object System.Collections.Generic.List[object]
    $disabled = 0
    foreach ($s in @(Get-CimInstance Win32_StartupCommand)) {
        $isOn = $true
        $keys = @([string]$s.Name, [string]$s.Command) | ForEach-Object { $_.ToLower() }
        foreach ($k in $keys) { if ($approved.ContainsKey($k)) { $isOn = $approved[$k]; break } }
        if (-not $isOn) { $disabled++; continue }
        $cmd = [string]$s.Command
        if ($cmd.Length -gt 160) { $cmd = $cmd.Substring(0, 160) }
        $enabled.Add([ordered]@{ name = $s.Name; command = $cmd; location = $s.Location })
    }
    $out['startup_apps'] = $enabled.ToArray()
    $out['startup_apps_disabled'] = $disabled
}

Invoke-Section 'reboot_state' {
    $out['pending_reboot'] = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    $hb = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue
    $out['fast_startup'] = ($null -ne $hb -and $hb.HiberbootEnabled -eq 1)
}

Invoke-Section 'antivirus' {
    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
    # productState bits 12-15 == 1 means real-time protection is on
    $out['antivirus_products'] = @($av | Where-Object { (([int]$_.productState -shr 12) -band 0xF) -eq 1 } |
        Select-Object -ExpandProperty displayName -Unique)
}

Invoke-Section 'gpu' {
    $out['gpus'] = @(Get-CimInstance Win32_VideoController | ForEach-Object {
            $date = $null
            if ($_.DriverDate) { $date = $_.DriverDate.ToString('yyyy-MM-dd') }
            [ordered]@{ name = $_.Name; driver_version = $_.DriverVersion; driver_date = $date }
        })
}

Invoke-Section 'thermal' -NeedsAdmin {
    $tz = @(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature)
    $out['acpi_thermal_c'] = @($tz | ForEach-Object { [math]::Round($_.CurrentTemperature / 10 - 273.15, 1) })
}

$out['errors'] = $errs.ToArray()
$out | ConvertTo-Json -Depth 6 -Compress
