# SPDX-License-Identifier: GPL-2.0-only
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'evidence/windows-hardware.json')
)
$ErrorActionPreference = 'Stop'

function Read-NamedRegistryValues {
    param([string]$SubKey, [string[]]$Names)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey)
    if ($null -eq $key) { throw "Registry key unavailable: $SubKey" }
    try {
        $values = [ordered]@{}
        foreach ($name in $Names) {
            $value = $key.GetValue($name, $null)
            if ($value -is [string]) { $value = $value.Trim() }
            $values[$name] = $value
        }
        return $values
    } finally {
        $key.Dispose()
    }
}

$bios = Read-NamedRegistryValues 'HARDWARE\DESCRIPTION\System\BIOS' @(
    'BaseBoardManufacturer', 'BaseBoardProduct', 'BaseBoardVersion',
    'BIOSVendor', 'BIOSVersion', 'BIOSReleaseDate'
)
if ($bios.BaseBoardProduct -ne 'B550M GAMING X WIFI6') {
    throw "Expected B550M GAMING X WIFI6; reported: $($bios.BaseBoardProduct)"
}
$cpu = Read-NamedRegistryValues 'HARDWARE\DESCRIPTION\System\CentralProcessor\0' @(
    'ProcessorNameString', 'Identifier', 'VendorIdentifier'
)
$pciIds = [System.Collections.Generic.HashSet[string]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()
$pciKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    'SYSTEM\CurrentControlSet\Enum\PCI'
)
if ($null -eq $pciKey) {
    $warnings.Add('PCI registry inventory unavailable.')
} else {
    try {
        foreach ($deviceName in $pciKey.GetSubKeyNames()) {
            $deviceKey = $pciKey.OpenSubKey($deviceName)
            if ($null -eq $deviceKey) { continue }
            try {
                foreach ($instanceName in $deviceKey.GetSubKeyNames()) {
                    $instanceKey = $deviceKey.OpenSubKey($instanceName)
                    if ($null -eq $instanceKey) { continue }
                    try {
                        foreach ($hardwareId in @($instanceKey.GetValue('HardwareID', @()))) {
                            if ($hardwareId -is [string] -and $hardwareId.StartsWith('PCI\')) {
                                [void]$pciIds.Add($hardwareId)
                            }
                        }
                    } finally {
                        $instanceKey.Dispose()
                    }
                }
            } finally {
                $deviceKey.Dispose()
            }
        }
    } catch {
        $warnings.Add('Some PCI registry entries could not be read.')
    } finally {
        $pciKey.Dispose()
    }
}
$report = [ordered]@{
    schema_version = 1
    source = 'Selected Windows registry reports; no direct hardware probing'
    bios = $bios
    cpu = $cpu
    physical_board_revision = $null
    pci_hardware_ids = @($pciIds | Sort-Object)
    limitations = @(
        'Read the PCB revision from the board.',
        'CPU Identifier is an OS report, not a direct CPUID result.',
        'PCI registry IDs can include historical devices and do not reveal routing.',
        'No flash-chip, GPIO, SPD, Super I/O, ACPI, or PCI-register measurements.'
    )
    warnings = @($warnings)
}
$absoluteOutput = [System.IO.Path]::GetFullPath($OutputPath)
[void][System.IO.Directory]::CreateDirectory(
    [System.IO.Path]::GetDirectoryName($absoluteOutput)
)
[System.IO.File]::WriteAllText(
    $absoluteOutput, ($report | ConvertTo-Json -Depth 6) + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output "Saved selected hardware reports to $absoluteOutput"
