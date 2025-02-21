# BuddyGPO_EntraIntune - v0.12 by jm@cloudware.host

Import-Module GroupPolicy

function Show-SubMenu {
    param (
        [string]$Title = 'Select GPOs for Provisioning'
    )
    Clear-Host
    Write-Host "================ $Title =================="
    Write-Host "1: Create Azure Hybrid Join Policy"
    Write-Host "2: Create MDM Auto Enrollment Policy"
    Write-Host "3: Enable WinRM Policy"
    Write-Host "4: Allow WinRM Windows Firewall Policy"
    Write-Host "Q: Back to Main Menu"
}

function Create-HybridJoinGPO {
    param (
        [string]$DomainName,
        [string]$OUPath
    )
    $GPOName = "Azure Hybrid Join Policy - Updated"
    if (-not (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $GPOName | Out-Null
        Write-Host "GPO '$GPOName' created successfully."
    } else {
        Write-Host "GPO '$GPOName' already exists."
    }
    $DeviceRegPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin"
    $HybridJoinSettings = @(
        @{ Name = "AutoWorkplaceJoin"; Type = "DWord"; Value = 1 },
        @{ Name = "WamDefaultSetTenant"; Type = "String"; Value = "yes" }
    )
    foreach ($Setting in $HybridJoinSettings) {
        Set-GPRegistryValue -Name $GPOName -Key $DeviceRegPath -ValueName $Setting.Name -Type $Setting.Type -Value $Setting.Value
        Write-Host "Configured '$($Setting.Name)' in '$GPOName'."
    }
    $DeviceRegistrationPolicyPath = "Computer Configuration\Policies\Administrative Templates\Windows Components\Device Registration"
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Registration" -ValueName "EnableDeviceRegistration" -Type DWord -Value 1
    Write-Host "Enabled 'Device Registration' in '$GPOName'."
    New-GPLink -Name $GPOName -Target $OUPath -Enforced Yes
    $GroupName = "Domain Computers"
    Set-GPPermission -Name $GPOName -PermissionLevel GpoApply -TargetName $GroupName -TargetType Group
    Write-Host "GPO '$GPOName' linked to '$OUPath' and applied to '$GroupName'."
    Invoke-Command -ScriptBlock { gpupdate /force /quiet } -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name) -AsJob
    Write-Host "Azure Hybrid Join Policy GPO configured successfully!"
}

function Create-MDMAutoEnrollGPO {
    param (
        [string]$DomainName,
        [string]$OUPath
    )
    $GPOName = "MDM Auto Enrollment"
    if (-not (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $GPOName | Out-Null
        Write-Host "GPO '$GPOName' created successfully."
    } else {
        Write-Host "GPO '$GPOName' already exists."
    }
    $MDMPath = "Software\Policies\Microsoft\Windows\CurrentVersion\MDM"
    $RegistrySettings = @(
        @{ Name = "AutoEnrollMDM"; Type = "DWord"; Value = 1 },
        @{ Name = "UseAADCredential"; Type = "DWord"; Value = 1 }
    )
    $GPO = Get-GPO -Name $GPOName
    foreach ($Setting in $RegistrySettings) {
        Set-GPRegistryValue -Name $GPOName -Key "HKLM\$MDMPath" -ValueName $Setting.Name -Type $Setting.Type -Value $Setting.Value
        Write-Host "Configured $($Setting.Name) in '$GPOName'."
    }
    New-GPLink -Name $GPOName -Target $OUPath -Enforced Yes
    $GroupName = "Domain Users"
    $GroupDN = Get-ADGroup -Identity $GroupName | Select-Object -ExpandProperty DistinguishedName
    Set-GPPermission -Name $GPOName -PermissionLevel GpoApply -TargetName $GroupName -TargetType Group
    Write-Host "GPO linked to '$OUPath' and applied to '$GroupName'."
    Invoke-Command -ScriptBlock { gpupdate /force } -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name)
    Write-Host "GPO configuration completed successfully!"
}

function Create-WinRMGPO {
    param (
        [string]$DomainName,
        [string]$OUPath
    )
    $GPOName = "Enable WinRM"
    if (-not (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $GPOName | Out-Null
        Write-Host "GPO '$GPOName' created successfully."
    } else {
        Write-Host "GPO '$GPOName' already exists."
    }
    $WinRMSettings = @(
        @{ Path = "Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service"; Name = "Allow remote server management through WinRM"; State = "Enabled" },
        @{ Path = "Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client"; Name = "Allow unencrypted traffic"; State = "Enabled" },
        @{ Path = "Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client"; Name = "Trusted Hosts"; State = "Enabled"; Value = "*" }
    )
    foreach ($Setting in $WinRMSettings) {
        Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\$($Setting.Name)" -Type String -Value $Setting.State
        Write-Host "Configured '$($Setting.Name)' in '$GPOName'."
    }
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\AuthorizedApplications\List" -ValueName "%SystemRoot%\System32\svchost.exe" -Type String -Value "TCP:5985:*:Enabled:WinRM"
    New-GPLink -Name $GPOName -Target $OUPath -Enforced Yes
    $GroupName = "Domain Computers"
    Set-GPPermission -Name $GPOName -PermissionLevel GpoApply -TargetName $GroupName -TargetType Group
    Write-Host "GPO '$GPOName' linked to '$OUPath' and applied to '$GroupName'."
    Invoke-Command -ScriptBlock { gpupdate /force /quiet } -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name) -AsJob
    Write-Host "WinRM GPO configuration completed successfully!"
}

function Create-WinRMFirewallGPO {
    param (
        [string]$DomainName,
        [string]$OUPath
    )
    $GPOName = "Allow WinRM Windows Firewall"
    if (-not (Get-GPO -Name $GPOName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $GPOName | Out-Null
        Write-Host "GPO '$GPOName' created successfully."
    } else {
        Write-Host "GPO '$GPOName' already exists."
    }
    $FirewallPath = "Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security\Inbound Rules"
    $WinRMFirewallRules = @(
        @{ Name = "Allow WinRM HTTP (TCP 5985)"; Port = 5985; Protocol = "TCP"; Action = "Allow" },
        @{ Name = "Allow WinRM HTTPS (TCP 5986)"; Port = 5986; Protocol = "TCP"; Action = "Allow" }
    )
    foreach ($Rule in $WinRMFirewallRules) {
        Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -ValueName "$($Rule.Name)" -Type String -Value "v2.10|Action=$($Rule.Action)|Active=TRUE|Dir=In|Protocol=$($Rule.Protocol)|LPort=$($Rule.Port)|RA4=*"
        Write-Host "Configured firewall rule: $($Rule.Name) in '$GPOName'."
    }
    New-GPLink -Name $GPOName -Target $OUPath -Enforced Yes
    $GroupName = "Domain Computers"
    Set-GPPermission -Name $GPOName -PermissionLevel GpoApply -TargetName $GroupName -TargetType Group
    Write-Host "GPO '$GPOName' linked to '$OUPath' and applied to '$GroupName'."
    Invoke-Command -ScriptBlock { gpupdate /force /quiet } -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name) -AsJob
    Write-Host "Firewall GPO for WinRM configured successfully!"
}

function Show-Menu {
    param (
        [string]$Title = 'BuddyGPO_EntraIntune v0.12 | By jm@cloudware.host'
    )
    Clear-Host
    Write-Host "================ $Title =================="
    Write-Host "1: Create GPOs"
    Write-Host "2: Set Domain/OU Path"
    Write-Host "3: Set Execution Policy to Unrestricted for Current User"
    Write-Host "Q: Quit"
}

$domainName = ""
$ouPath = ""

do {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection) {
        '1' {
            if ([string]::IsNullOrEmpty($domainName) -or [string]::IsNullOrEmpty($ouPath)) {
                Write-Host "Domain and OU path must be set first."
                Pause
                continue
            }
            do {
                Show-SubMenu
                $subSelection = Read-Host "Please make a selection"
                switch ($subSelection) {
                    '1' { Create-HybridJoinGPO -DomainName $domainName -OUPath $ouPath }
                    '2' { Create-MDMAutoEnrollGPO -DomainName $domainName -OUPath $ouPath }
                    '3' { Create-WinRMGPO -DomainName $domainName -OUPath $ouPath }
                    '4' { Create-WinRMFirewallGPO -DomainName $domainName -OUPath $ouPath }
                }
                Pause
            } until ($subSelection -eq 'q')
        }
        '2' {
            $domainName = Read-Host "Enter your domain name (e.g., DC=DOMAIN,DC=COM)"
            $ouPath = Read-Host "Enter the OU path or domain root for GPO linking"
        }
        '3' { Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force; Write-Host "Execution Policy set to Unrestricted for Current User." }
    }
    Pause
} until ($selection -eq 'q')