:: source https://github.com/atlantsecurity/windows-hardening-scripts/blob/main/Windows-10-Hardening-script.cmd

:: Enable SMB/LDAP Signing
:: Sources:
:: http://eddiejackson.net/wp/?p=15812
:: https://en.hackndo.com/ntlm-relay/
:: ---------------------
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
:: 1- Negotiated; 2-Required
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\ldap" /v "LDAPClientIntegrity " /t REG_DWORD /d 1 /f

:: prevent Allowed Null Session
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f

:: Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f

:: Enable SmartScreen for Edge
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
:: Enable Notifications in IE when a site attempts to install software
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
:: Disable Edge password manager to encourage use of proper password manager
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f


:: EDGE HARDENING ::
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SitePerProcess" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLVersionMin" /t REG_SZ /d "tls1.2^@" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NativeMessagingUserLevelHosts" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverrideForFiles" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLErrorOverrideAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0x00000000" /f

:: disable Cached Logon Credential
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "cachedlogonscount" /t REG_DWORD /d "0x00000000" /f


:: Defender
setx /M MP_FORCE_USE_SANDBOX 1
::
::Enable Windows Defender sandboxing
setx /M MP_FORCE_USE_SANDBOX 1
:: Update signatures

"%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
:: Enable Defender signatures for Potentially Unwanted Applications (PUA)
powershell.exe Set-MpPreference -PUAProtection enable
:: Enable Defender periodic scanning
reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f

:: Enable early launch antimalware driver for scan of boot-start drivers
:: 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f

:: Enable Network protection
:: Enabled - Users will not be able to access malicious IP addresses and domains
:: Disable (Default) - The Network protection feature will not work. Users will not be blocked from accessing malicious domains
:: AuditMode - If a user visits a malicious IP address or domain, an event will be recorded in the Windows event log but the user will not be blocked from visiting the address.
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled


:: Removal Media Settings
:: Disable autorun/autoplay on all drives
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
::

::Disable AutoRun
:: ---------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
::

:: Stop NetBIOS over TCP/IP
wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
:: Disable NTLMv1
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
:: Disable Powershellv2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
::

::
::#######################################################################
:: Windows 10 Privacy Settings
::#######################################################################
::

:: Disable the advertising ID
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

:: Set Windows Analytics to limited enhanced if enhanced is enabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
:: Set Windows Telemetry to security only
:: If you intend to use Enhanced for Windows Analytics then set this to "2" instead
:: Note my understanding is W10 Home edition will do a minimum of "Basic"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f
:: Disable location data
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f
:: Prevent the Start Menu Search from providing internet results and using your location
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
:: Disable publishing of Win10 user activity
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f

:: Disable Microsoft consumer experience which prevent notifications of suggested applications to install
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f

:: Disable websites accessing local language list
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f


:: logging
:: Enable PowerShell Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
::
:: Enable Windows Event Detailed Logging
:: This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
:: For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
:: Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
:: Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

:: remove unwanted applications
powershell.exe -command "Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.NET.Native.Framework.1.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage"

:: Removed Provisioned Apps
:: This will prevent these apps from being reinstalled on new user first logon
:: Obviously I manually chose this list. If you truly want to nuke all the provisioned apps, you can use the below commented command in PowerShell
:: Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Microsoft3DViewer'} | Remove-AppxProvisionedPackage -Online"

::
::
::#######################################################################
:: Enable and Configure Google Chrome Internet Browser Settings
::#######################################################################
::
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f

::
:: #####################################################################
:: Chrome hardening settings
:: #####################################################################
reg add "HKLM\Software\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "RemoteAccessHostFirewallTraversal" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultPopupsSetting" /t REG_DWORD /d "33554432" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "33554432" /f

reg add "HKLM\Software\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AutoplayAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d "tls1.1" /f

:: Harden all version of MS Office against common malspam attacks
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Options\vpref\fNoCalclinksOnopen_90_1" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Options\DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Security" /v AllowDDE /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Options\DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security" /v AllowDDE /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Options\DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v AllowDDE /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\Security" /v DisableAllActiveX /t REG_DWORD /d 1 /f


CVE-2013-3900 - WinVerifyTrust Signature Validation Vulnerability
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config " /v EnableCertPaddingCheck /t REG_DWORD /d 1 /f
