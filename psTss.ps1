# Script: psTSS.ps1 - for help, type: get-help .\psTSS.ps1
#requires -version 4
#requires -RunAsAdministrator
#requires -Modules NetEventPacketCapture

#region ::::: psTSS intro :::::
<#
	Best Practice Reference: https://github.com/PoshCode/PowerShellPracticeAndStyle

	runs only on Win8.1/2012-R2 or later

	TO-DO:
      - Add persistent switch
#>

<#	LIMITED USE LICENSE
    
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
	WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


    This PowerShell script (the “software”) is provided AS-IS with no warranties or guarantees, explicit
    or implied, and is to be used exclusively for troubleshooting in conjunction with an active and open
    Microsoft support case (the “case”). By using the software the Microsoft support case customer (the
    “customer”) agrees to abide by this agreement. The software is provided to assist with complex data
    collection needed for specific supports cases. Use of the software without direction from Microsoft
    support is strictly prohibited.

    While the software has been internally tested, Microsoft can make no guarantees that the software will
    operate without issue in the customer environment. Microsoft cannot guarantee that by using the software
    all the necessary information for the case will be gathered. The customer should test the software in a
    similar QA or testing environment prior to any use in a production environment. Microsoft support will make
    a best effort, deemed appropriate by Microsoft support, to assist with software use to collect case pertinent
    data. If the software does not work as intended the Microsoft support agent may decide to use an alternate
    method rather than supporting, updating, or fixing the software.

    The software will NOT be serviced, updated, fixed, or in any way supported once the case for which the
    software was provided has been closed. Any support requests for the software sent to Microsoft, including
    all Microsoft support entities, after case closure, archival, contract expiration, or any other disengagement
    of troubleshooting will be denied.


    PRIVACY NOTICE

    This PowerShell script gathers network data and diagnostics information from a Windows system. This data
    should only be sent to Microsoft through the secure upload workspace provided by the support engineer to
    ensure it is securely sent to Microsoft. Microsoft policy requires that all customer data be stored on secured
    and fulled encrypted systems. Every precaution is taken to ensure your data remains safe.

    The data will only be used to troubleshoot the case issue. All case data sent to Microsoft will be deleted
    within 90 days of case closure.
#>

<# 
.SYNOPSIS
The PowerShell based TSS TroubleShootingScript/toolset psTSS.ps1 is intended for rapid flexible data collection.
Collects data on system and network configuration for diagnosing Microsoft Windows issues.

If you receive the error '...is not digitally signed.' or "psTSS.ps1 cannot be loaded because running scripts is disabled on this system."
	then enable execution of scripts for the current PowerShell window with the following:
      Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
	or see https://blogs.msdn.microsoft.com/pasen/2011/12/07/set-executionpolicy-windows-powershell-updated-your-execution-policy-successfully-but-the-setting-is-overridden-by-a-policy-defined-at-a-more-specific-scope/
	
SYNTAX: .\psTSS.ps1 [trace options] [component options]
Trace options:
	-Trace           # perform network sniff
	-scenario        # comma separated scenario names of NETSH trace scenarios to collect from, example: 'wlan_dbg','wwan_dbg'
	-level           # level at which to capture ETL, Level 0x4 is used when no level is passed.
	-noCapture       # does not capture packets, only ETW events
	-udpOnly         # capture only UDP packets, usefull for Cluster heartbeat scenarios, or DNS server
	-PromiscuousMode # capture in promiscuous mode (captures all packets whether they are destined for the interface or not, helpful with doing port mirroring (SPAN))
	-chooseNics      # capture on NICS, [default: 1 = $True]
	-CaptureMode     # [SaveToFile|RealtimeRPC|RealtimeLocal]
	-truncBytes      # sets the number of bytes to collect of each captured packet
	-maxSize         # maximum size in MB of the circular ETL file
	-TraceBufferSize # the amount of memory, in kilobytes, for a buffer for event tracing. Maximum = 1024.
	-dbg             # use optional debug options for ETL tracing
Component options:
	-Auth            # collect Authentication logs (Kerberos, NTLM, SSL, negoexts, pku2u, Http)
	-Bluetooth       # collect Bluetooth events, logs, and data.
	-CSVspace        # collect CSV_space ETL-log
	-DCOM            # collect DCOM ETL-log, Reg-settings and SecurityDescriptor info
	-BITS            # collect BITS events, logs, and data.
	-DAsrv           # collect DirectAccess server ETL-log and Eventlog
	-DFSsrv          # collect DFS server ETL-log and Eventlog
	-DHCPcli         # collect DHCP client events, logs, and data.
	-DHCPsrv         # collect DHCP server events, logs, and data.
	-DNScli          # collect DNS client events, logs, and data.
	-DNSsrv          # collect DNS server events, logs, and data.
	-EvtHoursBack         # number of hours back, for Eventlog
	-GPresult        # collect GPresult
	-HyperV          # collect Hyper-V server events, logs, and data. (includes LBFO)
	-IPsec           # collect IPsec events
	-LBFO            # collect LBFO teaming events
	-mini            # collect only minimal data, no supporting information data like Sysinfo, Tasklist, Services, Registry hives
	-MsInfo32        # collect MSinfo32
	-NetBase         # Network Base Event Tracing
	-NetIso          # collect Network Isolation events, logs, and data.
	-NPS             # collect Network Policy Server NPS events, logs, and data.
	-Perfmon         # option to collect Perfmon logging
	-ProcDump Pname.exe # option to collect ProcDumps of process
	-ProcMon         # option to collect ProcMon logging
	-PSR             # enable Problem Steps Recooder (PSR)
	-SMBcli          # collect SMB client events, logs, and data.
	-SMBsrv          # collect SMB File Server events, logs, and data.
	-RAS             # collect RAS Server/Client events, logs, and data.
	-RDMA            # collect RDMA events, logs, and data. (includes LBFO)
	-SysFileVer      # collect System File Versions
	-WinHTTP         # collect WinHTTP events, logs, and data.
	-Wireless        # collect Wireless events, logs, and data. On Surface, add -Surface
	 -Surface        # use Surface WiFi debug options
	-WLAN            # collect WLAN/Wireless events, logs, and data. On Surface, add -Surface
	-WPR             # option to collect WPR logging
	-WWAN            # collect WWAN events, logs, and data.
	-WinSock         # collect WinSock data.
	-NoZip           # use to skip zipping data
	-verbose         # use to see onscreen progress messages
Utils:
	-Ports           # use to get onetime overview of TCP/UDP ports usage by process
	-PortExhaust h   # use to collect longterm view of TCP/UDP port usage, default: 24 h
	-BindWatch portNr # TCP port watcher, stop once rebind of given port happens, default port: 3389

.DESCRIPTION
The script will trace relavant data for troubleshooting at time of failure / repro scenario.
By default it will ask for NIC interface(s) which shall be traced ([A] for All)
Without any additional options specified it will collect network sniff and basic network dubug logs (.etl)

After initialization, the script will wait at stage:
 " === Reproduce the issue then press the 's' key to stop tracing. ==="
and finish data collection after you hit 's'.

.PARAMETER ComputerNames
	Defines on which Computers you want to run the script (Default is local Host)

.PARAMETER LogPathLocal
	Path where we store the data (default is SystemDrive\MS_DATA\DataTime; e.g. C:\MS_DATA\180925-101214)

.PARAMETER HoursBack
	How much Hours should we look back in the data and collect them
	
.PARAMETER EventLogNames
	Define the Eventlogs you want to gather; Wildcard * is allowed
	Sample: -EventLogNames "System", "Application", "*CSVFS*", "*Smb*", "*winrm*", "*wmi*", "*spaces*" 
	
.EXAMPLE
 .\psTSS.ps1 -DNSsrv -udpOnly -verbose

.EXAMPLE
  .\psTSS.ps1 -noCapture -GPresult -MsInfo32 -SysFileVer -NoZip

.LINK
Download on https://github.com/walter-1/psTSS
internal KB: https://internal.support.services.microsoft.com/en-us/help/4089531
waltere@microsoft.com

#>

#endregion ::::: psTSS intro :::::


#region ::::: Script Input PARAMETERS :::::
[CmdletBinding()]param(
        ## Trace scenario parameters
        [Parameter(Position=0,HelpMessage='Scenario, see HKLM:\SYSTEM\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses')]
         [string[]]$Scenario = '',									# comma separated scenario names of netsh trace scenarios to collect from, example: 'wlan_dbg','wwan_dbg'
        [Parameter(Position=1)]
         [AllowNull()]
         [byte]$Level = '',											# level at which to capture ETL
        [Parameter(Position=2)]
        [int]$maxSize = 1024,										# maximum size in MB of the circular ETL file
        [int]$TraceBufferSize = 1024,								# Specifies the amount of memory, in kilobytes, for a buffer for event tracing. The maximum value is 1024.
        [byte]$MaxNumberOfBuffers = [Byte]::MaxValue,				# Specifies the maximum number of buffers used in a session.
        ### packet capture parameters ###
        [ValidateSet("SaveToFile", "RealtimeRPC", "RealtimeLocal")]	## New-NetEventSession options ##
		[Parameter(Position=3,HelpMessage='Choose SaveToFile|RealtimeRPC|RealtimeLocal')]
         [string]$CaptureMode = "SaveToFile",
		 <# save modes:         -- SaveToFile. Saves the capture to an .etl file.
								-- RealtimeRPC. Connects remotely for a live event and packet capture.
								-- RealtimeLocal. Connects locally for a live event and packet capture.
         #>

        ## Add-NetEventPacketCaptureProvider options ##
        [ValidateSet("Physical", "Switch", "BothPhysicalAndSwitch")]
		[Parameter(Position=4,HelpMessage='Choose Physical|Switch|BothPhysicalAndSwitch')]
        <# Specifies whether the packet capture is enabled for physical network adapters, virtual switches, or both. The acceptable values for this parameter are:
            -	Physical. Captures packets from physical network adapters.
            -	Switch. Captures packets from the virtual machine switch(es) on Hyper-V hosts.
            -	BothPhysicalAndSwitch. Captures packets from both the physical network adapters and the virtual machine switch(es).
		#>
        [string]$captureType = "Physical",
        [byte]$capLevel = 0x4,							# packet capture level. Should remain 0x4 unless you know what you're doing. No packets are captured below 0x4.
        [ValidateRange(64,65535)]
         [int]$truncBytes = 1500,						# sets the number of bytes to collect of each captured packet
        [Switch]$udpOnly = $false,						# capture only UDP packets

		## session parameters ##
        [string]$tracePath = "$ENV:SYSTEMDRIVE\MS_DATA",# base file path for the data collection
        [string]$Date_time = "$(get-date -format "yyyyMMdd_HHmmss")",	# base name used for NetEventSession, capture files and folders
        
        ## Add-NetEventNetworkAdapter options ##
        # this function prompts the user to select the NIC(s) to capture when there is more than one available NIC
		[bool]$chooseNics	= $true,					# offers a selection of NICS for capturing packet sniff
        [Switch]$Trace		= $false,					# perform network sniff, does capture packets
        [Switch]$NetBase	= $false,					# Network Base Event Tracing
        ## miscellaneous flags ##
        [Switch]$PromiscuousMode = $false,				# capture in promiscuous mode (captures all packets whether they are destined for the interface or not, helpful with doing port mirroring (SPAN))
        [Switch]$noCapture 	= $false,					# does not capture packets, only ETW events
        #[switch]$persistent = $false,					# capture survives a single reboot
		[switch]$Auth		= $false,              		#-+ scenario: Authentication logs ^(Kerberos, NTLM, SSL, negoexts, pku2u, Http^), network trace, Procmon, SDP
		[switch]$Bluetooth  = $false,					# collect Bluetooth events, logs, and data.
		[switch]$CSVspace 	= $false,					# collect CSV_space ETL-log
		[switch]$DCOM 		= $false,					# collect DCOM ETL-log, Reg-settings and SecurityDescriptor info
		[switch]$SysFileVer = $false,					# collect System File Versions
        [Switch]$psr 		= $false,					# enable Problem Steps Recooder (PSR)
        [Switch]$Perfmon 	= $false,					# Option/switch to collect Perfmon logging
        [string]$ProcDump 	= '',						# Option/switch to collect ProcDumps
        [Switch]$WPR 		= $false,					# Option/switch to collect WPR logging
		[switch]$ProcMon 	= $false,					# option to collect ProcMon logging
		[switch]$MsInfo32 	= $false,					# collect MSinfo32
		[switch]$GPresult 	= $false,					# collect GPresult
		[switch]$BITS 		= $false,					# collect BITS events, logs, and data.
		[switch]$DFSsrv		= $false,					# collect DFS server ETL-log and Eventlog
		[switch]$DAsrv 		= $false,					# collect DirectAccess server ETL-log and Eventlog
		[switch]$DHCPcli 	= $false,					# collect DHCP client events, logs, and data.
		[switch]$DHCPsrv 	= $false,					# collect DHCP server events, logs, and data.
		[switch]$DNScli 	= $false,					# collect DNS client events, logs, and data.
		[switch]$DNSsrv 	= $false,					# collect DNS server events, logs, and data.
		[switch]$HyperV 	= $false,					# collect Hyper-V server events, logs, and data.
		[switch]$IPsec 		= $false,					# collect IPsec events
		[switch]$LBFO 		= $false,					# collect LBFO teaming events
		[switch]$NetIso 	= $false,					# collect Network Isolation events, logs, and data.
		[switch]$NPS 		= $false,					# collect Network Policy Server NPS events, logs, and data.
		[switch]$RAS 		= $false,					# collect Server/Client RAS events, logs, and data.
		[switch]$RDMA 		= $false,					# collect RDMA events, logs, and data.
		[switch]$SMBcli		= $false,					# collect SMB client events, logs, and data.
		[switch]$SMBsrv		= $false,					# collect SMB File Server events, logs, and data.
		[switch]$SMBshareWatch= $false,					# collect SMB File Server Watch events, logs, and data.
		[switch]$WinHTTP 	= $false,					# collect WinHTTP events, logs, and data.
		[switch]$Wireless 	= $false,					# collect Wireless events, logs, and data. On Surface, add -Surface
		[switch]$WLAN    	= $false,					# collect WLAN/Wireless events, logs, and data. On Surface, add -Surface
		 [Switch]$Surface	= $false,					# use Surface WiFi debug options
		[switch]$WWAN 		= $false,					# collect WWAN events, logs, and data.
		[switch]$WinSock	= $false,					# collect WinSock data.
        [Switch]$dbg 		= $false,					# use optional debug options for ETL tracing
		[switch]$NoZip 		= $false,					# use to skip zipping data
		[switch]$mini 		= $false,            		# collect only minimal data, no supporting information data like Sysinfo, Tasklist, Services, Registry hives
		[switch]$Ports 		= $false,					# use to get onetime overview of TCP/UDP ports usage by process
		[int32]$PortExhaust,							# use to collect longterm view of TCP/UDP port usage, script default: 24 h
		[int32]$BindWatch,								# TCP port watcher, script default port: 3389
		[int32]$script:EvtHoursBack						# number of hours back, for Eventlog extract, script default: 0 = no limit
)

$ScriptVer = "1.05"	#Date: 2018-11-19
Write-Host "*** v$ScriptVer - Don't click inside the script window while processing as it will cause the script to pause. ***"  -ForegroundColor Yellow
#endregion ::::: Script Input PARAMETERS :::::


#region ::::: Global Variables ::::: 
    # Section for global variables, which you don´t want to show up in the parameter region        
    [bool]$IsCluster = $False						# define script scope variable, whether we are running the script on a cluster or not
    $TimeStampScriptStart = Get-Date				# get the timestamp, when this script starts
    $TimeStampStartSaved = $TimeStampScriptStart	# only first time save the script start timestamp
    
#endregion ::::: Global Variables ::::: 


#region ::::: FUNCTIONS :::::
#region ::::: Helper Functions ::::

function Show-help { 
# SYNOPSIS: display options
Write-Host "
SYNTAX: .\psTSS.ps1 [trace options] [component options]
Trace options:
	-Trace           # perform network sniff
	-scenario        # comma separated scenario names of NETSH trace scenarios to collect from, example: 'wlan_dbg','wwan_dbg'
	-level           # level at which to capture ETL, Level 0x4 is used when no level is passed.
	-noCapture       # does not capture packets, only ETW events
	-udpOnly         # capture only UDP packets, usefull for Cluster heartbeat scenarios, or DNS server
	-PromiscuousMode # capture in promiscuous mode (captures all packets whether they are destined for the interface or not, helpful with doing port mirroring (SPAN))
	-chooseNics      # capture on NICS, [default: 1 = $True]
	-CaptureMode     # [SaveToFile|RealtimeRPC|RealtimeLocal]
	-truncBytes      # sets the number of bytes to collect of each captured packet
	-maxSize         # maximum size in MB of the circular ETL file
	-TraceBufferSize # the amount of memory, in kilobytes, for a buffer for event tracing. Maximum = 1024.
	-dbg             # use optional debug options for ETL tracing
Component options:
	-NetBase         # Network Base Event Tracing
	-BITS            # collect BITS events, logs, and data.
	-DHCPcli         # collect DHCP client events, logs, and data.
	-DHCPsrv         # collect DHCP server events, logs, and data.
	-DNScli          # collect DNS client events, logs, and data.
	-DNSsrv          # collect DNS server events, logs, and data.
	-EvtHoursBack         # number of hours back, for Eventlog
	-GPresult        # collect GPresult
	-HyperV          # collect Hyper-V server events, logs, and data.
	-MsInfo32        # collect MSinfo32
	-NetIso          # collect Network Isolation events, logs, and data.
	-NPS             # collect Network Policy Server NPS events, logs, and data.
	-Perfmon         # option to collect Perfmon logging
	-ProcDump Pname.exe # option to collect ProcDumps of process
	-ProcMon         # option to collect ProcMon logging
	-PSR             # enable Problem Steps Recooder (PSR)
	-SMBcli          # collect SMB client events, logs, and data.
	-SMBsrv          # collect SMB File Server events, logs, and data.
	-RAS             # collect RAS events, logs, and data.
	-RDMA            # collect RDMA events, logs, and data.
	-SysFileVer      # collect System File Versions
	-WinHTTP         # collect WinHTTP events, logs, and data.
	-Wireless        # collect Wireless events, logs, and data. On Surface, add -Surface
	-WLAN            # collect WLAN/Wireless events, logs, and data. On Surface, add -Surface
	 -Surface        # use Surface WiFi debug options
	-WPR             # option to collect WPR logs
	-WWAN            # collect WWAN events, logs, and data.

	-NoZip           # use to skip zipping data
	-verbose         # use to see onscreen progress messages
Utils:
	-Ports           # use to get onetime overview of TCP/UDP ports usage by process
	-PortExhaust h   # use to collect longterm view of TCP/UDP port usage, default: 24 h
	-BindWatch portNr # TCP port watcher, stop once rebind of given port happens, default port: 3389
"
}
#endregion ::::: Helper Functions ::::

function Trace-Nic {
# SYNOPSIS: get a NIC if there are multiple, helps with packet dupes with teaming/Hyper-V
    [CmdletBinding()]param([bool]$chooseNics = $true)
        [string[]]$traceNic = $(
                        # prompt for a NIC if multiple active NICs are detected
                        # get a list of active NICs with an IP address
                        #[array]$nicIdx = Get-WmiObject Win32_NetworkAdapterConfiguration | where {$_.IPAddress} | foreach {$_.Index}
                        #[array]$NICs = Get-WmiObject Win32_NetworkAdapter | where {$nicIdx -contains $_.DeviceID} | foreach {$_.NetConnectionID}
						## PoSh... IfType 6 = wired Ethernet, IfType 71 = 802.11
                        [array]$NICs = (Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and ($_.InterfaceType -eq 6 -or $_.InterfaceType -eq 71)}).Name
                        if ($nics.count -eq 1) {
                            $nics[0]
                        } elseif ($nics.count -gt 1) {
						 if ($chooseNics) {
                            $selection = @()
                            do {
                                $title = "Select Network Adapter"
                                $message = "Please select a network adapter you would like to use for tracing:"
                                $count = 0
                                $opts = '$options = [System.Management.Automation.Host.ChoiceDescription[]]('
                                foreach ($nic in $nics) {
                                    Invoke-Expression "`$o$count = New-Object System.Management.Automation.Host.ChoiceDescription `"`&$($count + 1) - $($nic)`n`"`, `"$($nic)`""
                                    $opts += "`$o$count`,"
                                    $count++
                                }
                                $oAll = New-Object System.Management.Automation.Host.ChoiceDescription "&All", "Select all NICs"
                                $opts += '$oAll,'
                                $oQuit = New-Object System.Management.Automation.Host.ChoiceDescription "&Quit", "Quit menu. Will not capture if no NIC selected."
                                $opts += '$oQuit)'
                                Invoke-Expression "`$options = $opts"
                                $result = $host.ui.PromptForChoice($title, $message, $options, 0)
                                switch ($result) {
                                    ($options.count - 1) {
                                        if (!$selection) { # make sure at least 1 NIC was selected
                                            Write-Host -ForegroundColor Yellow "No network adapter was selected. Continue with ETL-logs."
                                            Start-Sleep 3
                                            exit
                                        }
                                        break
                                    }
                                    ($options.count - 2) { # set selection eq to $NICs
                                        #$selection = $NICs
										# set to $null of all selected, which skips the NIC add and uses default of all
										$selection = $null
                                        break
                                    }
                                    default { # add NIC to selection
                                        $selection += $nics[$result]
                                        # remove the selection from NICs
                                        $NICs = $NICs | Where-Object {$_ -ne $NICs[$result]}
                                        break
                                    }
                                }
                            } until ($result -eq ($options.count - 1) -or $result -eq ($options.count - 2) -or !$NICs)
                            #Write-Host -ForegroundColor Yellow "selected: $($nics.name -join ',')"
                            $selection # return selection
						 }
                        } else { # if no NICS are found that meet the 
                            $null
                        }
        )
}


function Add-Providers {
# SYNOPSIS: Adds ETW providers to a NetEventPacketCapture session.
    [CmdletBinding()]param(
		$cap, 				# capture session or session name
		$level, 			# capture level for the provider. Level 0x4 is used when no level is passed.
		[array]$providers)	# Array of the providers to add to the session.
    # set error action so try-catch works
    $ErrorActionPreference = "Stop"
    # ensure $cap is a valid NetEventSession, if a string is passed instead of a NetEventSession
	if ($cap -isnot [CimInstance] -and $cap.CimCLass -ne 'root/StandardCimv2:MSFT_NetEventSession') {
        try {
            $cap =  Get-NetEventSession -Name $cap
        } catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
            Write-Log "NetEventSession $cap could not be found." -tee -foreColor Red
            return $false
        }
    }
    # make sure provider list only contains unique GUIDs
    #$providers = $providers | Sort-Object -Unique    <<<< this is messing with hashtables. Need to rethink this for a mix of hashtable and string values
    $tmpStrPrvdr = $providers | Where-Object {$_ -is [string]} | Sort-Object -Unique
    $tmpHshPrvdr = $providers | Where-Object {$_ -is [hashtable]} # | Sort-Object -Property Provider -Unique  <<<< the unique op breaks hashtable sorting
    $providers = $tmpStrPrvdr
    $providers +=  $tmpHshPrvdr
    ## add the ETW providers
    foreach ($provider in $providers) {
        # test whether the provider is a string...
        if ($provider -is [string])
        {
            $providerName = $provider
            $keyWords = "0xFFFFFFFFFFFFFFFF"
        # ...or a hashtable...
        } elseif ($provider -is [hashtable])
        {
            # @{provider='{}'; level=""; keywords=""}
            $providerName = $provider.provider
            ## set and test custom level
            $level = $provider.level
            try
            {
                [void]( [byte]$level )
            } catch
            {
                Write-Log "Invlaid level, setting to default: `n`rprovider=$providerName `n`rlevel=$level `n`rerror=$($Error[0].ToString())`n`r" -tee -foreColor Red
                $level = $script:defEtwLvl
            }
            # make sure the level is not out of bounds
            if ([byte]$level -gt [byte]$script:maxEtwLvl)
            {
                Write-Log "Level $level is out of bounds for this OS. Setting $providerName to max etw lvl of $script:maxEtwLvl`." -tee -foreColor Red
                [byte]$level = [byte]$script:maxEtwLvl
            }
            # set and test custom keywords
            $keyWords = $provider.keywords
            try
            {
                [void]( [uint64]$keyWords )
            } catch
            {
                Write-Log "Invlaid keywords, setting to default: `n`rprovider=$providerName `n`rkeyWords=$keyWords `n`rerror=$($Error[0].ToString())`n`r" -tee -foreColor Red
                $keyWords = "0xFFFFFFFFFFFFFFFF"
            }
        # ...or unknown.
        } else
        {
            Write-Log "Invalid provider: $($provider)" -tee -foreColor Red
            $providerName = $null
        }
        # add the provider
        if ($providerName)
        {
            Write-Log "Adding provider: $providerName` level=$($level) keywords=$($keyWords)"

            try {
                [void]( Add-NetEventProvider -SessionName $cap.Name -Name $providerName -Level $level -MatchAnyKeyword $keyWords )
            } catch {
                Write-Log "Could not add provider $providerName`. `n`rerror=$($Error[0].ToString())`n`r" -tee -foreColor Red
            }
        }
    }
    return $true
} # end Add-Providers


function Clear-Caches {
# SYNOPSIS:  clear DNS, Netbios and Kerberos-Ticket Caches
	Write-Log " ... deleting DNS, NetBIOS and Kerberos caches" -tee -foreColor Gray
	[array]$CLEAR_CACHES_COMMANDS = [array]("[void] (IPconfig /flushDNS)", ''),	# "[void]Do-Something" executes a lot faster than "Do-Something | Out-Null"
									[array]("[void] (NBTstat -RR)", ''),
									[array]("[void] (KLIST purge -li 0x3e7)", ''),
									[array]("[void] (KLIST purge)", '')
									#[array]("[void] (DFSutil /PKTflush)", '')
	Start-Command $CLEAR_CACHES_COMMANDS $dataPath
} # end Clear-Caches


function Add-Log {
# SYNOPSIS: Creates a log file and then appends further details to it, and tee's output to the console
    [CmdletBinding()]param( [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
            $str)
    if ($str -cmatch 'ERROR:') {
        $color = "red"
    } elseif ($str -cmatch 'WARNING:') {
        $color = "yellow"
    } else {
        $color = "green"
    }
    Write-Host -ForegroundColor $color "$(get-date -format "yyyy-MM-dd HH:mm:ss")`: $str"
} # end Add-Log


function Copy-Log {
# SYNOPSIS: Finds and copies an event log EVTX based on the log name.
    [CmdletBinding()]param([string]$logName, $destination)
    # validate the destination path
    if ($destination -is [System.IO.FileSystemInfo]) {
        [string]$destination = $($destination.FullName)
    } elseif ($destination -isnot [string]) {
        Write-Log "WARNING: Copy-Log destination can only be a System.String or System.IO.FileSystemInfo data type."
        return $false
    }
    # make sure the log name is valid
    $tmpEvt = Get-WinEvent -ListLog $logName -EA SilentlyContinue
    if (!$tmpEvt) {
        Write-Log "WARNING: Log not found: $logName." -tee -foreColor Yellow
        return $false
    } else {
        # get the log path, in PowerShell format, of the log
        $logPath = (Get-WinEvent -ListLog $logName).LogFilePath -replace [regex]::Escape('%SystemRoot%'), "$ENV:SystemRoot"
    }
    # set error action so try-catch works
    $ErrorActionPreference = "Stop"
    # try to copy the log file
    Try {
        Copy-Item $logPath $destination -Force
    } catch {
        Write-Log "WARNING: Log file not found for $logName." -tee -foreColor Yellow
        return $false
    }
    Write-Log "Log file for $logName was successfuly copied."
    return $true
} # end Copy-Log


function Write-Log {
# SYNOPSIS: Writes script information to a log file and to the screen when -Verbose is set.
    [CmdletBinding()]param([string]$text, [Switch]$tee = $false, [string]$foreColor = $null)
    $foreColors = "Black","Blue","Cyan","DarkBlue","DarkCyan","DarkGray","DarkGreen","DarkMagenta","DarkRed","DarkYellow","Gray","Green","Magenta","Red","White","Yellow"
    # check the log file, create if missing
    $isPath = Test-Path "$script:dataPath\$script:logName"
    if (!$isPath) {
		"TSS v$ScriptVer Log started on $ENV:ComputerName - $Script:osVer - $Script:osNameLong " | Out-File "$script:dataPath\$script:logName" -Force
		"Local log file path: $script:dataPath\$script:logName" | Out-File "$script:dataPath\$script:logName" -Append
		"PowerShell version: $Script:PSver " | Out-File "$script:dataPath\$script:logName" -Append
		"Start time (UTC):   $((Get-Date).ToUniversalTime())" | Out-File "$script:dataPath\$script:logName" -Append
		"Start time (Local): $((Get-Date).ToLocalTime()) $(if ((Get-Date).IsDaylightSavingTime()) {([System.TimeZone]::CurrentTimeZone).DaylightName} else {([System.TimeZone]::CurrentTimeZone).StandardName})`n" | Out-File "$script:dataPath\$script:logName" -Append
        Write-Host "$(get-date -format "HH:mm:ss") Local log file path: $("$script:dataPath\$script:logName")"
    }
    # write to log
    "$(Get-TimeStamp): $text" | Out-File "$script:dataPath\$script:logName" -Append
    # write text verbosely
    Write-Verbose $text
    if ($tee)
    {
        # make sure the foreground color is valid
        if ($foreColors -contains $foreColor -and $foreColor)
        {
            Write-Host -ForegroundColor $foreColor $text
        } else {
            Write-Host $text
        }
    }
} # end Write-Log


function Compress-Directory {
# SYNOPSIS:  Compresses all the files in a dir to a cab file
    [CmdletBinding()]param([string]$dir, [string]$cabName, [string]$cabPath)
    $ddf = ".Set CabinetNameTemplate=$cabName
.set CompressionType=LZX
.set DiskDirectory=.
.set DiskDirectory1=.
.set Cabinet=on
.set InfFileName=nul
.set RptFileName=nul
.set maxdisksize=0
"
    $dirfullname = (get-item $dir).fullname
    $ddfpath = ($env:TEMP+"\temp.ddf")
    $ddf += (Get-ChildItem -recurse $dir | Where-Object {!$_.psiscontainer} | Select-Object -expand fullname| ForEach-Object {'"'+$_+'" "'+$_.SubString($dirfullname.length+1)+'"'}) -join "`r`n"

    $ddf | Out-File -encoding UTF8 $ddfpath

    Push-Location "$cabPath"
    makecab /F $ddfpath /L $cabPath
    Remove-Item $ddfpath
    Pop-Location
}


function Copy-File {
# SYNOPSIS: Copies a file to the dataPath
    [CmdletBinding()]param($file, $dataPath)
    # make sure something is passed in
    if ($file -eq '' -or $file -eq $null)
    {
        Write-Log "No files were sent to Copy-File."
        return $false
    }
    # validate the destination path
    if ($dataPath -is [System.IO.FileSystemInfo]) {
        [string]$dataPath = $($dataPath.FullName)
    } elseif ($dataPath -isnot [string]) {
        Write-Log "WARNING: Copy-File destination can only be a System.String or System.IO.FileSystemInfo data type."
        return $false
    }
    # test whether the file exists
    $isFileFnd = Test-Path $file -EA SilentlyContinue
    if (!$isFileFnd -and $file -notmatch "[*]") {
        Write-Log "File not found: $file"
        return $false
    }
    # double check the dataPath, create if does not exist
    $isPathFnd = New-Folder $dataPath
    # finally, copy the file
    if ($isPathFnd)
    {
        try
        {	Write-Log "File copy from $file to $dataPath`."
            ( Copy-Item $file $dataPath -Force -EA Stop )
        }
        catch
        {
            Write-Log "File copy from $file to $dataPath failed: `n $($Error[0].toString())"
            return $false
        }
    }
    return $true
} # end Copy-File


function Copy-Win-Folder {
# SYNOPSIS: Copies a folder to the dataPath
	[CmdletBinding()]param($CopyDirs, $dataPath)
	#Write-Log " ...Copying CBS, WindowsUpdate, DISM, Panther, Driverstore directories" -tee
	#[string[]]$CopyDirs = @("Logs\CBS", "Logs\WindowsUpdate", "Logs\DISM", "\Panther", "\System32\DriverStore")
	foreach ($Dir in $CopyDirs)
		{[string]$DirOut = $Dir.split("\")[1]
		 Write-Log " ....Copying $Dirout directory."
		 Copy-Item C:\Windows\$Dir $dataPath\$DirOut -recurse -ErrorAction Ignore
		 }
} #end Copy-Win-Folder


# SYNOPSIS: Will find all the root and dependency providers for a netsh trace scenario. Works with both public and hidden (wpp/dbg) scenarios.
# List of found scenarios
# MUST BE OUTSIDE OF Convert-WppScenario TO PREVENT A FUNCTION RECURSION LOOP!!!
$script:foundScenario = @()
function Convert-WppScenario {
    [CmdletBinding()]param($scenario)

    # PURPOSE: Searches through HostDLLs for a valid scenario name, defined as a key equal to the scenario name, and a sub-key named Providers or Dependencies
    function Find-ProviderPath {
        [CmdletBinding()]param($scenario)
        # HelperClass path
        $helperPath = "HKLM:\SYSTEM\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses"
        # root path
        $rootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs"
        # reg path to WPP scenarios
        $wppPath = "$helperPath\$scenario"
        # return if the Providers key is found in the HelperClass\$scenario path
        $isWppPathFnd = Test-Path "$wppPath\Providers"
        if ($isWppPathFnd) {
            return "$wppPath\Providers"
        }
        # if the above failed then we search the root path
        $rootProvPath = Get-ChildItem $rootPath -Recurse | Where-Object {(Split-Path -Leaf $_.Name) -eq $scenario -and ((Test-Path "$($_.PSPath)\Providers") -or (Test-Path "$($_.PSPath)\Dependencies"))}
        # return the path, if found
        if ($rootProvPath) {
            return "$($rootProvPath.PSPath)\Providers"
        }
        # when everythng fails return null
        return $null
    } #end Find-ProviderPath

    # PURPOSE: Reads the keys and values under the Providers key and creates Provider objects
    function Convert-Path2Providers {
        [CmdletBinding()]param($regPath)
        # blank array of providers
        $pathProviders = @()
        # get root provider list, adding Providers to the path if needed
        if ($regPath) {
            $regPathLeaf = Split-Path -Leaf $regPath -EA SilentlyContinue
            if ($regPathLeaf -ne "Providers") {
                [array]$wppProviders = Get-ChildItem "$regPath\Providers" -EA SilentlyContinue
            } else {
                [array]$wppProviders = Get-ChildItem $regPath -EA SilentlyContinue
            }
            # format all discovered providers
            if ($wppProviders) {
                foreach ($provider in $wppProviders) {
                    $tmpProvider = New-Object PSObject -Property @{
                        Provider =           $provider.GetValue("Name")
                        "Provider Guid" =    Split-Path $provider.name -leaf
                        "Default Level" =    "0x$('{0:X}' -f $provider.GetValue("Level"))"
                        "Default Keywords" = "0x$('{0:X}' -f $provider.GetValue("Keywords"))"
                    }
                    # add the provider to the providers array
                    $pathProviders += $tmpProvider
                }
            }
            # return the providers list
            return $pathProviders
        }
        return $null
    } #end Convert-Path2Providers
    # empty array to store providers
    $providers = @()
    # check whether the scenario providers have already been added
    if ($script:foundScenario -notcontains $scenario) {
        # add the scenario to the foundScenario list
        $script:foundScenario += $scenario
        # get the reg path to the providers
        $wppPath = Find-ProviderPath $scenario
        # get the providers
        $providers += Convert-Path2Providers $wppPath
    }
    # check for dependencies
    if ($wppPath) {
        $wppParent = Split-Path -Parent $wppPath -EA SilentlyContinue
        if ($wppParent) {
            [array]$depProviders = Get-Item "$wppParent\Dependencies" -EA SilentlyContinue
        }
    }
    # continue if dependencies were found
    if ($depProviders) {
        # get the name(s) of the scenario dependencies
        [array]$depProviders = $depProviders.GetValueNames()
        # loop through the found dependencies
        foreach ($depProvider in $depProviders) {
            # make sure the scenario hasn't already been processed
            if ($script:foundScenario -notcontains $depProvider) {
                # add it if not
                $script:foundScenario += $scenario
                # get the provider path
                $depPath = Find-ProviderPath $depProvider
                # get the providers if the path was found
                if ($depPath) {
                    # recursively call the host function, Convert-WppScenario, in case the dependency has dependencies
                    $providers += Convert-WppScenario $depProvider
                }
            }
        }
    }
    # sort the providers list, filter by unique, then return th results
    return ($providers | Sort-Object -Property "Provider Guid" -Unique)
} #end Convert-WppScenario


function Get-WebFile {
# SYNOPSIS: Downloads a file from the web when given a URL and an output location (path\file.ext)
    [CmdletBinding()]param($dlUrl, $output)
    Add-Log "Attempting to download: $dlUrl"
    try {
        Invoke-WebRequest -Uri $dlUrl -OutFile $output -EA Stop
    } catch {
        Add-Log "ERROR: $($Error[0])"
        return $false
    }
    Add-Log "Downloaded successfully to: $output"
    return $true
} # end Download-WebFile


function Get-UserShares {
# SYNOPSIS: Runs "net use" in CMD run under the user context. Otherwise only the admin shares are shown.
    [CmdletBinding()]param([string]$dataPath,
            [PSCredential]$creds,
            [string]$fileName)
    # initialize the results array
    $results = @()
    # get share list from user context
    Start-Process cmd -ArgumentList "/c net use" -RedirectStandardOutput "$dataPath\$fileName" -WindowStyle Hidden -WorkingDirectory $dataPath -Credential $creds
		# this sleep allows the CMD to write the file and close. Without the sleep the PowerShell script continues too fast and the file does not exist yet.
		Start-Sleep 1
    [array]$tmpLines = Get-Content "$dataPath\$fileName" | Where-Object {$_ -match '\\\\'}
    if ($tmpLines) {
        $tmpLines = $tmpLines
        # parse the text
        $tmpLines | ForEach-Object {
            # trim the name using substr (not going to use regex to clear whitespace since there could be whitespace in the share name)
            $tmpNm = $_.Substring(13,10).Trim(" ")
            # trim out the path using substr
            $tmpPath = $_.Substring(23,26).Trim(" ")
            # add values to results
            $results += New-Object psobject -Property @{
                Local = $tmpNm
                Remote = $tmpPath
            }
        } #end $tmpLines |...
    } else {
        Write-Log "No shares found." -tee -foreColor Yellow
    } #end if
    return $results
} #end Get-UserShares


function Get-TimeStamp {
# SYNOPSIS: Returns a timestamp string
    return "$(Get-Date -format "yyyyMMdd_HHmmss_ffff")"
} # end Get-TimeStamp


function Get-SysFileVer {
# SYNOPSIS: Scan a system and get the file version of all *.sys and *.dll in $env:windir\system32
    [CmdletBinding()]param(
            [string[]]$paths = @("$env:windir\system32\*", "$env:windir\system32\Drivers\*"),
            #[regex]$filter = "^*.[dll|sys|exe]$",
            $filter = @("*.dll","*.sys","*.exe"),
            [string]$dataPath = "."
    )
    # stores results
    $result = @()
    # loop through paths to find system file versions
    foreach ($path in $paths)
    {
        #$result = Get-ChildItem -Path $path -Recurse -Force -ea SilentlyContinue | Where-Object {$_.Name -match $filter -and !$_.PsIsContainer} |
        $tmpResult = Get-ChildItem $path -Include $filter -Force -EA SilentlyContinue |  # -Attributes !D |  <<<< the -Attributes param does not work on 2008 R2
        foreach-object {
            New-Object psobject -Property @{
                    Name = $_.Name;
                    BaseName = $_.BaseName;
                    FullName = $_.FullName;
                    Path = $_.Directory;
                    Extension = $_.Extension;
                    DateModified = $_.LastWriteTime;
                    Version = $_.VersionInfo.FileVersion;
					VersionPriv = $_.VersionInfo.FilePrivatePart;
                    Length = $_.length;
                }
        }
        # update results
        $result += $tmpResult
    }
    # export results
    if ($result)
    {
        $result | Export-Csv "$dataPath\$env:COMPUTERNAME`_$([environment]::OSVersion.Version -join '.')`_SysFileVer.csv" -NoTypeInformation -Force
    }
    # look for the Get-Hotfix cmdlet
    $isHtfxFnd = Get-Command get-hotfix -ea SilentlyContinue
    if ($isHtfxFnd)
    {
        Get-HotFix | Export-Csv "$dataPath\$env:COMPUTERNAME`_$([environment]::OSVersion.Version -join '.')`_hotfixes.csv" -NoTypeInformation -Force
    } else {
        Get-WmiObject Win32_QuickFixEngineering | Export-Csv "$dataPath\$env:COMPUTERNAME`_$([environment]::OSVersion.Version -join '.')`_hotfixes.csv" -NoTypeInformation -Force
    }
} #end Get-SysFileVer


function Get-Eventlogs {
# SYNOPSIS: collect eventlogs
	[CmdletBinding()]param($Evtlogs, $EvtHoursBack)
	#[CmdletBinding()]param([string[]]$Evtlogs, $EvtHoursBack)
	foreach ($Evtlog in $Evtlogs)
	{
	[String]$EvtlogFile = ($Evtlog).Replace("/","-")
	if ($script:EvtHoursBack) {
		#First, obtain the Event logs from last 30 days:
		[String]$EventLogOutputFile = "$datapath\$env:COMPUTERNAME`_Evt_$EvtlogFile`_last$script:EvtHoursBack`hours.evtx"
		$SecondsToFilter = 3600000 * $script:EvtHoursBack # Seconds per hour * hours
		wevtutil.exe epl $Evtlog $EventLogOutputFile /q:"*[System[TimeCreated[timediff(@SystemTime) <=$SecondsToFilter]]]" /ow:true}
	else {wevtutil.exe epl $Evtlog "$datapath\$env:COMPUTERNAME`_Evt_$EvtlogFile`.evtx" /ow:true}
	Write-Log "Write EvtLog: $datapath\$env:COMPUTERNAME`_Evt_$EvtlogFile`.evtx"
	#Write-Verbose "Parameter script:EvtHoursBack $script:EvtHoursBack"
	}
}


function Get-Registry-Info {
# SYNOPSIS: get the content of Registry keys and LastWriteTime
	[CmdletBinding()]param([array]$RegList) #REGISTRY_LIST
	#[CmdletBinding()]param([string]$keyPrefix, [string[]]$Shortkeys)
	if ($RegList) {
		Write-Log " ...Exporting Registry keys and LastWriteTime" -tee -foreColor Gray
		# loop through list
		#Write-Verbose "RegList $RegList"
		foreach ($RegLine in $RegList) {
		#if ($RegLine -is [array]) {
			[string]$keyPrefix 	 = $RegLine[0]	# ex: 'HKLM:\System\CurrentControlSet\'
			#Write-Verbose "keyPrefix $keyPrefix"
			[string[]]$Shortkeys = $RegLine[1]	# ex: 'Enum\PCI', 'Control\PnP\Pci', 'Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}', 'Control\Network\Uninstalled'
			$Shortkeys = @($RegLine[1])
			#Write-Verbose "Shortkeys $Shortkeys"
			[array]$keys = @()

			#$keys = 'HKLM\System\CurrentControlSet\Control\PnP\Pci', 'HKLM\SYSTEM\CurrentControlSet\Enum\PCI', 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}', 'HKLM\System\CurrentControlSet\Control\Network\Uninstalled'
			#$keyPrefix='HKLM:\System\CurrentControlSet\'
			#[array]$keys = @()
			#[string[]]$Shortkeys = @('Enum\PCI', 'Control\PnP\Pci', 'Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}', 'Control\Network\Uninstalled')
			foreach ($Key in $Shortkeys)
			{
			#Write-Verbose "Key: $Key"
			 $CurrentKey = Get-Item ($KeyPrefix+$Key).ToString() -ErrorAction SilentlyContinue
			 #Write-Verbose "CurrentKey: $CurrentKey"
			 If ($CurrentKey) {
				$RegInfos =  $CurrentKey | Add-RegKeyMember  | select Name, LastWriteTime
				Write-Log " ....RegKey-LastWriteTime: $RegInfos"  }
			 if ( Get-ChildItem -path "$($KeyPrefix+$Key)"  ) {[void]($keys +="$(($KeyPrefix).replace(`":`",`"`"))$Key") } else {Write-Log "Note: '$(($KeyPrefix).replace(`":`",`"`"))$Key' not found"}
			}
			$keys | ForEach-Object {
				$tmp = $_.Split('\') -Replace " ",""
				if ($Script:osMajVer -eq 6 -and $Script:osMinVer -le 1)
				{
					$result = REG EXPORT `"$_`" "$dataPath\$env:COMPUTERNAME`_Reg_$($tmp[-2])`_$($tmp[-1]).reg"
					Write-Log " ...Exporting $_`. Result: $result"
				} else {
					Write-Log " ...Exporting $_`. Result: "
					#REG EXPORT $_ "$dataPath\$env:COMPUTERNAME`_Reg_$($tmp[-2])`_$($tmp[-1]).reg" *>> $dataPath\$script:logName
					Invoke-Expression "REG QUERY `"$_`" /s | Out-File `"$dataPath\$env:COMPUTERNAME`_Reg_$($tmp[-2])`_$($tmp[-1]).txt`" -Force *>> $dataPath\$script:logName"
				}
			}
			#} else {Write-host "incorrect Reg.array"}
	}
	}
} #end Get-Registry-Info


function Add-RegKeyMember {
# PURPOSE:  to get a Registry key's last modified time and class name. #requires -version 2.0
<#
.SYNOPSIS
Adds note properties containing the last modified time and class name of a registry key.

.DESCRIPTION
The Add-RegKeyMember function uses the unmanged RegQueryInfoKey Win32 function
to get a key's last modified time and class name. It can take a RegistryKey
object (which Get-Item and Get-ChildItem output) or a path to a registry key.

.EXAMPLE
PS> Get-Item HKLM:\SOFTWARE | Add-RegKeyMember | Select Name, LastWriteTime

Show the name and last write time of HKLM:\SOFTWARE

.EXAMPLE
PS> Add-RegKeyMember HKLM:\SOFTWARE | Select Name, LastWriteTime

Show the name and last write time of HKLM:\SOFTWARE

.EXAMPLE
PS> Get-ChildItem HKLM:\SOFTWARE | Add-RegKeyMember | Select Name, LastWriteTime

Show the name and last write time of HKLM:\SOFTWARE's child keys

.EXAMPLE
PS> Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | Add-RegKeyMember | where classname | select name, classname

Show the name and class name of child keys under Lsa that have a class name defined.

.EXAMPLE
PS> Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Add-RegKeyMember | where lastwritetime -gt (Get-Date).AddDays(-30) |
>> select PSChildName, @{ N="DisplayName"; E={gp $_.PSPath | select -exp DisplayName }}, @{ N="Version"; E={gp $_.PSPath | select -exp DisplayVersion }}, lastwritetime |
>> sort lastwritetime

Show applications that have had their registry key updated in the last 30 days (sorted by the last time the key was updated).
NOTE: On a 64-bit machine, you will get different results depending on whether or not the command was executed from a 32-bit
      or 64-bit PowerShell prompt.

#>
    [CmdletBinding()]param(
        [Parameter(Mandatory=$true, ParameterSetName="ByKey", Position=0, ValueFromPipeline=$true)]
        [ValidateScript({ $_ -is [Microsoft.Win32.RegistryKey] })]
        # Registry key object returned from Get-ChildItem or Get-Item. Instead of requiring the type to
        # be [Microsoft.Win32.RegistryKey], validation has been moved into a [ValidateScript] parameter
        # attribute. In PSv2, PS type data seems to get stripped from the object if the [RegistryKey]
        # type is an attribute of the parameter.
        $RegistryKey,
        [Parameter(Mandatory=$true, ParameterSetName="ByPath", Position=0)]
        # Path to a registry key
        [string] $Path
    )

    begin {
        # Define the namespace (string array creates nested namespace):
        $Namespace = "CustomNamespace", "SubNamespace"

        # Make sure type is loaded (this will only get loaded on first run):
        Add-Type @"
            using System;
            using System.Text;
            using System.Runtime.InteropServices;

            $($Namespace | ForEach-Object {
                "namespace $_ {"
            })

                public class advapi32 {
                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegQueryInfoKey(
                        IntPtr hKey,
                        StringBuilder lpClass,
                        [In, Out] ref UInt32 lpcbClass,
                        UInt32 lpReserved,
                        out UInt32 lpcSubKeys,
                        out UInt32 lpcbMaxSubKeyLen,
                        out UInt32 lpcbMaxClassLen,
                        out UInt32 lpcValues,
                        out UInt32 lpcbMaxValueNameLen,
                        out UInt32 lpcbMaxValueLen,
                        out UInt32 lpcbSecurityDescriptor,
                        out Int64 lpftLastWriteTime
                    );

                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegOpenKeyEx(
                        IntPtr hKey,
                        string lpSubKey,
                        Int32 ulOptions,
                        Int32 samDesired,
                        out IntPtr phkResult
                    );

                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegCloseKey(
                        IntPtr hKey
                    );
                }
            $($Namespace | ForEach-Object { "}" })
"@

        # Get a shortcut to the type:
        $RegTools = ("{0}.advapi32" -f ($Namespace -join ".")) -as [type]
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            "ByKey" {
                # Already have the key, no more work to be done :)
            }

            "ByPath" {
                # We need a RegistryKey object (Get-Item should return that)
                $Item = Get-Item -Path $Path -ErrorAction Stop

                # Make sure this is of type [Microsoft.Win32.RegistryKey]
                if ($Item -isnot [Microsoft.Win32.RegistryKey]) {
                    throw "'$Path' is not a path to a registry key!"
                }
                $RegistryKey = $Item
            }
        }
        # Initialize variables that will be populated:
        $ClassLength = 255 # Buffer size (class name is rarely used, and when it is, I've never seen
                            # it more than 8 characters. Buffer can be increased here, though.
        $ClassName = New-Object System.Text.StringBuilder $ClassLength  # Will hold the class name
        $LastWriteTime = $null
        # Get a handle to our key via RegOpenKeyEx (PSv3 and higher could use the .Handle property off of registry key):
        $KeyHandle = New-Object IntPtr
        if ($RegistryKey.Name -notmatch "^(?<hive>[^\\]+)\\(?<subkey>.+)$") {
            Write-Error ("'{0}' not a valid registry path!")
            return
        }
        $HiveName = $matches.hive -replace "(^HKEY_|_|:$)", ""  # Get hive in a format that [RegistryHive] enum can handle
        $SubKey = $matches.subkey
        # Get hive. $HiveName should contain a valid MS.Win32.RegistryHive enum, but it will be in all caps. It seems that
        # [enum]::IsDefined is case sensitive, so that won't work. There's an awesome static method [enum]::TryParse, but it
        # appears that it was introduced in .NET 4. So, I'm just wrapping it in a try {} block:
        try {
            $Hive = [Microsoft.Win32.RegistryHive] $HiveName
        }
        catch {
            Write-Error ("Unknown hive: {0} (Registry path: {1})" -f $HiveName, $RegistryKey.Name)
            return  # Exit function or we'll get an error in RegOpenKeyEx call
        }
        Write-Verbose ("Attempting to get handle to '{0}' using RegOpenKeyEx" -f $RegistryKey.Name)
        switch ($RegTools::RegOpenKeyEx(
            $Hive.value__,
            $SubKey,
            0,  # Reserved; should always be 0
            [System.Security.AccessControl.RegistryRights]::ReadKey,
            [ref] $KeyHandle
        )) {
            0 { # Success
                # Nothing required for now
                Write-Verbose "  -> Success!"
            }

            default {
                # Unknown error!
                Write-Error ("Error opening handle to key '{0}': {1}" -f $RegistryKey.Name, $_)
            }
        }
        switch ($RegTools::RegQueryInfoKey(
            $KeyHandle,
            $ClassName,
            [ref] $ClassLength,
            $null,  # Reserved
            [ref] $null, # SubKeyCount
            [ref] $null, # MaxSubKeyNameLength
            [ref] $null, # MaxClassLength
            [ref] $null, # ValueCount
            [ref] $null, # MaxValueNameLength
            [ref] $null, # MaxValueValueLength
            [ref] $null, # SecurityDescriptorSize
            [ref] $LastWriteTime
        )) {
            0 { # Success
                $LastWriteTime = [datetime]::FromFileTime($LastWriteTime)

                # Add properties to object and output them to pipeline
                $RegistryKey |
                    Add-Member -MemberType NoteProperty -Name LastWriteTime -Value $LastWriteTime -Force -PassThru |
                    Add-Member -MemberType NoteProperty -Name ClassName -Value $ClassName.ToString() -Force -PassThru
            }
            122  { # ERROR_INSUFFICIENT_BUFFER (0x7a)
                throw "Class name buffer too small"
                # function could be recalled with a larger buffer, but for
                # now, just exit
            }
            default {
                throw "Unknown error encountered (error code $_)"
            }
        }
        # Closing key:
        Write-Verbose ("Closing handle to '{0}' using RegCloseKey" -f $RegistryKey.Name)
        switch ($RegTools::RegCloseKey($KeyHandle)) {
            0 {
                # Success, no action required
                Write-Verbose "  -> Success!"
            }
            default {
                Write-Error ("Error closing handle to key '{0}': {1}" -f $RegistryKey.Name, $_)
            }
        }
    }
} # end Add-RegKeyMember


function Get-NetConnection08R2 {
# SYNOPSIS: collect table of TCP/UDP ports by process, find port depletion on older OS 2008-R2, 2012, similar to NETSTAT -anoQ
	$portsInUse = netstat -ano | where {$_ -match ':'} | foreach {($_ -replace '\s+'," ").Trim(" ")} | ForEach-Object {
        $tmp = $_.Split(" ")
        $lclColon = $tmp[1].LastIndexOf(':')
        $rmtColon = $tmp[2].LastIndexOf(':')
        [int]$tmpPID = $tmp[4]
        $process = Get-Process -PID $tmpPID -EA SilentlyContinue
        if ($process)
        {
            $processName = $process.Name
        } else {
            $processName = "PID not found"
        }
        $tmpObj = New-Object PSObject -Property @{
            Protocol = $tmp[0]
            LocalIP = $tmp[1].SubString(0,$lclColon)
            LocalPort = $tmp[1].SubString($lclColon + 1)
            RemoteIP = $tmp[2].SubString(0,$rmtColon)
            RemotePort = $tmp[2].SubString($rmtColon + 1)
            State = $tmp[3]
            PID = $tmpPID
            Process = $processName
        }
        $tmpObj
    }
	$portsInUse | Format-Table Protocol,LocalIP,LocalPort,RemoteIP,RemotePort,State,PID,Process -AutoSize
} #end Get-NetConnection08R2


function Get-PortUsage {
# SYNOPSIS: port exhaustion detection: Gets the number of ports in use per process
    $isNetTcpFnd = Get-Command Get-NetTCPConnection -EA SilentlyContinue
    if ($isNetTcpFnd)
    {
        $tcpPorts = Get-NetTCPConnection | Group-Object -Property State, OwningProcess | Select-Object -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | Sort-Object Count -Descending
        if($Script:osMajVer -ge 10)
        {
            $udpPorts = Get-NetUDPEndpoint | Group-Object -Property State, OwningProcess | Select-Object -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | Sort-Object Count -Descending
        } else {
            $tmp = ""
            $udp = netstat -p UDP -anoq | Where-Object {$_ -match "UDP"} | ForEach-Object {($tmp = $_ -replace "\s+"," ").Trim(" ")}
            $udpPorts = @()
            $udp | ForEach-Object {
                $tmp = $_.Split(" ")
                $tmpObj = New-Object psobject -Property @{
                    protocol = $tmp[0]
                    lclAddr = $tmp[1]
                    rmtAddr = $tmp[2]
                    OwningProcess = $tmp[3]
                }
                $udpPorts += $tmpObj
            }
            $udpPorts = $udpPorts | Group-Object -Property OwningProcess | Select-Object -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | Sort-Object Count -Descending
        }
        return ($tcpPorts,$udpPorts)
    } else {
        # look for handle.exe in the script path
        $isHandleFnd = Get-Item "$Script:ScriptPath\handle.exe" -EA SilentlyContinue
        if (!$isHandleFnd)
        {
            # try to download handle.exe from Sysinternals Live
            [uri]$url = 'https://live.sysinternals.com/handle.exe'
            $path = "$Script:ScriptPath\handle.exe"

            $clnt = new-object System.Net.WebClient
            $clnt.DownloadFile($url,$path)
        }
        $isHandleFnd = Get-Item "$Script:ScriptPath\handle.exe" -EA SilentlyContinue
        if (!$isHandleFnd)
        {
            #Write-Error "Failed to find or download handle.exe. Please place a copy of handle.exe from https://live.sysinternals.com into the script path: $Script:ScriptPath"
            Write-Log   "Failed to find or download handle.exe. Please place a copy of handle.exe from https://live.sysinternals.com into the script path: $Script:ScriptPath" -tee -foreColor Red
            exit
        }
        Push-Location $Script:ScriptPath
        [array]$afdDevices = .\handle.exe -a afd -nobanner -accepteula
        $udpPorts = @()
        $tcpPorts = @()
        $afdDevices = $afdDevices | Where-Object {$_ -ne "" -and $_ -match 'Device\\Afd'} | ForEach-Object {
            # parse the line
            $tmpLine = ($_ -Replace "\s+"," ").Split(" ")
            $tmp = New-Object psobject -Property @{
                ProcessName = $tmpLine[0]
                PID = $tmpLine[2]
                handle = $tmpLine[-1]
            }
            if ($_ -match 'Device\\Afd\\endpoint')
            {
                $udpPorts += $tmp
            } else {
                $tcpPorts += $tmp
            }
        }
        Pop-Location
        $udpPorts = $udpPorts | Group-Object -Property PID | Select-Object -Property Count, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | Sort-Object Count -Descending
        $tcpPorts = $tcpPorts | Group-Object -Property PID | Select-Object -Property Count, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | Sort-Object Count -Descending
        return ($tcpPorts,$udpPorts)
    }
} #end Get-PortUsage


function Get-PortUsage-Loop {
# SYNOPSIS: calls Get-PortUsage for port exhaustion detection: Gets the number of ports in use per process
	[CmdletBinding()]param(
		[int]$runTimeHrs = 24,			# default is 1 day
		[int]$testIntervalSec = 600,	# default is 600 seconds = 10 minutes
		[string]$Destination = $script:dataPath,
		[string]$fileName = "$env:COMPUTERNAME`_Get-PortUsage.txt"
	)
	Write-Log " ...Port exhaustion monitoring started, running for $runTimeHrs h, get snapshot every $testIntervalSec seconds"
	if (($Script:osMajVer -eq 6 -and $Script:osMinVer -ge 2) -or $Script:osMajVer -ge -10)
	{
		[string]$dynPorts = Get-NetTCPSetting | Select-Object SettingName,DynamicPortRangeStartPort,DynamicPortRangeNumberOfPorts,@{Name='DynamicPortRangeEndPort';Expression={$_.DynamicPortRangeStartPort + $_.DynamicPortRangeNumberOfPorts - 1}} | Out-String
	} else
	{
		[string]$dynPorts = netsh int ipv4 show dynamicportrange tcp
	}
	Write-Log "DynamicPortRange: $dynPorts"
	$PU_startTime = Get-Date
	"Start Time: $((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss'))" | Out-File -FilePath "$Destination\$filename" -Force
	$taskSVC = tasklist.exe /SVC | Out-String
	"===Tasklist/svc:===`n $taskSVC" | Out-File -FilePath "$Destination\$filename" -Append
	while ((Get-Date) -le $PU_startTime.AddHours($runTimeHrs))
	#while ((Get-Date) -le $PU_startTime.AddMinutes($runTimeHrs)) # for testing
	{
		$CurrentDate = (Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')
		"$CurrentDate`: `r`n" | Out-File -FilePath "$Destination\$filename" -Append
		$results = Get-PortUsage
		$results | Out-File -FilePath "$Destination\$filename" -Append
		[int]$totalTcpPorts = ($results[0] | Measure-Object -Sum count).Sum
		[int]$totalUdpPorts = ($results[1] | Measure-Object -Sum count).Sum
		Write-Log "Ports in use; TCP = $totalTcpPorts  UDP = $totalUdpPorts"
		start-sleep -seconds $testIntervalSec
	}
	$taskSVC = tasklist.exe /SVC | Out-String
	"End Time: $((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')) `r`n ===Tasklist/svc:===`n $taskSVC" | Out-File -FilePath "$Destination\$filename" -Append
	Write-Log " ...Stopped Get-PortUsage-Loop"
} #end Get-PortUsage-Loop


function BindWatch {
# SYNOPSIS: # TCP port watcher
	[CmdletBinding()]param([int]$BW_port = 3389)
	# init list of started logs
	#$Script:Started_Logs = @()
	# name of the log file
	#$script:logName = "$env:COMPUTERNAME`_traceLog_Start-BindWatcher.log"
	# get list of all event logs
	#$Script:ALL_LOGS = Get-WinEvent -ListLog *
	$dataPath = $Script:dataPath
	[string]$isPrtListnr = Get-NetTCPConnection -LocalPort $BW_port -EA SilentlyContinue | Select-Object -Property LocalAddress,LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -PID ($_.OwningProcess)).Name}}, @{Name="Svc";Expression={(tasklist /FI "PID eq $($_.OwningProcess)" /FO CSV /SVC)[-1].Split(",")[-1].Trim('"')}}, CreationTime | Format-List | Out-String
	if ($isPrtListnr)
	{
		Write-Log " ...Starting port details:`r`n $isPrtListnr"
	} else {
		Write-Log " ...There are currently no listeners on port $BW_port`."
	}
	[int]$startingPID = Get-NetTCPConnection -LocalPort $BW_port -EA SilentlyContinue | ForEach-Object {$_.OwningProcess} | Sort-Object -Unique
	[void]( Start-Evt-Log "Microsoft-Windows-Winsock-AFD/Operational" )
	#Get-NetTCPConnection | Group-Object -Property State, OwningProcess | Select-Object -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | Sort-Object Count -Descending
	# look for event ID
	[String[]]$stopLogName = ("Microsoft-Windows-Winsock-AFD/Operational")
	[int[]]$eventID = (1030)
	#[string[]]$provider = ("Winsock Network Event")
	# used to keep queries to the event logs down to a manageable time period
	$BW_time = Get-Date
	# set a stopwatch to update $BW_time every 3 minutes
	$sw = New-Object System.Diagnostics.StopWatch
	$sw.Start()
	$stop = $null
	# search for matches using the appropriate filter
	[hashtable]$eventFilter = @{LogName=$stopLogName; ID=$eventID; StartTime=$BW_time}
	Write-Log " ...Started port $BW_port monitoring." -tee -foreColor Green
	do {
		[array]$stop = Get-WinEvent -FilterHashtable $eventFilter -EA SilentlyContinue
		if ($stop)
		{
			$currPort = Get-NetTCPConnection -LocalPort $BW_port -EA SilentlyContinue
			$found = $false
			$stop | ForEach-Object {if ($_.Message -match "`:$BW_port") {$found = $true}}
			if (!$found)
			{
				$stop = $null
			} else {
				if ($currPort)
				{
					$currPort = $currPort | Select-Object -Property LocalAddress,LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -PID ($_.OwningProcess)).Name}}, @{Name="Svc";Expression={(tasklist /FI "PID eq $($_.OwningProcess)" /FO CSV /SVC)[-1].Split(",")[-1].Trim('"')}}, CreationTime | Format-List | Out-String
				} else {
					$currPort = Get-NetTCPConnection -LocalPort $BW_port -EA SilentlyContinue | Select-Object -Property LocalAddress,LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -PID ($_.OwningProcess)).Name}}, @{Name="Svc";Expression={(tasklist /FI "PID eq $($_.OwningProcess)" /FO CSV /SVC)[-1].Split(",")[-1].Trim('"')}}, CreationTime | Format-List | Out-String
				}
				# try and catch the current port onwer
				Write-Log " ...Exporting tasklist to $dataPath\$env:COMPUTERNAME`_Tasklist.csv"
				tasklist /FO CSV /SVC > "$dataPath\$env:COMPUTERNAME`_Tasklist.csv"
				$stop = $stop | Where-Object {$_.Message -match "`:$BW_port"}
			}
		}
		# restart the stopwatch and update time if stopwatch greater than 3 minutes
		if (!$stop -and $sw.Elapsed.TotalMinutes -gt 3) {
			# subtract a minute from the time or you run the risk of missing the stop event.
			$BW_time = (Get-Date).AddMinutes(-1)
			[hashtable]$eventFilter = @{LogName=$stopLogName; ID=$eventID; StartTime=$BW_time}
			# restart the timer (do not use Restart(), as older versions of .NET do not support it).
			$sw.Stop()
			$sw.Reset()
			$sw.Start()
		}
	} until ($found)
	# wait 1 second to stop the log to try and catch the socket close
	Start-Sleep 1
	Stop-Evt-Log
	Write-Log " ...Rebinding of port $BW_port found." -tee -foreColor Yellow
	Write-Log " ...Stop event(s): $($stop | Select-Object Id,LogName,ProviderName,TimeCreated,Message -ExpandProperty Properties | Format-List * | Out-String)"
	if ($currPort)
	{
		Write-Log " ...Stop port owner: $currPort"
	} else {
		Write-Log " ...Stop port owner not found."
	}
	#Write-Log " ...Task list CSV dump:`r`n$taskList"
	[void]( Copy-Log -logName "Microsoft-Windows-Winsock-AFD/Operational" -destination "$dataPath" )
	#Write-Log " ...Please upload the following files to Microsoft:`r`n$dataPath\tasklist.csv`r`n$dataPath\traceLog_Start-BindWatcher.log`r`n$dataPath\Microsoft-Windows-Winsock-AFD`%4Operational.evtx" -tee -foreColor Green
	Write-Log " ...BindWatch Work complete."
} #end BindWatch


function Disable-Enable-MrvlLogging {
# SYNOPSIS: Dis-/Enable Marvell logging and restart the Marvell adapter
# Disable-MrvlLogging: $EnTrace = 0 $MarMessageAction : 	"being disabled:"	- $MarMessageLog :	"Disabling"
#  Disable-Enable-MrvlLogging -EnTrace 0 -MarMessageAction "being disabled:" -MarMessageLog "Disabling"
# Enable-MrvlLogging:  $EnTrace = 1 $MarMessageAction : 	"not enabled:"		- $MarMessageLog :	"Enabling"
#  Disable-Enable-MrvlLogging -EnTrace 1 -MarMessageAction "not enabled:" -MarMessageLog "Enabling"
	[CmdletBinding()]param( [int]$EnTrace, [String]$MarMessageAction, [String]$MarMessageLog)
    $key = 'HKLM:SYSTEM\CurrentControlSet\Services\mrvlpcie8897\'
    #$EnTrace = 0
	Write-Log "EnTrace = $EnTrace"
    # prompt to add trace value
    Write-Warning "Marvell driver tracing is $MarMessageAction This will temporarily disconnect the wireless connection."
    Write-Log "$MarMessageLog Marvell tracing."
    # get the value of HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrvlpcie8897\EnableTracing
    $mrvlTrc = Get-ItemPropertyValue -Path $key -Name EnableTracing -EA SilentlyContinue
    # see if the propery was found
    if ($mrvlTrc) {
        # test for a value of $EnTrace
        if ($mrvlTrc -ne $EnTrace) {
            # set the reg key value
            try {
                [void]( New-ItemProperty -Path $key -Name EnableTracing -Value $EnTrace -Force -EA Stop )
            } catch {
                Write-Log "Could not enable Marvell tracing.`n`n$($Error[0])"
            }
        }
    } else {
        # set the reg key value
        try {
            [void]( New-ItemProperty -Path $key -Name EnableTracing -Value $EnTrace -Force -EA Stop )
        } catch {
            Write-Log "Could not enable Marvell tracing.`n`n$($Error[0])"
        }
    }
    # update the value
    $mrvlTrc = Get-ItemPropertyValue -Path $key -Name EnableTracing -EA SilentlyContinue
    # restart the adapter if it worked
    if ($mrvlTrc -eq $EnTrace) {
        # hardware ID of the Marvell adapter
        $mrvlID = "PCI\\VEN_11AB"
        # get the adapter with the Marvell adapter PNP ID
        $mrvlWnic = Get-NetAdapter | Where-Object {$_.InterfaceType -eq 71 -and $_.PnPDeviceID -match $mrvlID}
        # restart the adapter
        if ($mrvlWnic) {
            Restart-NetAdapter $mrvlWnic.Name -Confirm:$false
        }
    } else {
        Write-Log "Unable to enable Marvell tracing. Continuing without Marvell tracing."
    }
} # end Disable-Enable-MrvlLogging


function New-Folder {
# SYNOPSIS: Given a path, test whether the path is a) valid, b) exists, and c) create the path if it does not and is valid
    [CmdletBinding()]param($path)
    # check whether the path is a string or a file system object. convert to string path if file system object
    if ($path -is [System.IO.FileSystemInfo])
    {
        $path = $path.FullName.toString()
    }
    elseif ($path -isnot [string])
    {
        Write-Log "WARNING: Copy-Log destination can only be a System.String or System.IO.FileSystemInfo data type."
        return $false
    }
    # make sure the patth is valid
    $isValid = Test-Path $path -IsValid
    if (!$isValid)
    {
        Write-Log "The path is invalid: $path"
        return $false
    }
    # test whether the path already exists
    $isFnd = Test-Path $path
    if (!$isFnd)
    {
        try {
            New-Item -Path $path -ItemType Directory -Force -EA Stop | Write-Log
        }
        catch {
            Write-Log "ERROR: Data path was not found and could not be created: $path `n$($Error[0].toString())"
            return $false
        }
    }
    return $true
} #end New-Folder


function Set-NetLogonDBFlags {
# SYNOPSIS: Turn on/off NetLogonDBFlags, example: Set-NetLogonDBFlags on 0x2080ffff
    [CmdletBinding()]param(
		[ValidateSet("on", "off")]
		$state, 	# on / off
		$flags		# 0x2080ffff or 0x0
		)
    Write-Log " ...Turning $state Netlogon Debug flags" -tee -foreColor Gray
    $NetlogonParamKey = get-itemproperty  -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $Global:NetLogonDBFlags = $NetlogonParamKey.DBFlag
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DBFlag" -Value 0x2080ffff -PropertyType DWORD -Force | Out-Null
}
function Start-Capture {
# SYNOPSIS: Creates and starts the ETW trace session
    [CmdletBinding()]param(
        # New-NetEventSession options
        $name,
        $CaptureMode,
        $traceFile,
        $maxSize,
        $TraceBufferSize,
        $MaxNumberOfBuffers,
        # Add-NetEventPacketCaptureProvider options
        $udpOnly,
        $capLevel,
        $captureType,
        $truncBytes,
        # Add-NetEventNetworkAdapter options
        $traceNic,
        $PromiscuousMode,
        # Add-Provider options
        $scenarios,
        $PROVIDER_LIST,
        # misc options
        $noCapture = $false
    )
    Write-Log "Creating capture session."
    try {
        $cap = New-NetEventSession -Name "$name" -CaptureMode $CaptureMode -LocalFilePath "$traceFile" -MaxFileSize $maxSize -TraceBufferSize $TraceBufferSize -MaxNumberOfBuffers $MaxNumberOfBuffers -EA SilentlyContinue
    }
    catch {
        Write-Log "Could not create the NetEventSession."
        return $null
    }
    # add the packet capture provider
    if (!$noCapture)
    {
        Write-Log "Adding packet capture."
        try {
            # add the packet capture provider
            if ($udpOnly)
            {
                [void]( Add-NetEventPacketCaptureProvider -SessionName $name -Level $capLevel -CaptureType $captureType -TruncationLength $truncBytes -IpProtocols 17 -EA SilentlyContinue )
            } else {
                [void]( Add-NetEventPacketCaptureProvider -SessionName $name -Level $capLevel -CaptureType $captureType -TruncationLength $truncBytes -EA SilentlyContinue )
            }
        }
        catch {
            Write-Log "Packet capture could not be added to the NetEventSession. Trace is continuing in case the ETW data is sufficient to troubleshoot the issue."
        }
        # check whether the trace is running
        if ((Get-NetEventPacketCaptureProvider).Name -eq $name) {
            Write-Log "Packet capture successfully added."
        }
    } else {
        Write-Log "NoCapture set. Add-NetEventPacketCaptureProvider skipped."
    }
    # set the capture interface
    if ($traceNic -and $PromiscuousMode) {
        foreach ($nic in $traceNIC) {
            try {
                [void]( Add-NetEventNetworkAdapter $nic -PromiscuousMode -EA SilentlyContinue )
            }
            catch {
                Write-Log "Failed to add the network adapter with PromiscuousMode to the NetEventSession."
            }
        }
    } elseif ($traceNic) {
        foreach ($nic in $traceNIC) {
            try {
                [void]( Add-NetEventNetworkAdapter $nic -EA SilentlyContinue )
            }
            catch {
                Write-Log "Failed to add the network adapters to the NetEventSession."
            }
        }
    }
    # add the ETW providers
    if ($cap -is [CimInstance] -and $cap.CimCLass -match 'MSFT_NetEventSession') {
        # add providers from scenarios
        if ($scenarios) {
            foreach ($scen in $scenarios) {
                # List of found scenarios
                # MUST BE CALLED BEFORE EACH ITERATION OF Convert-WppScenario TO PREVENT A FUNCTION RECURSION LOOP!!!
                $script:foundScenario = @()
                $PROVIDER_LIST += (Convert-WppScenario $scen).'Provider Guid'
            }
        }
        $result = Add-Providers -cap $cap -level $script:defEtwLvl -providers $PROVIDER_LIST
        if ($result) {
            Write-Log "Stack providers added as shown above."
        } else {
            Write-Log "Critical failure adding stack providers." -tee -foreColor Red
        }
    } else {
        Write-Log "Failure creating the NetEventSession." -tee -foreColor Red
        Start-Sleep 3
        exit
    }
    Write-Log "$(get-date -format "HH:mm:ss") === Starting NetEventSession trace. ===" -tee -foreColor Gray
    Start-NetEventSession $name
    return $cap
} #end Start-Capture


function Stop-Capture {
# SYNOPSIS: Stops the ETW/packet capture
    [CmdletBinding()]param( $cap )
    [string]$name = $cap.name
    Write-Log "$(get-date -format "HH:mm:ss") === Stopping trace. ===" -tee -foreColor Green
    Stop-NetEventSession -Name $name
    # remove the session
    Remove-NetEventSession -Name $name
} #end Stop-Capture


function Start-Command {
# SYNOPSIS: Run a command and save the output to dataPath
    [CmdletBinding()]param([array]$commands, $dataPath)
	# - strings are treated as the command and file name
	# - arrays are treated as ("command", "filename")
	# - arrays with an empty ('' or "") second object assume that the file write is part of the command (see the gpresult command)
	if ($commands)
	{
		# double check the dataPath, create if does not exist
		$isPathFnd = New-Folder $dataPath
		if ($isPathFnd)
		{
			# loop through commands
			foreach ($command in $commands) {
				# run the command and output to the data path
				if ($command -is [array]) {
					if ($command[1] -eq '' -or $command[1] -eq "" -or $command[1] -eq $null) {
						Write-Log "Invoking command: $($command[0])"
						Invoke-Expression "$($command[0])"
					} else {
						if ($command[1] -match ".csv")
						{
							Write-Log "Invoking command: $($command[0]) | Export-CSV `"$dataPath\$($command[1])`" -Force"
							Invoke-Expression "$($command[0]) | Export-CSV `"$dataPath\$($command[1])`" -NoTypeInformation -Force"
						} else {
							Write-Log "Invoking command: $($command[0]) | Out-File `"$dataPath\$($command[1])`.txt`" -Force"
							Invoke-Expression "$($command[0]) | Out-File `"$dataPath\$($command[1])`.txt`" -Force"
						}
					}
				} else {
					Write-Log "Invoking command: $command | Out-File `"$dataPath\$command`.txt`" -Force"
					Invoke-Expression "$command | Out-File `"$dataPath\$command`.txt`" -Force"
				}
			}
		}
	} else { Write-Log "No command to process" }
} # end Start-Command


function Start-Evt-Log {
# SYNOPSIS: Tests whether an event log is stopped, and starts if it is not
    [CmdletBinding()]param([string[]]$logName)
    foreach ($log in $logName) {
        # make sure the log name exists
        if ($Script:ALL_LOGS.LogName -notcontains $log) {
            Write-Log "Log not found: $log"
            return $false
        } else {
            # check if the log is already enabled
            if (($Script:ALL_LOGS | Where-Object LogName -EQ $log).IsEnabled) {
                Write-Log "$log Eventlog is enabled."
            } else {
                # enable the log
                Write-Log "Start logging for $log."
                $tmp = $Script:ALL_LOGS | Where-Object LogName -EQ $log
                $tmp.isEnabled = $true
                $tmp.MaximumSizeInBytes = $(50MB)
                $tmp.SaveChanges()
                # record the log name
                $Script:Started_Logs += $log
            }
        }
    }
    return $true
} # end Start-Evt-Log

function Stop-Evt-Log {
# SYNOPSIS: Tests whether an event log is started, and stops if it is not
    [CmdletBinding()]param([string[]]$logName)
    foreach ($log in $logName) {
        # disable the log
        Write-Log "Stop Event logging for $log."
        $tmp = $Script:ALL_LOGS | Where-Object LogName -EQ $log
        if ($tmp) {
            $tmp.isEnabled = $false
            $tmp.SaveChanges()
        } else {
            Write-Log "WARNING: Could not stop Event logging for $log."
        }
    }
} # end Stop-Evt-Log


function Start-PerfmonLogs {
# SYNOPSIS: Start Perfmon tracing using the logman method.
    [CmdletBinding()]param(
		$tracePath = "$tracePath\$Date_time\"
		)
	Write-Log "Starting PerfmonLog, Interval=1sec."
    Invoke-Expression "logman create counter `"$env:COMPUTERNAME`_Perfmon_base`" -o `"$tracePath\$env:COMPUTERNAME`_Perfmon_base`" -f bincirc -v mmddhhmm -max 500 -c `"\LogicalDisk(*)\*`" `"\Memory\*`" `"\.NET CLR Memory(*)\*`" `"\Cache\*`" `"\Network Interface(*)\*`" `"\Netlogon(*)\*`" `"\Paging File(*)\*`" `"\PhysicalDisk(*)\*`" `"\Processor(*)\*`" `"\Processor Information(*)\*`" `"\Process(*)\*`" `"\Thread(*)\*`" `"\Redirector\*`" `"\Server\*`" `"\System\*`" `"\Server Work Queues(*)\*`" `"\Terminal Services\*`" -si 00:00:01"
    Invoke-Expression "logman start `"$env:COMPUTERNAME`_Perfmon_base`""
} # end Start-PerfmonLogs

function Stop-PerfmonLogs {
# SYNOPSIS: Stop Perfmon tracing using the logman method.
	Write-Log "Stopping PerfmonLog."
    Logman stop `"$env:COMPUTERNAME`_Perfmon_base`"
    Logman delete `"$env:COMPUTERNAME`_Perfmon_base`"
}


function StartPerfLogs {
# SYNOPSIS: collect Windows Performance Monitor (PerfMon) logs, Example: StartPerfLogs $true
	[CmdletBinding()]param([bool]$Long = $false)
    if ($Long)
    {
        [string]$StartArg = ' create counter PerfLog5min  -o ' + "$dataPath\$env:COMPUTERNAME`PerfLog5min.blg"  + " -f bincirc -v mmddhhmm -max 300 -c " + "\LogicalDisk(*)\* " + "\Memory\* \Cache\* " + "\Network Interface(*)\* " + "\NTDS(*)\* " + "\Netlogon(*)\* " + "\Database(lsass)\* " + "\Paging File(*)\* " + "\PhysicalDisk(*)\* " + "\Processor(*)\* " + "\Processor Information(*)\* " + "\Process(*)\* "+ "\Redirector\* "+ "\Server\* " + "\System\* " + "\Server Work Queues(*)\* " + "-si 00:05:00"
        $StartArg1 = 'start "PerfLog5min"'
    }
    else
    {
        [string]$StartArg = ' create counter PerfLog5Sec -o ' + "$dataPath\$env:COMPUTERNAME`PerfLog5sec.blg" + " -f bincirc -v mmddhhmm -max 300 -c " + "\LogicalDisk(*)\* " + "\Memory\* \Cache\* " + "\Network Interface(*)\* " + "\NTDS(*)\* " + "\Netlogon(*)\* " + "\Database(lsass)\* " + "\Paging File(*)\* " + "\PhysicalDisk(*)\* " + "\Processor(*)\* " + "\Processor Information(*)\* " + "\Process(*)\* "+ "\Redirector\* "+ "\Server\* " + "\System\* " + "\Server Work Queues(*)\* " + "-si 00:00:05"
        $StartArg1 = ' start "PerfLog5sec"'
    }
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = $StartArg
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
    $ps1 = new-object System.Diagnostics.Process
    $ps1.StartInfo.Filename = "logman.exe"
    $ps1.StartInfo.Arguments = $StartArg1
    $ps1.StartInfo.RedirectStandardOutput = $false
    $ps1.StartInfo.UseShellExecute = $false
    $ps1.Start()
    $ps1.WaitForExit()
}

function StopPerfLogs {
# SYNOPSIS: stop Windows Performance Monitor (PerfMon) logs
	[CmdletBinding()]param([bool]$Long = $false)
    if ($Long)
    {
        $StartArgs = ' stop "PerfLog5min"'
        $StartArgs1 = ' delete "PerfLog5min"'
    }
    else
    {
        $StartArgs = ' stop "PerfLog5sec"'
        $StartArgs1 = ' delete "PerfLog5sec"'
    }
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = $StartArgs
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
    $ps1 = new-object System.Diagnostics.Process
    $ps1.StartInfo.Filename = "logman.exe"
    $ps1.StartInfo.Arguments = $StartArgs1
    $ps1.StartInfo.RedirectStandardOutput = $false
    $ps1.StartInfo.UseShellExecute = $false
    $ps1.start()
    $ps1.WaitForExit()
}

function Start-Procmon {
# SYNOPSIS: Start Procmon
    # force a queue depth of 1 million // check if procmon was run before
    Set-ItemProperty "HKCU:\Software\Sysinternals\Process Monitor" -Name "HistoryDepth" -Value 1
    Push-Location "$Script:ScriptPath"
    Unblock-File .\Procmon.exe -Confirm:$false
	#load config - if file exists in script folder: /LoadConfig ProcmonConfiguration.pmc -, avoid it if you don't know exactly, what you are looking for! Otherwise just trace all with default settings
    .\Procmon.exe /AcceptEula /BackingFile `"$tracePath\$Date_time\$env:COMPUTERNAME`_procmon.pml`" /NoFilter /Minimized
    Pop-Location
}

function Stop-Procmon {
# SYNOPSIS: Stop Procmon
	Start-Process "$Script:ScriptPath\Procmon.exe" -ArgumentList "/terminate"
}


function Start-PSR {
# SYNOPSIS: Starts Problem Steps Recorder
    [CmdletBinding()]param([string]$outputFile = $(throw "ZipFile must be specified."))
    Write-Log "Starting PSR."
    psr /start /output $outputfile /gui 0 /sc 1 /sketch 1 /maxsc 100
} # end Start-PSR

function Stop-PSR {
# SYNOPSIS: Stops Problem Steps Recorder
    Write-Log "Stopping PSR."
    psr /stop
} # end Stop-PSR


function Start-Tcmd {
# SYNOPSIS: start t.cmd
	[CmdletBinding()]param($mode)
	Push-Location "$Script:ScriptPath"
	Invoke-Expression "$Script:ScriptPath\t.cmd $mode verbose circ:$maxSize"
	Pop-Location
}

function Stop-Tcmd {
# SYNOPSIS: stop t.cmd (Mode=OFF)
	[CmdletBinding()]param($mode)
	Push-Location "$Script:dataPath"
	Invoke-Expression "$Script:ScriptPath\t.cmd $mode"
	Pop-Location
}

function GetProcDumps {
# SYNOPSIS: collect ProcDumps, Example: GetProcDumps "lsass.exe -mp -n 2 -s 5 -AcceptEula $dataPath"
	[CmdletBinding()]param([string]$arg)
	# look for procmon.exe
	if (!(Test-Path "$Script:ScriptPath\procdump.exe")) {
		$isDl = Get-WebFile -dlUrl "$sysUrl/procdump.exe" -output "$Script:ScriptPath\procdump.exe"
		if (!$isDl)
		{
			Write-Log "ERROR! procdump.exe was not found. Please be sure the file is in the same directory as this script, $Script:ScriptPath`. " -tee -foreColor Red
			Start-Sleep 8; exit
		}
	}
    $procdump = Test-Path "$Script:ScriptPath\procdump.exe"
    if ($procdump) {
		Write-Log "$(get-date -format "HH:mm:ss") === collect ProcDumps ===" -tee -foreColor Gray
        $ps = new-object System.Diagnostics.Process
        $ps.StartInfo.Filename = "$Script:ScriptPath\procdump.exe"
        $ps.StartInfo.Arguments = $arg
        $ps.StartInfo.RedirectStandardOutput = $false
        $ps.StartInfo.UseShellExecute = $false
        $ps.start()
        $ps.WaitForExit()
    }
    else
    {
        Write-Host "Procdump.exe not found in script root - Skipping dump collection"
    }   
}

function StartWPR {
# SYNOPSIS: collect Windows Performance Recorder (WPR) data, Example: StartWPR "-Start GeneralProfile -Start CPU -Start Heap -Start VirtualAllocation"
	[CmdletBinding()]param([string]$arg)
	Write-Log "$(get-date -format "HH:mm:ss") === Starting wpr GeneralProfile tracing ===" -tee -foreColor Gray
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "wpr.exe"
    $ps.StartInfo.Arguments = "$arg"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
}

function StopWPR {
# SYNOPSIS: stop Windows Performance Recorder (WPR) logging, Example: StopWPR
	Write-Log "$(get-date -format "HH:mm:ss") === Stopping wpr tracing ===" -tee -foreColor Gray
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "wpr.exe"
    $ps.StartInfo.Arguments = " -Stop $dataPath\$env:COMPUTERNAME`_WPR.ETL"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
}


function Test-RunningNetSession {
# SYNOPSIS: make sure there are no existing netevent sessions running.
	$netSession = Get-NetEventSession
	if ($netSession) {
		if ($netSession.SessionStatus -ne "Running") {	# if the session is stopped simply remove it
			$netSession | Remove-NetEventSession
		} else {										# if it's running prompt to stop
			Write-Log "There is an existing capture session running. The session must be stopped and removed before continuing.`n`nIf a previous execution of this script was abnormally terminated, which can leave a running capture session, then it should be safe to stop; otherwise, please select No unless you are certain it is safe to stop the existing session." -tee -foreColor Yellow
			Write-Log "`nRemove the existing capture session?`n`nPress 'y' to remove the existing session or 'n' to exit the script." -tee -foreColor Yellow
			# wait for n or y to be pressed
			do {$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")} until ($x.Character -ieq 'n' -or $x.Character -ieq 'y')
			switch ($x.Character) {
				"N" {Write-Log "Exit reason: existing netevent sessions." -tee -foreColor Cyan
					exit}
				"Y" {
					 Get-NetEventSession | Stop-NetEventSession
					 Get-NetEventSession | Remove-NetEventSession
					}
				default { Write-Log "Exit reason: existing netevent sessions." -tee -foreColor Cyan
						exit}
			}
		}
	}
}

#endregion ::::: FUNCTIONS :::::


#region ::::: CONSTANTS AND VARIABLES :::::
Write-Verbose "Nr. of Args: $($Args.Count) - Nr boundparam: $($psboundparameters.count) - sum: $($psboundparameters.count + $args.count) "
if ($($psboundparameters.count) -eq 0) {Write-Host "Please invoke script with proper arguments."; Show-help; exit}

## Define data path ##
$script:dataPath = "$tracePath\$Date_time"
$dataPath = $script:dataPath							# location of the data files

# name of the log file
$script:logName = "_traceLog_$Date_time`.log"

# path to the script location
$Script:ScriptPath = Split-Path $MyInvocation.MyCommand.Path -Parent

# OS version
#[void]( $Script:OSinfo = (Get-CimInstance Win32_OperatingSystem) )
$Script:osVer = (Get-WmiObject win32_operatingsystem).Version
$Script:osNameLong = $Script:osName = (Get-WmiObject win32_operatingsystem).Name
$Script:osMajVer = [System.Environment]::OSVersion.Version.Major
$Script:osMinVer = [System.Environment]::OSVersion.Version.Minor
$Script:osBldVer = [System.Environment]::OSVersion.Version.Build
$Script:PSver = $PSVersionTable.PSVersion.Major

# OS version name
if ($Script:osMajVer -le 5) {
    [string]$Script:osName = "Unsupported"
 } elseif ($Script:osMajVer -eq 6 -and $Script:osMinVer -eq 0) {
    [string]$Script:osName = "Unsupported"
 } elseif ($Script:osMajVer -eq 6 -and $Script:osMinVer -eq 1) {
    [string]$Script:osName = "2008R2"
 } elseif ($Script:osMajVer -eq 6 -and $Script:osMinVer -eq 2) {
    [string]$Script:osName = "2012"
 } elseif ($Script:osMajVer -eq 6 -and $Script:osMinVer -eq 3) {
    [string]$Script:osName = "2012R2"
 } elseif ($Script:osMajVer -eq 10) {
    [string]$Script:osName = "10"
 }
 
# list of providers on the system
#Write-Verbose "Collecting a list of all providers on the system."
$script:ALL_PROVIDERS = $(
        switch -Regex ($Script:osName) {   
            "2008R2|2012"	{netsh trace show providers}
            "2012R2|10"		{Get-NetEventProvider -ShowInstalled}
        })

# get list of all event logs
$Script:ALL_LOGS = Get-WinEvent -ListLog *

# Sysinternals URL
$sysUrl = 'https://live.sysinternals.com'

Start-Transcript -Path "$script:dataPath\_tss_$Date_time`_Transcript.Log"

##############################
### START EDITABLE CONTENT ###
##############################

## EVENT LOGS ##
# list of event logs to collect at the end of tracing
[string[]]$EVENT_LOG_LIST_BASE = 'System', 'Application'
[string[]]$EVENT_LOG_LIST += $EVENT_LOG_LIST_BASE

## TRACING PROVIDERS ##
<#
    Rules and recommendations for adding ETW providers.
       - Use the ETW GUID, from InsightWeb or code, not the ETW name.
         Not all ETW names are recognizable by the parser, all GUIDs, however, are. So using the GUID increases the chance that it will be added.
       - Use single quotes (' ') to surround the GUID. PowerShell may not parse squiggly brackets ({}) properly inside of double quotes (" ").
       - Custom levels override the default or parameter based levels.
       - Putting the GUID in a string uses the maximum ETW level (0x5 or 0xff, depending on the version of Windows) and keywords (0xFFFFFFFFFFFFFFFF).
       - Use a hashtable to specify custom levels and keywords. Please use the hashtable template below to create custom provider levels and keywords.

           Template:
           @{provider='{}'; level=""; keywords=""}

           Example:
           @{provider='{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}'; level="0x5"; keywords="0x18DF"}
#>

# create and process the complete provider list
[array]$PROVIDER_LIST =  @()

# list of Default Network stack providers to collect from... do not remove or change these!


if ($NetBase) { Write-Log " ...Enabling Network Stack Base Provider: Winsock-AFD WFP TCPIP NetIO NDIS" -tee
	$ProviderName = "Net_Base"
	[array]$PROVIDERS_NET_STACK =	'{E53C6823-7BB8-44BB-90DC-3F86090D48A6}', # Microsoft-Windows-Winsock-AFD
                                    '{0C478C5B-0351-41B1-8C58-4A6737DA32E3}', # Microsoft-Windows-WFP
                                    '{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}', # Microsoft-Windows-TCPIP
                                    '{EB004A05-9B1A-11D4-9123-0050047759BC}', # NetIO
							   @{provider='{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}'; level="0x5"; keywords="0xFFFFFFFFFFFFFFFF"} # Microsoft-Windows-NDIS ... never use level=0xFF, it may spam the log file
	
		$PROVIDER_LIST += $PROVIDERS_NET_STACK}

# list of scenario based providers to collect from
[array]$ADDITIONAL_PROVIDERS = ''

# additional providers, such as dbg and wpp level events, to collect when -dgb is set
if ($dbg) {
    $ADDITIONAL_PROVIDERS += ''
}

# initialize list of additional netsh trace scenarios to pull providers from
[string[]]$scenarios = @()

## FILE COLLECTION ##
# initialize list of files, full path, to collect after tracing is done
[string[]]$FILE_LIST = @()

## REGISTRY COLLECTION ##
# list of Registry locations to collect after tracing is done
[array]$REGISTRY_LIST = @()

## PRE-TRACING COMMANDS ##
# list of commands to run before tracing is done
[array]$PRE_COMMANDS = @()

## POST-TRACING COMMANDS ##
# list of commands to run after tracing is done

# - strings are treated as the command and file name
# - arrays are treated as ("command", "filename")
# - arrays with an empty ('' or "") second object assume that the file write is part of the command (see the gpresult command)
if (!$mini) {
	[array]$POST_COMMANDS = [array]("systeminfo.exe >$datapath\$env:COMPUTERNAME`_Systeminfo.txt",''),
							[array]("tasklist /SVC /FO CSV > '$dataPath\$env:COMPUTERNAME`_Tasklist.csv'",''),
							[array]("[void]( REG SAVE HKLM\System $datapath\$env:COMPUTERNAME`_System.hiv /Y )", ''),
							[array]("[void]( REG SAVE HKLM\Software $datapath\$env:COMPUTERNAME`_Software.hiv /Y )", ''),
							[array]("[void]( REG SAVE HKCU\Software $datapath\$env:COMPUTERNAME`_Software_User.hiv /Y )", '')
	if ($MsInfo32) { [array]$POST_COMMANDS += [array]("msinfo32 /nfo `"$datapath\$env:COMPUTERNAME`.nfo`" /wait", '')}
	if ($GPresult) { [array]$POST_COMMANDS += [array]("pushd $dataPath; GPresult /H $datapath\$env:COMPUTERNAME`_GPresult.html; popd",'')}
	if (($Script:osMajVer -eq 6 -and $Script:osMinVer -gt 1) -or $Script:osMajVer -gt 6)
		{ # get some basic network infos
		[array]$POST_COMMANDS += [array]('Get-NetAdapter | fl *', '$env:COMPUTERNAME`_Get-NetAdapter'), [array]("Get-NetIPAddress", '$env:COMPUTERNAME`_Get-NetIPAddress'), [array]('Get-DnsClientCache | fl *', '$env:COMPUTERNAME`_Get-DnsClientCache')
	}
}
############################
### END EDITABLE CONTENT ###
############################

## add Eventlogs, Providers, Pre-/Post-Commands, file and Registry lists for predefined scenarios

if ($Auth) { $ProviderName = "Auth"
	[string[]]$EVENT_LOG_LIST_Auth = 'Microsoft-Windows-CAPI2/Operational', 'Microsoft-Windows-Kerberos/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_Auth
	[array]$PROVIDERS_Auth = 		@{provider='{6B510852-3583-4e2d-AFFE-A67F9F223438}'; level="0xFF"; keywords="0x7ffffff"}, # Security: Kerberos Authentication
									@{provider='{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}'; level="0xFF"; keywords="0x7ffffff"}, # Active Directory: Kerberos Client
									@{provider='{1BBA8B19-7F31-43C0-9643-6E911F79A06B}'; level="0xFF"; keywords="0xfffff"}, # Security: KDC
									@{provider='{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90}'; level="0xFF"; keywords="0x5ffDf"}, # Security: NTLM, NegoExts Authentication
									@{provider='{37D2C3CD-C5D4-4587-8531-4696C44244C8}'; level="0xFF"; keywords="0x4000ffff"}, # Security: SChannel
									@{provider='{91CC1150-71AA-47E2-AE18-C96E61736B6F}'; level="0xFF"; keywords="0x4000ffff"}, # Microsoft-Windows-Schannel-Events
									@{provider='{1F678132-5938-4686-9FDC-C8FF68F15C85}'; level="0xFF"; keywords="0x4000ffff"}, # Schannel
									@{provider='{5AF52B0D-E633-4EAD-828A-4B85B8DAAC2B}'; level="0xFF"; keywords="0xFFFF"}, # NegoExtsGlobalDebugTraceControlGuid
									@{provider='{2A6FAF47-5449-4805-89A3-A504F3E221A6}'; level="0xFF"; keywords="0xFFFF"}  # Security: Pku2u Authentication
				$PROVIDER_LIST += $PROVIDERS_Auth
	[array]$PRE_COMMANDS_Auth =  	[array]("netsh wfp capture start file=`"$datapath\$env:COMPUTERNAME`_wfpdiag.cab`"", ''),
									[array]("Set-NetLogonDBFlags on 0x2080ffff", '')
				$PRE_COMMANDS += $PRE_COMMANDS_Auth
	[array]$POST_COMMANDS_Auth = 	[array]("netsh wfp capture stop", ''),
									[array]("Set-NetLogonDBFlags off 0x0", '')
				$POST_COMMANDS += $POST_COMMANDS_Auth
	[string[]]$FILE_LIST_Auth = "$env:windir\System32\lsass.log", "$env:windir\debug\netlogon.log", "$env:windir\debug\netlogon.bak", "$env:windir\debug\netsetup.log"
				$FILE_LIST += $FILE_LIST_Auth
	[array]$REGISTRY_LIST_Auth = 	[array]("HKLM:\SYSTEM\CurrentControlSet\", [array]('Control\Lsa','Services\LanmanServer','Services\LanmanWorkstation','Services\Netlogon','Control\SecurityProviders\Schannel','Control\Cryptography','Control\Session Manager\Memory Management')),
									[array]("HKLM:\Software\Microsoft\", [array]('Windows NT\CurrentVersion','Windows\CurrentVersion\Policies')),
									[array]("HKLM:\Software\Policies\", [array]('Microsoft\Cryptography\Configuration\SSL'))
									# QUERY "HKLM\Software\Microsoft\" /v BuildLabEx
				$REGISTRY_LIST += $REGISTRY_LIST_Auth
}

if ($Trace) { $ProviderName = "Trace"
	[string[]]$EVENT_LOG_LIST_Trace = 'Microsoft-Windows-Dhcp-Client/Admin', 'Microsoft-Windows-Dhcp-Client/Operational', 'Microsoft-Windows-Dhcpv6-Client/Admin', 'Microsoft-Windows-Dhcpv6-Client/Operational', 'Microsoft-Windows-DNS-Client/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_Trace
	[array]$PROVIDERS_Trace = 		'{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}', # Microsoft-Windows-DNS-Client
                                    '{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}', # DNS Trace
                                    '{9CA335ED-C0A6-4B4D-B084-9C9B5143AFF0}', # Microsoft.Windows.Networking.DNS
                                    '{367B7A5F-319C-4E40-A9F8-8856095389C7}', # Dnscmd
                                    '{609151DD-04F5-4DA7-974C-FC6947EAA323}', # DNS API/DNS lib
                                    '{FA01E324-3485-4533-BDBC-68D36832AC23}', # DnsServerPSProvider
                                    '{76325CAB-83BD-449E-AD45-A6D35F26BFAE}', # DNS Client Trace
                                    '{F230B1D5-7DFD-4DA7-A3A3-7E87B4B00EBF}'  # DNS Resolver
				$PROVIDER_LIST += $PROVIDERS_Trace
	[array]$POST_COMMANDS_Trace = [array]('Get-DnsClientGlobalSetting', '$env:COMPUTERNAME`_Get-DnsClientGlobalSetting'),
                        [array]('Get-DnsClientServerAddress', '$env:COMPUTERNAME`_Get-DnsClientServerAddress')
				$POST_COMMANDS += $POST_COMMANDS_Trace
}

if ($BITS) { $ProviderName = "BITS"
	[string[]]$EVENT_LOG_LIST_BITS = 'Microsoft-Windows-Bits-Client/Analytic', 'Microsoft-Windows-Bits-Client/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_BITS
	[array]$PROVIDERS_BITS = 		'{7D44233D-3055-4B9C-BA64-0D47CA40A232}', # Microsoft-Windows-WinHttp
                                    '{50B3E73C-9370-461D-BB9F-26F32D68887D}', # Microsoft-Windows-WebIO
                                    @{provider='{EF1CC15B-46C1-414E-BB95-E76B077BD51E}'; level="0xFF"; keywords="0x18DF"}, # Microsoft-Windows-Bits-Client
                                    @{provider='{4A8AAA94-CFC4-46A7-8E4E-17BC45608F0A}'; level="0xFF"; keywords="0x18DF"}, # CtlGuid (BITS_WPP)
                                    @{provider='{599071ED-D475-497C-9E40-FC7283A1249B}'; level="0xFF"; keywords="0x18DF"}  # CtlGuid (BITS_WPP)
				$PROVIDER_LIST += $PROVIDERS_BITS
	[array]$POST_COMMANDS_BITS = [array]('Get-BitsTransfer -AllUsers | fl *', '$env:COMPUTERNAME`_Get-BitsTransfer'),
                        [array]('Get-BitsTransfer -AllUsers | Select DisplayName,@{Name="List";Expression={$_.Filelist | fl * | Out-String}} | fl *', '$env:COMPUTERNAME`_Get-BitsTransferFileList')
				$POST_COMMANDS += $POST_COMMANDS_BITS
}

if ($Bluetooth) { $ProviderName = "Bluetooth"
	[string[]]$EVENT_LOG_LIST_Bluetooth = 'Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational','Microsoft-Windows-Bluetooth-MTPEnum/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_Bluetooth
	[array]$PROVIDERS_Bluetooth = 	'{D88ACE07-CAC0-11D8-A4C6-000D560BCBA5}', # bthport
                                    '{FF9D953D-86CD-4A4F-B8DF-B7236CB640A8}', # bthusb
                                    '{F0CB5D88-0C28-475A-8AE9-D3331ED861DE}', # bthmini
                                    '{F1CD3858-7EE7-43C4-B86A-DCD1BC873269}', # BthEnumTraceGuid
                                    '{1a973eb5-9862-46f0-a54b-ad8a6221654e}', # BthLEEnumTraceGuid
                                    '{F1B0EC6A-87CB-4EAA-BFBA-82770400A80B}', # RfCommTraceGuid
                                    '{1C5221CB-C1F6-4999-8136-501C2023E4CD}', # CtlGuid
									'{8bbe74b4-d9fc-4052-905e-92d01579e3f1}', # CtlGuid
                                    '{CA95AC21-E6FD-4A1B-81BE-ACF16FCFC0FC}', # BthServTraceGuid
                                    '{EB3B6950-120C-4575-AF39-2F713248E8A3}', # BthPrintTraceGuid
                                    '{8E1871AF-671E-43A2-907A-8ADF4BF687EE}', # BthModemTraceGuid
                                    '{71b7bd28-4894-4eaa-8399-a7944423936c}', # BthCSTITraceGuid
                                    '{a5ac3157-27d5-4418-8510-c8f0dc1fe098}', # 
                                    '{7fc34c90-0657-4fdf-960b-702abb741e24}', # CtlGuid
									'{c872ff32-5a0c-4736-bdf2-334c9b8d429f}', # CtlGuid
                                    '{07699FF6-D2C0-4323-B927-2C53442ED29B}', # HidBthTraceGuid
                                    '{0107cf95-313a-473e-9078-e73cd932f2fe}', # HidBthLETraceControl
                                    '{47c779cd-4efd-49d7-9b10-9f16e5c25d06}', # HidClassTraceGuid
                                    '{8a1f9517-3a8c-4a9e-a018-4f17a200f277}', # Microsoft-Windows-BTH-BTHPORT
                                    '{9EBD1710-E5B9-4213-A8F3-9B015FD615C1}', # HfgServiceTrace
                                    '{DFE2ECB4-536B-44AE-8011-67A8E2C3CA96}', # Btampm
									'{BF94D329-C5F9-4deb-AD29-2C6682D485F0}', # EXBUSAUD
                                    '{B79B9C1F-2626-4d0c-9574-5CFCE4E793E6}', # BthA2DP
                                    '{a8e3e135-780c-4e4a-8410-f4da062e5981}', # BthAvrcptg
                                    '{565D84DC-23F7-400a-B2FA-23580731F09F}', # BthHFAud
                                    '{DDB6DA39-08A7-4579-8D0C-68011146E205}', # Microsoft-Windows-BTH-AudioClassDriver
                                    '{75509D47-E67D-48B4-A346-6FEAB02E51BD}', # 
                                    '{5C836296-6C1A-48F4-90E2-28CC25423518}', # 
									'{842B43E3-F833-40B3-958A-5535B3251EE3}', # 
                                    '{F2A442CB-6CDE-44D0-ACEF-2B01CEB56A30}', # 
									'{5acbeb5b-fd8c-45d4-83f1-c8ce2303763c}', # CtlGuid
                                    '{797E4878-22CF-452A-86FF-3872D880F93B}', # DeviceAccess
                                    '{fd35e984-9dee-4011-9eae-5c135b050261}', # Windows_Devices_Background
                                    '{d2440861-bf3e-4f20-9fdc-e94e88dbe1f6}', # BiCommon
                                    '{e8109b99-3a2c-4961-aa83-d1a7a148ada8}', # BrokerCommon
                                    '{AE4BD3BE-F36F-45b6-8D21-BDD6FB832853}', # Microsoft-Windows-Audio
                                    '{e27950eb-1768-451f-96ac-cc4e14f6d3d0}', # AudioTrace
									'{9502CBC6-AA74-4eff-BA91-D9329BCCE758}', # 
                                    '{A6A00EFD-21F2-4A99-807E-9B3BF1D90285}', # Audio Engine
                                    '{71E0AC1E-CFA2-447C-91C7-4F307030F2FC}', # Microsoft-WindowsPhone-AudioSrvPolicyManager
                                    '{6F34C0F0-D9F6-40D3-A94C-419B50FD8407}', # Microsoft-WindowsPhone-PhoneAudioSes
                                    '{1B42986F-288F-4DD7-B7F9-120297715C1E}', # DeviceEnumeration
                                    '{9c1d5e55-2ff9-41a5-9402-40bd9e6f812b}', # 
                                    '{ac23ebce-f06e-4a75-b07b-7cc1defa2388}', # 
									'{56297848-CA78-4AA1-A2C2-29015EC7E498}', # 
                                    '{6ae9ebb4-66cf-4598-9abd-8d223d187301}', # 
                                    '{FCEB1377-EEAF-4A4F-A26A-1E5E0D4C53A4}', # 
                                    '{FE440530-3881-4354-A8FF-BCEC2C488533}', # 
                                    '{9E470B06-C3EB-496C-9CD2-24ACC293DC9A}', # 
                                    '{E71924CF-117B-427C-9E22-BD72021F06BA}', # 
                                    '{378B1AED-30D9-4C8B-92C6-A093D44F0AAB}', # 
                                    '{C01D7B34-43D0-439D-95AC-975645E4535F}', # 
                                    '{D951CB3F-2CBA-4A1C-9436-6CF2E904DDE8}', # Microsoft.Windows.Bluetooth
                                    '{ad8fe36a-0581-4571-a143-5a3f93e30160}', # Microsoft\Shell\DevicePairing
                                    '{9f30c07c-57ce-5ec3-bb5e-476dd25c2742}'  # 
				$PROVIDER_LIST += $PROVIDERS_Bluetooth
}

if ($CSVspace) { $ProviderName = "CSVspace"
	[array]$PROVIDERS_CSVspace = 	'{595F7F52-C90A-4026-A125-8EB5E083F15E}', # Microsoft-Windows-StorageSpaces-Driver
                                    '{929C083B-4C64-410A-BFD4-8CA1B6FCE362}', # Spaceport
                                    '{E7D0AD21-B086-406D-BE46-A701A86A5F0A}'  # SpTelemetry
				$PROVIDER_LIST += $PROVIDERS_CSVspace
}

if ($DAsrv) { $ProviderName = "DAsrv"
			#	$PROVIDER_LIST += $PROVIDERS_NET_STACK
	[string[]]$EVENT_LOG_LIST_DAsrv = 'Microsoft-Windows-RemoteAccess-RemoteAccessServer/Admin', 'Microsoft-Windows-RemoteAccess-MgmtClient/Operational', 'Microsoft-Windows-RemoteAccess-MgmtClientPerf/Operational', 'Windows Networking Vpn Plugin Platform/Operational',
 'Windows Networking Vpn Plugin Platform/OperationalVerbose', 'Microsoft-Windows-VPN-Client/Operational', 'Microsoft-Windows-CAPI2/Operational', 'Security'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_DAsrv
	[array]$PROVIDERS_DAsrv =  		'{214609E4-72CC-4E0E-95F8-1D503FC4AD7F}', # Microsoft-Windows-RemoteAccess-RemoteAccessServer
                                    '{C22D1B14-C242-49DE-9F17-1D76B8B9C458}', # Microsoft-Pef-WFP-MessageProvider
                                    '{66C07ECD-6667-43FC-93F8-05CF07F446EC}', # Microsoft-Windows-WinNat
									'{66A5C15C-4F8E-4044-BF6E-71D896038977}', # Microsoft-Windows-Iphlpsvc
									'{6600E712-C3B6-44A2-8A48-935C511F28C8}', # Microsoft-Windows-Iphlpsvc-Trace
									'{4EDBE902-9ED3-4CF0-93E8-B8B5FA920299}', # Microsoft-Windows-TunnelDriver
									'{A67075C2-3E39-4109-B6CD-6D750058A732}', # Microsoft-Windows-IPNAT
									'{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}'  # Microsoft-Windows-SharedAccess_NAT
				$PROVIDER_LIST += $PROVIDERS_DAsrv
	[string[]]$FILE_LIST_DAsrv = "$env:windir\tracing\*"
				$FILE_LIST += $FILE_LIST_DAsrv
	[array]$PRE_COMMANDS_DAsrv = 	[array]("netsh ras diag set trace enable", ''),
									[array]("netsh ras diag set trace clear", ''),
									[array]("netsh wfp capture start file=`"$datapath\$env:COMPUTERNAME`_wfpdiag.cab`"", '')	#Note: as we cannot set 'wfp capture' circular as - it may be too huge if running for long time
				$PRE_COMMANDS += $PRE_COMMANDS_DAsrv
	[array]$POST_COMMANDS_DAsrv = 	[array]("netsh ras diag set trace disable", ''),
									[array]("netsh wfp capture stop", ''),
									[array]("netsh ras dump ","$env:COMPUTERNAME`_RAS-dump"),
									[array]("netsh int iphttps show state","$env:COMPUTERNAME`_DA_iphttps-state"),
									[array]("netsh int ipv4 show dynamicportrange tcp","$env:COMPUTERNAME`_DA_dynamicportrange"),
									[array]('Get-DAEntryPointDC', '$env:COMPUTERNAME`_Get-DAEntryPointDC')
				$POST_COMMANDS += $POST_COMMANDS_DAsrv
	[string[]]$scenarios = 'DirectAccess','WFP-IPsec'
	[array]$REGISTRY_LIST_DAsrv = 	[array]("HKLM:\SYSTEM\CurrentControlSet\", "Control\SecurityProviders\Schannel"),
									#[array]("HKU:\S-1-5-18\Software\", "Microsoft\Windows\CurrentVersion\Internet Settings")
									[array]("HKCU:\Software\", "Microsoft\Windows\CurrentVersion\Internet Settings")
						$REGISTRY_LIST += $REGISTRY_LIST_DAsrv
}

if ($DCOM) { $ProviderName = "DCOM"
	[array]$PROVIDERS_DCOM = 		'{9474A749-A98D-4F52-9F45-5B20247E4F01}', # DCOMSCM
                                    '{C44219D0-F344-11DF-A5E2-B307DFD72085}'  # Microsoft-Windows-DirectComposition
				$PROVIDER_LIST += $PROVIDERS_DCOM
	[array]$POST_COMMANDS_DCOM = 	[array]("sc sdshow SCManager", '$env:COMPUTERNAME`_sdshow-SCManager'),
									[array]("sc sdshow msdtc", '$env:COMPUTERNAME`_sdshow-msdtc'),
									[array]("sc sdshow clussvc", '$env:COMPUTERNAME`_sdshow-ClusSvc')
									#[array]("SC sdshow msdtc${replaceWithTheguid} ", 'sdshow-msdtc-GUID') # .... You may also collect msdtc-cluster Security descriptors
				$POST_COMMANDS += $POST_COMMANDS_DCOM
	[array]$REGISTRY_LIST_DCOM = 	[array]("HKLM:\SYSTEM\CurrentControlSet\", [array]('Control\Lsa')),
									[array]("HKLM:\Software\Microsoft\", [array]('COM3','Rpc','OLE')),
									[array]("HKLM:\Software\Policies\", [array]('Microsoft\Windows NT\DCOM'))
				$REGISTRY_LIST += $REGISTRY_LIST_DCOM
}

if ($DFScli) { $ProviderName = "DFScli"
	[array]$REGISTRY_LIST_DFScli = 	[array]("HKLM:\SYSTEM\CurrentControlSet\", [array]('Control\Lsa','Services\LanmanServer','Services\LanmanWorkstation','Services\Netlogon')),
									[array]("HKLM:\Software\Microsoft\", [array]('Windows NT\CurrentVersion','Windows\CurrentVersion\Policies'))
				$REGISTRY_LIST += $REGISTRY_LIST_DFScli
}

				
if ($DFSsrv) { $ProviderName = "DFSsrv"
	[string[]]$EVENT_LOG_LIST_DFSsrv = 'Microsoft-Windows-DFSN-Server/Admin'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_DFSsrv
	[array]$PROVIDERS_DFSsrv = 		'{B6C4E17A-2CAC-4273-A390-6F6B8C8C9F01}', # Microsoft-Windows-DFSN-Server
                                    '{5407BAEA-A563-4E56-819F-7DEAA72807CE}', # Microsoft-Windows-DFSN-ServerFilter
                                    '{8F74445D-84F4-426D-9BE1-25AAC1A2B959}', # Microsoft Dfs V5
                                    '{27246E9D-B4DF-4F20-B969-736FA49FF6FF}', # DfsFilter
                                    '{7DA4FE0E-FD42-4708-9AA5-89B77A224885}'  # Microsoft-Windows-DfsSvc
				$PROVIDER_LIST += $PROVIDERS_DFSsrv
	$DFSroot = Read-Host "Please enter DFS root, i.e. \\contoso.com\myDFSroot"
	Write-Log "** DFS root: User provided answer : $DFSroot"
	[array]$POST_COMMANDS_DFSsrv = 	[array]('dfsdiag /TestDFSConfig /dfsroot:$DFSroot', '$env:COMPUTERNAME`_dfsdiag-TestDFSConfig'),
									[array]('dfsdiag /TestDFSIntegrity /dfsroot:$DFSroot /recurse /full', '$env:COMPUTERNAME`_dfsdiag-TestDFSIntegrity'),
									[array]('dfsdiag /TestDCs /domain:$env:USERDNSDOMAIN', '$env:COMPUTERNAME`_dfsdiag-TestDCs'),
									[array]("$env:windir`\system32\dfsutil.exe root export $DFSroot $dataPath\$env:COMPUTERNAME`_DFSroot-export.txt", ''),
									[array]("$env:windir`\system32\dfsutil.exe /root:$DFSroot /verbose /export:$dataPath\$env:COMPUTERNAME`_DFS-N_fsRoot.txt", ''),
									[array]("$env:windir`\system32\dfsutil.exe /ViewDfsDirs:C: /verbose", '$env:COMPUTERNAME`_dfs-ViewDfsDirs'),
									[array]("$env:windir`\system32\dfsutil.exe /domain:%USERDNSDOMAIN% /view", '$env:COMPUTERNAME`_dfs-domain-view')
				$POST_COMMANDS += $POST_COMMANDS_DFSsrv
}

if ($DHCPcli) { $ProviderName = "DHCPcli"
	[string[]]$EVENT_LOG_LIST_DHCPcli = 'Microsoft-Windows-Dhcp-Client/Admin', 'Microsoft-Windows-Dhcp-Client/Operational', 'Microsoft-Windows-Dhcpv6-Client/Admin', 'Microsoft-Windows-Dhcpv6-Client/Operational', 'Microsoft-Windows-DNS-Client/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_DHCPcli
	[array]$PROVIDERS_DHCPcli = 	'{609151DD-04F5-4DA7-974C-FC6947EAA323}', # DNS API/DNS lib
                                    '{F230B1D5-7DFD-4DA7-A3A3-7E87B4B00EBF}', # DNS Resolver
                                    '{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}', # Microsoft-Windows-DHCPv6-Client
                                    '{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}', # Microsoft-Windows-Dhcp-Client
                                    '{07A29C3D-26A4-41E2-856A-095B3EB8B6EF}', # DHCPv6 WPP
                                    '{5855625E-4BD7-4B85-B3A7-9307BAB0B813}', # DHCPv6 WPP
                                    '{CC3DF8E3-4111-48D0-9B21-7631021F7CA6}', # DHCPv4 WPP
                                    '{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}', # Microsoft-Windows-DNS-Client
                                    '{55404E71-4DB9-4DEB-A5F5-8F86E46DDE56}' # Microsoft-Windows-Winsock-NameResolution
				$PROVIDER_LIST += $PROVIDERS_DHCPcli
}

if ($DHCPsrv) { $ProviderName = "DHCPsrv"
	[string[]]$EVENT_LOG_LIST_DHCPsrv = 'DhcpAdminEvents', 'Microsoft-Windows-Dhcp-Server/FilterNotifications', 'Microsoft-Windows-Dhcp-Server/Operational', 'Microsoft-Windows-DNS-Client/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_DHCPsrv
	[array]$PROVIDERS_DHCPsrv = 	'{6D64F02C-A125-4DAC-9A01-F0555B41CA84}', # Microsoft-Windows-DHCP-Server
                                    '{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}', # Microsoft-Windows-DNS-Client
                                    '{AB636BAA-DFF3-4CB0-ABF0-56E192DAC2B3}', # Microsoft-Windows-IPAM
                                    '{91EFB500-642D-42A5-9822-F15C73064FBF}', # DhcpServerTrace
                                    '{6FCDF39A-EF67-483D-A661-76D715C6B008}', # CtlGuid Forwarder
									'{BA405734-9379-42CD-B447-40C249D354A2}', # CtlGuid DHCPwmi
                                    '{9B1DD39A-2779-40A0-AA7D-C4427208626E}'  # Extensible Storage Engine
				$PROVIDER_LIST += $PROVIDERS_DHCPsrv
	[string[]]$FILE_LIST_DHCPsrv = "$env:windir\System32\dhcp\Dhcp*.log"
				$FILE_LIST += $FILE_LIST_DHCPsrv
	[array]$POST_COMMANDS_DHCPsrv = [array]('Get-DhcpServerSetting', '$env:COMPUTERNAME`_Get-DhcpServerSetting'),
									[array]('Get-DhcpServerDatabase', '$env:COMPUTERNAME`_Get-DhcpServerDatabase'),
									[array]('Get-DhcpServerDnsCredential', '$env:COMPUTERNAME`_Get-DhcpServerDnsCredential'),
									[array]('Get-DhcpServerv4DnsSetting', '$env:COMPUTERNAME`_Get-DhcpServerv4DnsSetting')
				$POST_COMMANDS += $POST_COMMANDS_DHCPsrv
}

if ($DNScli) { $ProviderName = "DNScli"
	[string[]]$EVENT_LOG_LIST_DNScli = 'Microsoft-Windows-DNS-Client/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_DNScli
	[array]$PROVIDERS_DNScli = 		'{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}', # Microsoft-Windows-DNS-Client
                                    '{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}', # DNS Trace
                                    '{9CA335ED-C0A6-4B4D-B084-9C9B5143AFF0}', # Microsoft.Windows.Networking.DNS
                                    '{367B7A5F-319C-4E40-A9F8-8856095389C7}', # Dnscmd
                                    '{609151DD-04F5-4DA7-974C-FC6947EAA323}', # DNS API/DNS lib
                                    '{FA01E324-3485-4533-BDBC-68D36832AC23}', # DnsServerPSProvider
                                    '{76325CAB-83BD-449E-AD45-A6D35F26BFAE}', # DNS Client Trace
                                    '{F230B1D5-7DFD-4DA7-A3A3-7E87B4B00EBF}'  # DNS Resolver
				$PROVIDER_LIST += $PROVIDERS_DNScli
	[array]$POST_COMMANDS_DNScli = [array]('Get-DnsClientGlobalSetting', '$env:COMPUTERNAME`_Get-DnsClientGlobalSetting'),
                        [array]('Get-DnsClientServerAddress', '$env:COMPUTERNAME`_Get-DnsClientServerAddress')
				$POST_COMMANDS += $POST_COMMANDS_DNScli
}

if ($DNSsrv) { $ProviderName = "DNSsrv"
	[string[]]$EVENT_LOG_LIST_DNSsrv = 'Microsoft-Windows-DNSServer/Audit'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_DNSsrv
	[array]$PROVIDERS_DNSsrv = 		'{EB79061A-A566-4698-9119-3ED2807060E7}', # Microsoft-Windows-DNSServer
                                    '{57840C25-FA99-4F0D-928D-D81D1851E3DD}', # DNS Server Trace Provider
                                    '{71A551F5-C893-4849-886B-B5EC8502641E}', # Microsoft-Windows-DNS-Server-Service
                                    '{FA01E324-3485-4533-BDBC-68D36832AC23}', # DnsServerPSProvider
                                    '{406F31B6-E81C-457A-B5C3-62C1BE5778C1}', # DnsServer
									'{9CA335ED-C0A6-4B4D-B084-9C9B5143AFF0}', # Microsoft.Windows.Networking.DNS
                                    '{609151DD-04F5-4DA7-974C-FC6947EAA323}', # DNS API/DNS lib
									'{501DD790-B342-479D-A20D-5E8518D365E4}', # DnsValidator
									'{282895CD-F507-4B3A-9E1D-93B514F8DD86}'  # DnsServerWmiProvider
				$PROVIDER_LIST += $PROVIDERS_DNSsrv
	[string[]]$FILE_LIST_DNSsrv = "$env:windir\system32\dns\dns*.log"
				$FILE_LIST += $FILE_LIST_DNSsrv
	[array]$POST_COMMANDS_DNSsrv = [array]('Get-DnsServer', '$env:COMPUTERNAME`_Get-DnsServer'),
                        [array]('Get-DnsServerDiagnostics', '$env:COMPUTERNAME`_Get-DnsServerDiagnostics'),
                        [array]('Get-DnsServerSetting', '$env:COMPUTERNAME`_Get-DnsServerSetting'),
						[array]('Get-DnsServerStatistics', '$env:COMPUTERNAME`_Get-DnsServerStatistics'),
						[array]('DnsCmd /Info', '$env:COMPUTERNAME`_DnsCmd-info'),
						[array]('DnsCmd /EnumDirectoryPartitions', '$env:COMPUTERNAME`_DnsCmd-EnumDirectoryPartitions'),
						[array]('DnsCmd /EnumZones', '$env:COMPUTERNAME`_DnsCmd-EnumZones'),
						[array]('DnsCmd /Statistics', '$env:COMPUTERNAME`_DnsCmd-Statistics')
				$POST_COMMANDS += $POST_COMMANDS_DNSsrv
}

if ($HyperV -or $RDMA) { $ProviderName = "HyperV"
	[string[]]$EVENT_LOG_LIST_HyperV = 'Microsoft-Windows-Hyper-V-EmulatedNic-Admin', 'Microsoft-Windows-Hyper-V-Hypervisor-Admin', 'Microsoft-Windows-Hyper-V-Hypervisor-Operational',
 'Microsoft-Windows-Hyper-V-SynthNic-Admin', 'Microsoft-Windows-Hyper-V-VMMS-Networking', 'Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-VmSwitch-Operational', 'Microsoft-Windows-MsLbfoProvider/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_HyperV
	[array]$PROVIDERS_HyperV = 		'{B72C6994-9FE0-45AD-83B3-8F5885F20E0E}', # Microsoft-Windows-MsLbfoEventProvider
                                    '{11C5D8AD-756A-42C2-8087-EB1B4A72A846}', # Microsoft-Windows-NdisImPlatformEventProvider
                                    '{387ED463-8B1B-42C9-9EF0-803FDFD5D94E}', # Microsoft-Windows-MsLbfoSysEvtProvider
                                    '{B1809D25-B84D-4E40-8D1B-C9978D8946AB}', # LBFOProviderGUID
									'{62DE9E48-90C6-4755-8813-6A7D655B0802}', # Microsoft-Windows-NdisImPlatformSysEvtProvider
									'{9B5CB64B-6166-4369-98CA-986AE578E216}', # NdisImPlatformWPPGuid
                                    '{A781472C-CFC9-42CB-BCEA-A00B916AD1BE}', # NDISIMPLAT
                                    '{DD7A21E6-A651-46D4-B7C2-66543067B869}', # NDISTraceGuid
									'{6CC2405D-817F-4886-886F-D5D1643210F0}'  # NDISWMI
                                    '{6066F867-7CA1-4418-85FD-36E3F9C0600C}', # Microsoft-Windows-Hyper-V-VMMS
                                    '{7B0EA079-E3BC-424A-B2F0-E3D8478D204B}', # Microsoft-Windows-Hyper-V-VSmb
                                    '{3AD15A04-74F1-4DCA-B226-AFF89085A05A}', # Microsoft-Windows-Wnv
                                    '{1F387CBC-6818-4530-9DB6-5F1058CD7E86}', # vmswitch
                                    '{3FF1D341-0EE4-4617-A924-79B1DAD316F2}', # VMSNETSETUPPLUGIN
                                    '{67DC0D66-3695-47C0-9642-33F76F7BD7AD}', # VmSwitch
                                    '{0A18FF18-5362-4739-9671-78023D747B70}', # Microsoft-Windows-Hyper-V-Network
                                    '{152FBE4B-C7AD-4F68-BADA-A4FCC1464F6C}', # Microsoft-Windows-Hyper-V-NetVsc
                                    '{CA630800-D4D4-4457-8983-DFBBFCAC5542}'  # NFPTraceGuid (VMQ)
				$PROVIDER_LIST += $PROVIDERS_HyperV
	[array]$POST_COMMANDS_HyperV = [array]('Get-VM | Get-VMNetworkAdapter | fl *', '$env:COMPUTERNAME`_Get-VMNetworkAdapter'),
						[array]('Get-VMNetworkAdapter -ManagementOS | fl', '$env:COMPUTERNAME`_Get-VMNetworkAdapterHost'),
						[array]('Get-VMSwitch | fl *', '$env:COMPUTERNAME`_Get-VMswitch'),
						[array]('Get-VM | fl *', '$env:COMPUTERNAME`_Get-VM'),
						[array]('Get-NetLbfoTeam | fl *', '$env:COMPUTERNAME`_Get-NetLbfoTeam'),
						[array]('Get-NetLbfoTeamMember | fl *', '$env:COMPUTERNAME`_Get-NetLbfoTeamMember'),
						[array]('Get-NetLbfoTeamNic | fl *', '$env:COMPUTERNAME`_Get-NetLbfoTeamNic'),
						[array]('Get-NetAdapterVmqQueue | fl *', '$env:COMPUTERNAME`_Get-NetAdapterVmqQueue'),
						[array]('Get-NetAdapterVMQ | fl *', '$env:COMPUTERNAME`_Get-NetAdapterVMQ')
				$POST_COMMANDS += $POST_COMMANDS_HyperV
}

if ($IPsec) { $ProviderName = "IPsec"
	[array]$PROVIDERS_IPsec = 		'{C91EF675-842F-4FCF-A5C9-6EA93F2E4F8B}', # Microsoft-Windows-IPSEC-SRV
                                    '{94335EB3-79EA-44D5-8EA9-306F49B3A040}', # IpsecPolicyAgent
                                    '{94335EB3-79EA-44D5-8EA9-306F4FFFA070}'  # IpsecPAStore
                                    '{94335EB3-79EA-44D5-8EA9-306F49B3A070}'  # IpsecPolStore
                                    '{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}'  # Microsoft-Windows-GroupPolicy
                                    '{BD2F4252-5E1E-49FC-9A30-F3978AD89EE2}'  # Microsoft-Windows-GroupPolicyTriggerProvider
                                    '{2588030D-920F-4AD6-ACC0-8AA2CD761DDC}'  # IPsecGWWPPGuid
                                    '{12D06DF7-58EB-4642-9FB2-6D50D008900C}'  # RRAS IpSecFirewall
                                    '{E4FF10D8-8A88-4FC6-82C8-8C23E9462FE5}'  # NSHIPSEC
                                    '{5EEFEBDB-E90C-423A-8ABF-0241E7C5B87D}'  # Mpssvc
                                    '{94335EB3-79EA-44D5-8EA9-306F49B3A041}'  # MpsIpsecClient
                                    '{3BEEDE59-FC7D-5057-CE28-BABAD0B27181}'  # IPsec hcs
                                    '{2BEEDE59-EC7D-4057-BE28-C9EAD0B27180}'  # NAP IPsec
                                    '{8115579E-2BEA-4C9E-9AB1-821CC2C98AB0}'  #	Microsoft-Windows-NAPIPSecEnf								
                                    '{3AD15A04-74F1-4DCA-B226-AFF89085A05A}'  #	Microsoft-Windows-Wnv
									'{D8FA2E77-A77C-4494-9297-ACE3C12907F6}'  #	FwPolicyIoMgr
									'{49D6AD7B-52C4-4F79-A164-4DCD908391E4}'  #	NisDrvWFP Provider
									'{5AD8DAF3-405C-4FD8-BCC5-5ABE20B3EDD6}'  #	FW
									'{B40AEF77-892A-46F9-9109-438E399BB894}'  #	AFD Trace									
									$PROVIDER_LIST += $PROVIDERS_IPsec
}

if ($LBFO) { $ProviderName = "LBFO"	# included in HyperV and RDMA
	[string[]]$EVENT_LOG_LIST_LBFO = 'Microsoft-Windows-MsLbfoProvider/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_LBFO
	[array]$PROVIDERS_LBFO = '{B72C6994-9FE0-45AD-83B3-8F5885F20E0E}', # Microsoft-Windows-MsLbfoEventProvider
					 '{11C5D8AD-756A-42C2-8087-EB1B4A72A846}', # Microsoft-Windows-NdisImPlatformEventProvider
					 '{387ED463-8B1B-42C9-9EF0-803FDFD5D94E}', # Microsoft-Windows-MsLbfoSysEvtProvider
                     '{B1809D25-B84D-4E40-8D1B-C9978D8946AB}', # LBFOProviderGUID
                     '{62DE9E48-90C6-4755-8813-6A7D655B0802}', # Microsoft-Windows-NdisImPlatformSysEvtProvider
					 '{9B5CB64B-6166-4369-98CA-986AE578E216}', # NdisImPlatformWPPGuid
					 '{A781472C-CFC9-42CB-BCEA-A00B916AD1BE}', # NDISIMPLAT
					 '{6CC2405D-817F-4886-886F-D5D1643210F0}'  # NDISWMI
				$PROVIDER_LIST += $PROVIDERS_LBFO
}

		
if ($NetIso) { $ProviderName = "NetIso"
	[string[]]$EVENT_LOG_LIST_NetIso = 'Network Isolation Operational', 'Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose', 'Microsoft-Windows-NetworkProfile/Operational',
 'Microsoft-Windows-NetworkProvider/Operational', 'Microsoft-Windows-NlaSvc/Operational', 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 'Microsoft-Windows-WinHTTP-NDF/Diagnostic'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_NetIso
	[array]$PROVIDERS_NetIso = 		'{0D78C116-50F4-416C-AC97-589EB943DF49}', # FW_PLUMBER
									'{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}', # Microsoft-Windows-Windows Firewall With Advanced Security
									'{4D9DFB91-4337-465A-A8B5-05A27D930D48}', # LsaSrvTraceLogger
									'{DDDC1D91-51A1-4A8D-95B5-350C4EE3D809}', # Microsoft-Windows-AuthenticationProvider
									'{7D44233D-3055-4B9C-BA64-0D47CA40A232}', # Microsoft-Windows-WinHttp
									'{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}'  # WinHttp
	#if ($dbg) { $PROVIDERS_NetIso += @{provider='{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}'; level="0x5"; keywords="0xFFFFFFFFFFFFFFFF"} # Microsoft-Windows-NDIS ... never use level=0xFF, it may spam the log file
	#			}
				$PROVIDER_LIST += $PROVIDERS_NetIso
	<#
	if ($NetIso) {[array]$POST_COMMANDS_NetIso = [array]('Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation -EA SilentlyContinue', '$env:COMPUTERNAME`_NetworkIsolation')
				$POST_COMMANDS += $POST_COMMANDS_NetIso}
	#>
}

if ($NPS) { $ProviderName = "NPS"
	[string[]]$EVENT_LOG_LIST_NPS = 'Microsoft-Windows-CAPI2/Operational', 'Security'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_NPS
	[array]$PROVIDERS_NPS =  		'{91CC1150-71AA-47E2-AE18-C96E61736B6F}', # Microsoft-Windows-Schannel-Events
									'{37D2C3CD-C5D4-4587-8531-4696C44244C8}', # SchannelWppGuid
									'{1F678132-5938-4686-9FDC-C8FF68F15C85}', # Schannel LSA
									'{F6578502-DF4E-4a67-9661-E3A2F05D1D9B}'  # EapAuthenticator
				$PROVIDER_LIST += $PROVIDERS_NPS
	[array]$PRE_COMMANDS_NPS =  [array]("nltest /dbflag:0x2080ffff", ''),
                        [array]("netsh ras diag set trace enable", ''),
						[array]("netsh ras diag set trace clear", '')
						#[array]("netsh nps set tracing *=verbose", ''),
						$PRE_COMMANDS += $PRE_COMMANDS_NPS
	[array]$POST_COMMANDS_NPS =  [array]("netsh nps show config", ''),
						[array]("netsh ras diag set trace disable", ''),
                        [array]("NLTEST /dbflag:0x0", ''),
						[array]('Copy-Win-Folder \tracing ', '')
						#_#[array]("netsh nps set tracing *=none", '')
				$POST_COMMANDS += $POST_COMMANDS_NPS
	[string[]]$FILE_LIST_NPS = "$env:windir\debug\netlogon.*"
	#[string[]]$FILE_LIST_NPS = "$env:windir\tracing\*"
				$FILE_LIST += $FILE_LIST_NPS
	[string[]]$scenarios = 'Netconnection'
	[array]$REGISTRY_LIST_NPS = [array]("HKLM:\SYSTEM\CurrentControlSet\", "Control\SecurityProviders\Schannel"),
									[array]("HKLM:\SYSTEM\CurrentControlSet\", "Services\TcpIp")
						$REGISTRY_LIST += $REGISTRY_LIST_NPS
}

if ($Ras) { $ProviderName = "Ras"
	[string[]]$EVENT_LOG_LIST_RAS = 'Microsoft-Windows-RemoteAccess-MgmtClient/Operational', 'Microsoft-Windows-RemoteAccess-MgmtClientPerf/Operational', 'Windows Networking Vpn Plugin Platform/Operational',
 'Windows Networking Vpn Plugin Platform/OperationalVerbose', 'Microsoft-Windows-VPN-Client/Operational', 'Microsoft-Windows-CAPI2/Operational', 'Security'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_RAS
	[array]$PROVIDERS_Ras =  		'{79EEBE3E-AAB1-4639-94C8-05A1706A6417}', # Microsoft.Windows.Networking.RAS.Dialer
                                    '{8B2B4CA0-ED33-4508-BAD7-76CAC203C2A5}', # Microsoft.Windows.Networking.RAS.ClientConnectionInfo
                                    '{4D201500-E34A-44E3-99E7-013E3EB5C38E}', # TCGUID_NETCFG_COMMON
                                    '{B9F181E1-E221-43C6-9EE4-7F561315472F}', # VpnProfile
                                    '{2E060A13-A848-4B3F-B437-4E21F8AEE32F}', # Microsoft.Windows.Networking.VPNPlugin.AutoConnect
                                    '{7794A8F9-8482-4396-AA2C-2AB8EF51B6B0}', # Microsoft.Windows.Networking.RAS.Manager
                                    '{542F2110-2C0F-40D7-AA35-3309FE74B8AE}', # Microsoft.Windows.Networking.VPNPlugin.Manager
                                    '{B5325CD6-438E-4EC1-AA46-14F46F2570E4}', # Microsoft-Windows-Ras-AgileVpn
                                    '{106B464D-8043-46B1-8CB8-E92A0CD7A560}', # KernelFilterDriver
                                    '{D710D46C-235D-4798-AC20-9F83E1DCD557}', # Microsoft-Windows-EapMethods-Ttls
                                    '{9CC0413E-5717-4AF5-82EB-6103D8707B45}', # Microsoft-Windows-EapMethods-RasTls
									'{4EDBE902-9ED3-4CF0-93E8-B8B5FA920299}', # Microsoft-Windows-TunnelDriver
									'{D84521F7-2235-4237-A7C0-14E3A9676286}'  # Microsoft-Windows-Ras-NdisWanPacketCapture
				$PROVIDER_LIST += $PROVIDERS_Ras
	#[string[]]$FILE_LIST_Ras = "$env:windir\tracing\*"
	#			$FILE_LIST += $FILE_LIST_Ras
	#[array]$PRE_COMMANDS_RAS = [array]("netsh ras diag set trace enable", ''),
	#					[array]("netsh ras diag set trace clear", '')
	#			$PRE_COMMANDS += $PRE_COMMANDS_RAS
	#[array]$POST_COMMANDS_RAS = [array]("netsh ras dump ","$env:COMPUTERNAME`_RAS-dump"),
    #                    [array]("netsh ras diag set trace disable", '')
	#			$POST_COMMANDS += $POST_COMMANDS_RAS
	[string[]]$scenarios = 'VpnClient_dbg'
	[array]$REGISTRY_LIST_RAS = [array]("HKLM:\SYSTEM\CurrentControlSet\", "Control\SecurityProviders\Schannel"),
									[array]("HKLM:\SYSTEM\CurrentControlSet\", "Services\TcpIp")
						$REGISTRY_LIST += $REGISTRY_LIST_RAS
}

if ($RDMA) { $ProviderName = "RDMA"
	[string[]]$EVENT_LOG_LIST_RDMA = 'Microsoft-Windows-SMBClient/Audit', 'Microsoft-Windows-SmbClient/Connectivity', 'Microsoft-Windows-SMBClient/Operational', 'Microsoft-Windows-SmbClient/Security'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_RDMA
	[array]$PROVIDERS_RDMA = 		'{DB66EA65-B7BB-4CA9-8748-334CB5C32400}', # Microsoft-Windows-SMBDirect
									'{17EFB9CE-8CAB-4F19-8B96-0D021D9C76F1}', # CCFWmiGuid
									'{A7C8D6F2-1088-484B-A516-1AE0C3BF8216}', # SchedWmiGuid
									@{provider='{62BC0382-07D2-4C2E-B2C8-3DE3ED67DF13}'; level="0x7"; keywords="0x000003BF"} # SmbdTraceCtrlGuid
				$PROVIDER_LIST += $PROVIDERS_RDMA
	[array]$POST_COMMANDS_RDMA = [array]('Get-NetAdapterRdma | fl *', '$env:COMPUTERNAME`_Get-NetAdapterRdma'),
								[array]('Get-NetQosPolicy | fl *', '$env:COMPUTERNAME`_Get-NetQosPolicy'),
								[array]("`$fnd = Get-Command Get-NetQosFlowControl -EA SilentlyContinue; if(`$fnd) { Get-NetQosFlowControl | fl * | Out-File '$dataPath\$env:COMPUTERNAME`_Get-NetQosFlowControl.txt' -Force}", ''),
								[array]('Get-NetAdapterQos | fl *', '$env:COMPUTERNAME`_Get-NetAdapterQos'),
								[array]("`$fnd = Get-Command Get-NetQosTrafficClass -EA SilentlyContinue; if(`$fnd) { Get-NetQosTrafficClass | fl * | Out-File '$dataPath\$env:COMPUTERNAME`_Get-NetQosTrafficClass.txt' -Force}", '')
				$POST_COMMANDS += $POST_COMMANDS_HyperV
				$POST_COMMANDS += $POST_COMMANDS_RDMA
}

if ($WinHTTP) { $ProviderName = "WinHTTP"
	#[string[]]$EVENT_LOG_LIST_WinHTTP = ''
	#			$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_WinHTTP
	[array]$PROVIDERS_WinHTTP = 	'{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}', # WinHTTP
                                    '{7D44233D-3055-4B9C-BA64-0D47CA40A232}'   # Microsoft-Windows-WinHttp
				$PROVIDER_LIST += $PROVIDERS_WinHTTP
	[array]$PRE_COMMANDS_WinHTTP =  [array]("netsh wfp show state file=`"$datapath\$env:COMPUTERNAME`_wfpState_before.xml`"", ''),
									[array]("netsh wfp show filters file=`"$datapath\$env:COMPUTERNAME`_wfpFilters_before.xml`"", '')
				$PRE_COMMANDS += $PRE_COMMANDS_WinHTTP
	[array]$POST_COMMANDS_WinHTTP = [array]("netsh winhttp show proxy","$env:COMPUTERNAME`_WinHTTP-Proxy"),
									[array]('Get-Service | fl', '$env:COMPUTERNAME`_Get-Service'),
									[array]("netsh wfp show state file=`"$datapath\$env:COMPUTERNAME`_wfpState_after.xml`"", ''),
									[array]("netsh wfp show filters file=`"$datapath\$env:COMPUTERNAME`_wfpFilters_after.xml`"", '')
				$POST_COMMANDS += $POST_COMMANDS_WinHTTP
	#[string[]]$scenarios = 'InternetClient_dbg'
}
if ($WinSock) { $ProviderName = "WinSock"
	[array]$PROVIDERS_WinSock = 	'{E53C6823-7BB8-44BB-90DC-3F86090D48A6}', # Microsoft-Windows-Winsock-AFD
									'{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}', # Microsoft-Windows-TCPIP
									'{EB004A05-9B1A-11D4-9123-0050047759BC}', # NetIO
									'{D5C25F9A-4D47-493E-9184-40DD397A004D}', # Microsoft-Windows-Winsock-WS2HELP
									'{093DA50C-0BB9-4D7D-B95C-3BB9FCDA5EE8}', # Microsoft-Windows-Winsock-SQM
									'{55404E71-4DB9-4DEB-A5F5-8F86E46DDE56}', # Microsoft-Windows-Winsock-NameResolution
									'{9B307223-4E4D-4BF5-9BE8-995CD8E7420B}', # Microsoft-Windows-NetworkManagerTriggerProvider
									'{196A230F-7C17-4019-B2D9-71862D8F48C9}', # NamingShimGeneral
									'{EBAD5978-C172-4AD7-A2FB-1DBD779684A5}', # NamingStubGeneral
									'{4E887BED-1002-41E4-BA74-5AAF7C0EBC68}', # NamingProvGeneral
									'{B40AEF77-892A-46F9-9109-438E399BB894}', # AFD Trace
									'{C8F7689F-3692-4D66-B0C0-9536D21082C9}', # Microsoft-Windows-Tcpip-SQM-Provider
									'{064F02D0-A6C4-4924-841A-F3BADC2675F6}', # NDIS Trace Provider
                                    @{provider='{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}'; level="0x5"; keywords="0xFFFFFFFFFFFFFFFF"} # Microsoft-Windows-NDIS ... never use level=0xFF, it may spam the log file
				$PROVIDER_LIST += $PROVIDERS_WinSock
}

if ($Wireless -or $WLAN-or $WWAN) { $ProviderName = "Wireless"
	[string[]]$EVENT_LOG_LIST_Wireless = 'Microsoft-Windows-CAPI2/Operational', 'Microsoft-Windows-EapHost/Operational', 'Microsoft-Windows-EapMethods-RasTls/Operational', 'Microsoft-Windows-OneX/Operational', 'Microsoft-Windows-WLAN-AutoConfig/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_Wireless
	[array]$PROVIDERS_Wireless = 	'{0BD3506A-9030-4F76-9B88-3E8FE1F7CFB6}', # Microsoft-Windows-NWiFi
                                    '{314B2B0D-81EE-4474-B6E0-C2AAEC0DDBDE}', # Microsoft-Windows-VWiFi
                                    '{85FE7609-FF4A-48E9-9D50-12918E43E1DA}', # Microsoft-Windows-L2NACP
                                    '{9580D7DD-0379-4658-9870-D5BE7D52D6DE}', # Microsoft-Windows-WLAN-AutoConfig
                                    '{239CFB83-CBB7-4BBC-A02E-9BDB496AA7C2}', # Microsoft-Windows-WlanConn
                                    '{6EB8DB94-FE96-443F-A366-5FE0CEE7FB1C}', # Microsoft-Windows-EapHost
                                    '{AB0D8EF9-866D-4D39-B83F-453F3B8F6325}', # Microsoft-Windows-OneX
                                    '{DAA6A96B-F3E7-4D4D-A0D6-31A350E6A445}', # Microsoft-Windows-WLAN-Driver
                                    '{999AC137-42DC-41D3-BA9D-A325A9E1A986}', # Microsoft-Windows-WLAN-BMRHandler
                                    '{B8794785-F7E3-4C2D-A33D-7B0BA0D30E18}', # Microsoft-Windows-WiFiConnApi
                                    '{D0E84378-4DEC-41DA-82B7-FD86CC14FC3C}', # Microsoft-Windows-WiFiConfigSP
                                    '{CDDC4496-D9E2-4530-8FB5-9E4448AAF60D}', # CtlGuid
                                    '{0616F7DD-722A-4DF1-B87A-414FA870D8B7}', # Microsoft.Windows.ConnectionManager
                                    '{843AEEDD-D6D0-45A2-8F78-3B883E450621}', # OneX Supplicant Library UI
                                    '{7076BF7A-DB99-4A63-8AFE-0BB2AB92997A}', # OneX Supplicant Library
                                    '{20644520-D1C2-4024-B6F6-311F99AA51ED}', # MSMSecCtlGuid
                                    '{253F4CD1-9475-4642-88E0-6790D7A86CDE}', # Layer 2 Authentication Utilities
                                    '{0C5A3172-2248-44FD-B9A6-8389CB1DC56A}', # WLAN AutoConfig Trace
                                    '{7A0DB36B-2DCA-4B50-AB37-B4B15BF8DAD7}', # WiFiNetworkManager
                                    '{5CA18737-22AC-4050-85BC-B8DBB9F7D986}', # WiFiNetworkManagerCtlGuid
                                    '{8A3CF0B5-E0BC-450B-AE4B-61728FFA1D58}', # Wireless Client Trace
                                    '{21ba7b61-05f8-41f1-9048-c09493dcfe38}', # WDI WPP
                                    '{f3486b27-31d7-4465-b333-f851e60f6d4b}', # WDI TLV
                                    '{9CC0413E-5717-4AF5-82EB-6103D8707B45}', # EAP RAS/TLS
                                    '{58980F4B-BD39-4A3E-B344-492ED2254A4E}', # EAP RAS/MS-CHAPV2
									'{67D07935-283A-4791-8F8D-FA9117F3E6F2}', # Microsoft-Windows-Wcmsvc
									'{988CE33B-DDE5-44EB-9816-EE156B443FF1}', # WcmsvcCtlGuid
									'{50B3E73C-9370-461D-BB9F-26F32D68887D}', # Microsoft-Windows-WebIO
									'{4E749B6A-667D-4C72-80EF-373EE3246B08}', # WinInet
									'{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}', # Microsoft-Windows-WinINet
									'{A70FF94F-570B-4979-BA5C-E59C9FEAB61B}', # Microsoft-Windows-WinINet-Capture
									'{5402E5EA-1BDD-4390-82BE-E108F1E634F5}', # Microsoft-Windows-WinINet-Config
									'{609151DD-04F5-4DA7-974C-FC6947EAA323}', # DNS API/DNS lib
									'{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}', # WinHTTP
									'{7D44233D-3055-4B9C-BA64-0D47CA40A232}', # Microsoft-Windows-WinHttp
									'{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}', # Microsoft-Windows-TCPIP
									'{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}', # Microsoft-Windows-NDIS
									'{7DD42A49-5329-4832-8DFD-43D979153A88}'  # Microsoft-Windows-Kernel-Network
				$PROVIDER_LIST += $PROVIDERS_Wireless
	[array]$POST_COMMANDS_Wireless = [array]("pushd $dataPath; netsh wlan show all | Out-File '$dataPath\$env:COMPUTERNAME`_Wireless-netenv.txt' -Force; popd", ''),
                        [array]("pushd $dataPath; ipconfig /all | Out-File '$dataPath\$env:COMPUTERNAME`_Wireless-ipconfig.txt' -Force; popd", '')
				$POST_COMMANDS += $POST_COMMANDS_Wireless
	if ($dbg) { $ProviderName = "Wireless_dbg"
		[array]$PROVIDERS_Wl_dbg = 	'{D905AC1D-65E7-4242-99EA-FE66A8355DF8}', # Native WIFI MSM Trace
                                    '{D905AC1C-65E7-4242-99EA-FE66A8355DF8}', # NwfDrvCtlGuid
									'{6DA4DDCA-0901-4BAE-9AD4-7E6030BAB531}', # WLanDiagCtlGuid
									'{2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65}', # DiagL2SecCtlGuid
									'{1AC55562-D4FF-4BC5-8EF3-A18E07C4668E}', # Wlan AutoConfig
									'{3496B396-5C43-45E7-B38E-D509B79AE721}', # WFDPAL
									'{9CC9BEB7-9D24-47C7-8F9D-CCC9DCAC29EB}', # WFDProvCtlGuid
									'{4EF79621-73BA-4BC1-8AD9-222F6FACDB65}', # CTRLWLANSVCPAL
									'{F4190F32-F96E-479C-A45D-D485CFFE42E6}', # Microsoft.Windows.Networking.Wlan.Msmsec
									'{72B18662-744E-4A68-B816-8D562289A850}', # Microsoft.Windows.Networking.Wlan.Msmsec
									'{F860141E-94E0-418E-A8A6-2321623C3018}', # VlibGuid
									'{2C929297-CD5C-4187-B508-51A2754A95A3}', # VAN WPP
                                    '{36DFF693-C097-438B-B3CA-62E80D15D227}', # WlanGPUI WPP
                                    '{520319A9-B932-4EC7-943C-61E560939101}', # WlanDlg WPP
                                    '{5F31090B-D990-4E91-B16D-46121D0255AA}', # EAPHost WPP
                                    '{637A0F36-DFF5-4B2F-83DD-B106C1C725E2}', # WLAN Diagnostics Trace
                                    '{CBE56FBB-D6CB-4C6D-BCA5-1385426707A3}', # WlanSettings WPP
                                    '{E21E2366-917F-4CCC-BFE4-0FD23CB31209}', # EAPTTLS WPP
                                    '{ED092A80-0125-4403-92AC-4C06632420F8}', # WlanUtil WPP
                                    '{C100BECE-D33A-4A4B-BF23-BBEF4663D017}', # Wcn WPP
                                    '{24B4F621-1022-48ED-8B93-23FA02191D83}', # Microsoft.Windows.Networking.Wlan.Nwifi
                                    '{DD7A21E6-A651-46D4-B7C2-66543067B869}'  # NDISTraceGuid
					$PROVIDER_LIST += $PROVIDERS_Wl_dbg}
			
	if ($Surface) { $ProviderName = "Wireless_Surface"
		[array]$Surface_PROVIDERS = '{0160d072-248f-11e2-be71-082e5f28d97c}', # IHV WPP
                                    '{BFA91C93-9E18-497C-971B-490D06089E97}', # WABI Marvell
                                    '{07C9AAA5-FF6B-44CF-A417-C3BE5A719C0B}', # WABI WCF1
                                    '{63c8df35-893b-402e-91db-eb6b1d07c7bc}', # PCI GUID
                                    '{9486234b-887d-4b66-9f83-e3acd71dec32}'  # Surface Integration Driver
					$PROVIDER_LIST += $Surface_PROVIDERS}
}

if ($WWAN) { $ProviderName = "WWAN"
	[string[]]$EVENT_LOG_LIST_WWAN = 'Microsoft-Windows-WWAN-SVC-Events/Operational'
				$EVENT_LOG_LIST +=  $EVENT_LOG_LIST_WWAN
	[array]$PROVIDERS_WWAN = 		'{3A07E1BA-3A6B-49BF-8056-C105B54DD7FB}', # WwanControlGuid
                                    '{3CB40AAA-1145-4FB8-B27B-7E30F0454316}', # Microsoft-Windows-WWAN-SVC-EVENTS
                                    '{7839BB2A-2EA3-4ECA-A00F-B558BA678BEC}', # Microsoft-Windows-WWAN-MM-EVENTS
                                    '{78168022-ECA5-41E8-9E17-E8C7FD77AAE1}', # Microsoft-Windows-WWAN-UI-EVENTS
                                    '{D086235D-48B9-4E49-ADED-5304BF8F636D}', # WwanProtoControlGuid
                                    '{71C993B8-1E28-4543-9886-FB219B63FDB3}', # Microsoft-Windows-WWAN-CFE
                                    '{F4C9BE26-414F-42D7-B540-8BFF965E6D32}', # Microsoft-Windows-WWAN-MediaManager
                                    '{2DD11DE3-FDDE-4DA9-B57A-AF6585F74233}', # WwanRadioManager
                                    '{0255BB48-E574-488A-8348-AE2C7652AFC5}', # microsoft-windows-wwan-hlk
                                    '{B3EEE223-D0A9-40CD-ADFC-50F1888138AB}', # Microsoft-Windows-WWAN-NDISUIO-EVENTS
                                    '{D58C1268-B309-11D1-969E-0000F875A532}', # CommonWppTrace
                                    '{499F891B-A7CE-48AD-A593-38BD85A73F41}', # WcmConfigSPControlGuid
                                    '{E0D3CE46-1E48-42AA-A5E3-D0F18EC9A48B}', # Microsoft.Windows.CellCore.Provisioning
                                    '{B6A9C8BA-70DE-42E4-88DE-001A041B0768}', # Microsoft.Windows.ConnectionManager.WcmApi
                                    '{EFC154D7-91BC-4AFD-A7EE-ED4C1E3048F1}', # WcmSetup
                                    '{CE010BC1-A33E-4E0C-A766-B6378543FE02}'  # WcmListener
				$PROVIDER_LIST += $PROVIDERS_WWAN
	[string[]]$scenarios = 'wlan_dbg','wwan_dbg'
}


## process the complete provider list, include EDITABLE CONTENT
$PROVIDER_LIST += $ADDITIONAL_PROVIDERS
$Script:PROVIDER_LIST = $PROVIDER_LIST

# combine scenario (param) and scenarios (editable content) into scenarios
if ($scenario) { $scenarios += $scenario }

## Misc ##

# set the script var defEtwLvl to level, if a level was passed, or detect the default ETW level based on OS build
# set the maximum level to 0x5 or 0xff, depending on OS version
switch ($Script:osMajVer) {
    10 { # Windows 10
        [byte]$script:maxEtwLvl = 0xff	# set the ETW max level to 0xff
        # now test to make sure it works. # make sure there are no existing netevent sessions.
        Test-RunningNetSession
        # create test session
        [void]( New-NetEventSession test )
        # add a provider (# Microsoft-Windows-TCPIP) with 0xff level
        $test = Add-NetEventProvider -Name '{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}' -SessionName test -Level $script:maxEtwLvl -EA SilentlyContinue
        if ($Error)
        {
            if ($Error[0].ToString() -match 'method were invalid')
            {
                [byte]$script:maxEtwLvl = 0x5
            }
        }
        [void]( Get-NetEventSession | Remove-NetEventSession )
        break
       }
    # Windows 8.1\2012 R2 set 0x5
    6 {[byte]$script:maxEtwLvl = 0x5; break}
}

if ($level)
{
    [byte]$script:defEtwLvl = $level
} else {
    [byte]$script:defEtwLvl = $script:maxEtwLvl
}

[string]$traceFile = "$tracePath\$Date_time\$ENV:computername`_$Date_time`_$ProviderName.etl"	# full path to the trace file. Must contain the .ETL extension.
#endregion ::::: CONSTANTS :::::


#region ::::: VALIDATION :::::
if ($ProviderName -eq '' -or $ProviderName -eq $null) {Write-Log "`n$(get-date -format "HH:mm:ss") === Validation: missing ProviderName, please specify -Trace or any other Component option ===" -tee -foreColor Red
	exit}

Write-Log "`n$(get-date -format "HH:mm:ss") === Validation: Verifying Windows is version 6.1+  OSversion: $Script:osVer ===" -tee -foreColor Gray
# verify you're running at least Windows version 6.1
if ($Script:osMajVer -lt 6 -or ($Script:osMajVer -eq 6 -and $Script:osMinVer -eq 0)) {
    Write-Log "WARNING: You must be running Windows 7, Server 2008 R2 or greater to use NETSH TRACE. Exiting in 5 seconds." -tee -foreColor Red
    Start-Sleep 5; exit }

# make sure the script is run in the console
if ($host.name -ne "ConsoleHost")
{
    Write-Log "ERROR: The script cannot be run in PowerShell ISE. Please run the script from a PowerShell console. Exiting in 5 seconds." -tee -foreColor Red
    Start-Sleep 5; exit }

# .NET version
$Script:dotNetVer = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} | Select-Object PSChildName, Version
if (!($dotNetVer | Where-Object {$_.Version -ge 3.5})) {
    Write-Log "ERROR! You must have .NET Framework 3.5 or greater installed. Script is terminating." -tee -foreColor Red
    Start-Sleep 8; exit }
	
# make sure we are running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
# change the title according to whether the console is running as the admin or the user
if (!$currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
    Write-Log "ERROR: You must run this script in an elevated PowerShell console (Run as administrator)." -tee -foreColor Red
    Start-Sleep 5; exit }

# make sure Marvell driver tracing is enabled, and prompt to enable, if $surface is set.
if ($surface) {
    # get the value of HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrvlpcie8897\EnableTracing
    $mrvlTrc = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrvlpcie8897" -Name EnableTracing -EA SilentlyContinue
    # see if the property was found
    if ($mrvlTrc) {
        # test for a value of 1
        if ($mrvlTrc -ne 1) {
           $enableMrvlTracing = $true
        } else {
           $enableMrvlTracing = $false
        }
    } else {
        $enableMrvlTracing = $true
    }
}

# make sure the parent paths exists
$isPrntPathFnd = New-Folder "$(Split-Path $traceFile)"

# make sure the datapath is there, create if not
$isDataPathFnd = New-Folder $dataPath

# test for psr.exe (Problem Steps Recorder)
if ($psr) {
	$psrCommand = "$env:WINDIR\System32\psr.exe"
	$isPsrFnd = Test-Path $psrCommand
	if (!$isPsrFnd)
	{
        Write-Log "psr.exe was not found at $psrCommand." -tee -foreColor Red
	}
	set-alias psr $psrCommand
}

if ($SMBcli -or $SMBsrv -or $SMBwatch) {
	# look for t.cmd
	if (!(Test-Path "$Script:ScriptPath\t.cmd")) {
		$isTTxt = Get-Item "$Script:ScriptPath\psTss_t_cmd.txt"
		if ($isTTxt)
		{
			Rename-Item -Path "$Script:ScriptPath\psTss_t_cmd.txt" -NewName "t.cmd" -Force
		} else {
			Write-Log "ERROR! t.cmd was not found. Please be sure the file is in the same directory as this script, $Script:ScriptPath`. " -tee -foreColor Red
			Start-Sleep 8; exit
		}
	}
}

if ($ProcMon) {
	# look for procmon.exe
	if (!(Test-Path "$Script:ScriptPath\procmon.exe")) {
		$isDl = Get-WebFile -dlUrl "$sysUrl/procmon.exe" -output "$Script:ScriptPath\procmon.exe"
		if (!$isDl)
		{
			Write-Log "ERROR! procmon.exe was not found. Please be sure the file is in the same directory as this script, $Script:ScriptPath`. " -tee -foreColor Red
			Start-Sleep 8; exit
		}
	}
	<# look for ProcmonConfiguration.pmc
		if (!(Test-Path "$Script:ScriptPath\ProcmonConfiguration.pmc")) {
		Write-Log "ERROR! ProcmonConfiguration.pmc was not found. Please be sure the file is in the same directory as this script, $Script:ScriptPath`. " -tee -foreColor Red
		Start-Sleep 8; exit
		} 
	#>
}

# make sure there are no existing netevent sessions.
Test-RunningNetSession

#endregion ::::: VALIDATION :::::


#region ::::: MAIN :::::

#region ::::: START TRACING :::::
Write-Log "$(get-date -format "HH:mm:ss") === Initialize $ProviderName tracing ===" -tee -foreColor Gray
if ($Perfmon)	{ Start-PerfmonLogs -tracePath $dataPath}
if ($WPR)		{ StartWPR "-Start GeneralProfile -Start CPU -Start Heap -Start VirtualAllocation" }
if ($Trace)		{ Trace-Nic $chooseNics}

# enable Marvell Wireless tracing #Enable-MrvlLogging
if ($surface -and $enableMrvlTracing) {
	Disable-Enable-MrvlLogging -EnTrace 1 -MarMessageAction "not enabled:" -MarMessageLog "Enabling"
}

## start the combined ETW/packet capture ##
$cap = Start-Capture -name $ProviderName -CaptureMode $CaptureMode -traceFile $traceFile -maxSize $maxSize -TraceBufferSize $TraceBufferSize -MaxNumberOfBuffers $MaxNumberOfBuffers `
                         -udpOnly $udpOnly -capLevel $capLevel -captureType $captureType -truncBytes $truncBytes `
                         -traceNic $traceNic -PromiscuousMode $PromiscuousMode `
                         -scenarios $scenarios -PROVIDER_LIST $PROVIDER_LIST `
                         -noCapture $noCapture
# exit if the capture fails to start, i.e. null returned
if (!$cap) { Write-Log "Exit reason: Cannot start Capture. Missing input parameters" -tee -foreColor Cyan
		exit }

# create a text file with some details about the trace
$isTxtFnd = Test-Path "$dataPath\_trace_time.txt"
if (!$isTxtFnd) {[void]( New-Item "$dataPath\_trace_time.txt" -ItemType File -Force )}
# add some details
"Start time (UTC):   $((Get-Date).ToUniversalTime())" | Out-File "$dataPath\_trace_time.txt" -Force
"Start time (Local): $((Get-Date).ToLocalTime()) $(if ((Get-Date).IsDaylightSavingTime()) {([System.TimeZone]::CurrentTimeZone).DaylightName} else {([System.TimeZone]::CurrentTimeZone).StandardName})`r`r" | Out-File "$dataPath\_trace_time.txt" -Append
"`r`n=====================`r`n  IPconfig at Start`r`n=====================`r`n" | Out-File "$dataPath\_trace_time.txt" -Append
# get starting ipconfig
ipconfig /all | Out-File "$dataPath\_trace_time.txt" -Append
"`r`n`r`n" | Out-File "$dataPath\_trace_time.txt" -Append

# Clear Caches
Clear-Caches
## run PRE commands ##
if ($PRE_COMMANDS) { Start-Command -commands $PRE_COMMANDS -dataPath $dataPath }

# start Event logs
if ($EVENT_LOG_LIST) {
	Write-Log "...Starting/Enabling Eventlogs."
    $strtLog = Start-Evt-Log $EVENT_LOG_LIST
    $Script:ALL_LOGS = Get-WinEvent -ListLog *
}

# start problem steps recorder
if ($psr)		{ Start-PSR -outputFile "$datapath\$env:COMPUTERNAME`_psr.zip" }

if ($ProcMon)	{ Start-Procmon }
if ($SMBCli)	{Start-Tcmd -mode CliOn}
if ($SMBSrv)	{Start-Tcmd -mode SrvOn}

Write-Log "Providerlist: $Script:PROVIDER_LIST" -tee -foreColor Gray
Write-Log "Scenarios: $Script:scenarios" -tee -foreColor Gray
Write-Log "$(get-date -format "HH:mm:ss") === Starting $ProviderName tracing ===" -tee -foreColor Gray
# interactive stop tracing
Write-Log "`n$(get-date -format "HH:mm:ss") === Reproduce the issue then press the 's' key to stop tracing. ===`n" -tee -foreColor Green
do {
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} until ($x.Character -ieq 's')
#endregion ::::: START TRACING :::::

#region ::::: STOP TRACING :::::
# stop the capture
Stop-Capture $cap

# stop PSR
if ($psr) { Stop-PSR }

# disable Marvell Wireless tracing: #Disable-MrvlLogging
if ($surface -and $enableMrvlTracing) {
	Disable-Enable-MrvlLogging -EnTrace 0 -MarMessageAction "being disabled:" -MarMessageLog "Disabling"
}

# ProcDumps at stop
if ($ProcDump) { GetProcDumps "$ProcDump -mp -n 2 -s 5 -AcceptEula $dataPath" }

# stop Perfmon logs
if ($Perfmon) { Stop-PerfmonLogs }

# stop WPR loggging
if ($WPR) { StopWPR }

# stop event logs
if ($Script:Started_Logs) { Stop-Evt-Log $Script:Started_Logs }

if ($ProcMon) { Stop-Procmon }

Write-Log " ...Collecting tracing data in $dataPath" -tee

#Get Registry-Info
if ($REGISTRY_LIST) { Get-Registry-Info -RegList $REGISTRY_LIST }

# add ipconfig information
"End time (UTC):   $((Get-Date).ToUniversalTime())" | Out-File "$dataPath\_trace_time.txt" -Append
"End time (Local): $((Get-Date).ToLocalTime()) $(if ((Get-Date).IsDaylightSavingTime()) {([System.TimeZone]::CurrentTimeZone).DaylightName} else {([System.TimeZone]::CurrentTimeZone).StandardName})`n`n" | Out-File "$dataPath\_trace_time.txt" -Append
"`r`n===================`r`n  IPconfig at Stop`r`n==================="| Out-File "$dataPath\_trace_time.txt" -Append
ipconfig /all | Out-File "$dataPath\_trace_time.txt" -Append

# WiFi on Surface
if ($surface) { # prompt for details
    $issueDetails = Read-Host "Enter a brief description of the issue (Press Enter when done)"
    $issueDetails | Out-File $dataPath\IssueDescription.txt -Force
    Write-Log "Generating WLAN report." -tee  -foreColor Gray
    # run WlanReport
    if ((Test-Path "$Script:ScriptPath\WlanReport.exe")) {
        # go to script root
        Push-Location $Script:ScriptPath
        # run wlanreport
        .\WlanReport.exe
        # copy the results to dataPath
        Copy-Item "$env:ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html" "$dataPath" -Force
        Pop-Location
    }
    # get a sleep study
    Write-Log "Generating sleep study." -tee  -foreColor Gray
    Push-Location $dataPath
    POWERCFG /SLEEPSTUDY /OUTPUT "sleepstudy_%computername%.html"
    Pop-Location
    <# get Marvell FW dumps
		[void]( Copy-Item "$env:SystemRoot\system32\drivers\mrvl*.bin" "$dataPath" -Force )
		# delete the dumps
		[void]( del "$env:SystemRoot\system32\drivers\mrvl*.bin" -Force )
    #>
}

# Get table of ports
if ($Ports) { Write-log " ...Collecting table of TCP/UDP ports by process"  -tee  -foreColor Gray; Get-NetConnection08R2 | Out-File "$dataPath\$env:COMPUTERNAME`_Ports-InUse.txt" -Force}
if ($PortExhaust) { Get-PortUsage-Loop -runTimeHrs  $PortExhaust -testIntervalSec 600 }
if ($BindWatch) { BindWatch -BW_port $BindWatch }

## zip stuff ##
# copy/move stuff to it
#Move-Item $traceFile "$dataPath" -Force

# copy the event logs
<#
	foreach ($log in $EVENT_LOG_LIST) {
		[void]( Copy-Log -logName $log -destination "$dataPath" )
	} 
#>

## run post capture commands ##
$start_info32 = Get-Date
if ($POST_COMMANDS) { Start-Command -commands $POST_COMMANDS -dataPath $dataPath }

# copy files
if ($FILE_LIST) { Write-Log " ...copying files" -tee -foreColor Gray
	$FILE_LIST | ForEach-Object {Copy-File -file $_ -dataPath $dataPath} }

# get file versions and hotfixes
if ($SysFileVer) { Write-Log " ...Collecting SystemFile versions" -tee -foreColor Gray
	Get-SysFileVer -dataPath $dataPath
	}

if ($SMBCli -or $SMBsrv) {Stop-Tcmd -mode OFF}

Write-Log " ...Collecting Eventlogs $script:EvtHoursBack" -tee -foreColor Gray
# get Eventlogs for last xx days
#Get-Eventlogs -Evtlogs System,Application #30
Get-Eventlogs -Evtlogs $EVENT_LOG_LIST

Stop-Transcript
# Data Compression
if (!$noZip) {
	# moved to end: wait for msinfo32 to complete
	if ($MsInfo32) { 
		Write-Log " ...waiting on MsInfo32 to complete" -tee
		do
		{
			$isDone = Get-Process msinfo32 -EA SilentlyContinue
			if ($isDone) {Start-Sleep -Seconds 3}
		} until ($isDone -eq $null -or (Get-Date) -gt $start_info32.AddMinutes(3))
	}

	Write-Log "$(get-date -format "HH:mm:ss") ...Compressing data. Please be patient." -tee
	if ($Script:osMajVer -eq 6 -and $Script:osMinVer -le 1)
	{
		# cab file path and name
		$cabFile = "$dataPath\$rootName`_results.cab"
		# write the final prompt to log before compression to complete the log file
		Write-Log "Please upload the following file(s) to Microsoft for analysis, when compression finished:`n  $cabFile" -tee -foreColor Yellow
		Compress-Directory -dir "$dataPath" -cabName "$(Split-Path $cabFile -Leaf)" -cabPath "$(Split-Path $dataPath -Parent)"
		Write-Host -ForegroundColor Green "$(get-date -format "HH:mm:ss") *** Please upload the following file(s) to Microsoft for analysis:`n  $cabFile"
	} else {
		# write the final prompt to log before compression to complete the log file
		Write-Log "Please upload the following file(s) to Microsoft for analysis, when compression finished:`n  $dataPath`_Results.zip" -tee -foreColor Yellow
		Add-Type -Assembly "System.IO.Compression.FileSystem"
		[System.IO.Compression.ZipFile]::CreateFromDirectory("$dataPath", "$dataPath`_Results.zip")
		# prompt
		Write-Host -ForegroundColor Green  "$(get-date -format "HH:mm:ss") *** Please upload the following file(s) to Microsoft for analysis:`n  $dataPath`_Results.zip"
	}
} else { Write-Log "`n$(get-date -format "HH:mm:ss") *** Please compress all files in $dataPath, upload zip file to MS workspace`n" -tee -foreColor Yellow }
#endregion ::::: STOP TRACING :::::
#endregion ::::: MAIN :::::


#region ::::: Supporting Information :::::
<#
https://github.com/walter-1/psTSS

:: internal KBs
::  Servicing: Tools: TSS TroubleShootingScript/toolset for rapid flexible data collection for CritSit and standard cases
::   https://internal.support.services.microsoft.com/en-us/help/4089531
::  Servicing: Tools: SDP + RFL PS scripts identify missing updates (Recommended Fix List)
::   https://internal.support.services.microsoft.com/en-us/help/3070416
:: To download files from MS workspace, see KB article 4012140: How to use Secure File Exchange to exchange files with Microsoft Support https://support.microsoft.com/en-US/help/4012140
#>
#endregion ::::: Supporting Information :::::


#region  ::::: ToDo ::::::
<# //josefh - ShowProgress 
- Overwork add - Script Duration and Function Duration after Time Stamp - Make it short
- Document - What the columns mean SDur; FDur
- Sync with Walt
#>

<# //Walt - Post Processing 
- e.g. xml --> txt 
- Check if we could gather Events as *.XML and afterwards create *.evtx and *.txt
#> 

<# if Cluster: Distribute Jobs acros Hosts 
- 
#> 
#endregion ::::: ToDo ::::::
