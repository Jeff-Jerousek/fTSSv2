#region ::::: Help ::::: 

<#  
.SYNOPSIS 
	Script to gather data from a Windows based computer
	PSTSS-Sample-v0.7.1

.DESCRIPTION
	This script collects data from one or more computers

.PARAMETER ComputerNames
	Define on which computers you want to run the script. Default is local host

.PARAMETER LogPathLocal
	Path where we store the data. Default is SystemDrive\MS_DATA\DataTime; e.g. C:\MS_DATA\180925-101214

.PARAMETER HoursBack
	How much hours should we look back in the event data and collect them. Default =1 
	
.PARAMETER EventLogNames
	Define the Eventlogs you want to gather; wildcard * is allowed
	Sample: -EventLogNames "System", Create"Application", "*CSVFS*", "*Smb*", "*winrm*", "*wmi*", "*spaces*" 

.EXAMPLE
	psTSS.ps1  # simply run it without any parameter to collect all data with defaults

.EXAMPLE 
	psTSS.ps1 -ComputerName # run the script data collection on specific computer  

#>
#endregion


#region ::::: Define Script Input Parameters ::::: 
param(
    $ComputerNames = $env:COMPUTERNAME,	# Pass ComputerNames e.g. H16N1, default is local host name
    [String]$LogPath = "$env:SystemDrive\MS_DATA\" + (Get-Date -Format 'yyMMdd-HHmmss'), # Path where the data on the local computer will be stored    
    [Int]$HoursBack = 1,					# Define how much hours we should look back in the eventlogs

    # Define which EventLogNames should be collected; either you pass the full Eventlogname or a mask like "*Hyper*"
    # To check out what the Eventlog names look like for e.g. Hyper-V: Get-WinEvent -ListLog "*Hyper-V*"
    $EventLogNames=(
        "System", 
        "Application", 
        "*CSVFS*" 
        #"*Smb*", 
        #"*winrm*", 
        #"*wmi*", 
        #"*spaces*",
        #"*Hyper-V*",
        #"Microsoft-Windows-FailoverClustering/Operational" 
    ),

    #region  ::::: Switches ::::: 
    [switch]$NetInfo 		= $false      # If $NetInfo is true, we call GatherNetInfoPerHost to collect network related information
    #endregion  ::::: Switches ::::: 
)
#endregion


#region ::::: Define Global Variables ::::: 
    # Section for global variables, which you don´t want to show up in the parameter region        
    [bool]$IsClusSvcRunning = $False	# variable, to save status of cluster service running/stopped 

#endregion ::::: Define Global Variables ::::: 


#region ::::: Helper Functions :::::

#function Show Progress - Global parameters
$sTimeStampScriptStart= [String](Get-Date -Format 'yyMMdd-HHmmss')
$TimeStampScriptStart = Get-Date				         # get the timestamp, when this script starts
$TimeStampStartSaved  = $Script:TimeStampScriptStart	 # only first time save the script start timestamp

$DebugLogPath         = $LogPath                         # Directory, where the logs are stored
$DebugLogPathFull     = "$DebugLogPath\$sTimeStampScriptStart-ScriptDebug.log"   # FullPath of the Scripts Debug.log
$DebugLogLevel        = 3                                # If DebugLogLevel is 3 everything is logged; 0 is disabled, 1=Light, 2= Medium, 3=All
$DebugLogBuffer       = @()                              # Collect DebugLog Messages in ShowProgress and save them later to a file
$DebugLogCount        = 0                                # Counter for DebugLogs
$DebugLogCountMax     = 50                               # After X Messages Save to file 
$DebugLogToFile       = $True                            # Default is True, so we spew out the Debug Messages to a File 
$RunOnlyOnce          = $True                            # Bool to spew out some Messages only once
$ScriptFullName       = $MyInvocation.InvocationName     # Full Path of the Script Name


function ShowProgress { 
# SYNOPSIS: show what we are doing so far; should be placed on top of all other functions
    param(
        $MessageUser = "",		      # pass your own message
        $ForeColor =  "White"	      # default ForeGroundColor is White        
    )
    
    If ($Script:DebugLogLevel -eq 0 ) { Return } # If DebugLogLevel is 0 exit this function imediately      
    
    # Get the function name, that was calling ShowProgress
    function GetFunctionName ([int]$StackNumber = 1) {
        # https://stackoverflow.com/questions/3689543/is-there-a-way-to-retrieve-a-powershell-function-name-from-within-a-function
        return [string]$(Get-PSCallStack)[$StackNumber].FunctionName
    }
    $TimeDisplay = [String](Get-Date -Format 'yyMMdd-HHmmss') # time stamp to display on each action/function call. eg 'yyMMdd-HHmmss'
    $TimeStampCurrent = Get-Date
    $TimeDiffToStart = $TimeStampCurrent - $TimeStampScriptStart		# overall duration since start of script
    $TimeDiffToLast =  $TimeStampCurrent - $Script:TimeStampStartSaved	# time elapsed since the last action
	$Script:TimeStampStartSaved = $TimeStampCurrent						# update/save timestamp to measure next progress duration
    $FuncName =  GetFunctionName -StackNumber 2							# Last Function Name
    [String]$DurScriptDisplay = "" + $TimeDiffToStart.Minutes + ":" + $TimeDiffToStart.Seconds	# " ;Script ran for Min:Sec  = " # display duration since script start
    [String]$DurFunctionDisplay = "" + $TimeDiffToLast.Minutes +  ":" + $TimeDiffToLast.Seconds	# " ;Last Action took Min:Sec= " # display duration of last action or function call
    if (-not ($TimeDiffToLast.TotalSeconds -ge 1) ) { $DurFunctionDisplay = "0:0" }

    
    If ($RunOnlyOnce){ # Only first time write the head line to explain the columns        
        $Description= "Script Started at $sTimeStampScriptStart ScriptFullName:$ScriptFullName on Host:$($Env:ComputerName) "        
        If (-Not ( Test-Path -Path $DebugLogPath ) ){ # if the DebugLogPath does not already exist, e.g. default is c:\MSDATA, then Create it 
            New-Item -Path $DebugLogPath -ItemType Directory
        }
        write-host -fore Green $Description
        $Description | Out-File -FilePath $DebugLogPathFull -Append

        $Description= "TimeStamp    |TimeSinceScriptStarted Min:Sec|DurationOfLastAction Min:Sec|FunctionName| UserMessage"
        write-host $Description
        $Description | Out-File -FilePath $DebugLogPathFull -Append
        $Script:RunOnlyOnce= $False
    }
    $FullString= "$TimeDisplay|$DurScriptDisplay|$DurFunctionDisplay|$FuncName| $MessageUser"
    write-host -Fore $ForeColor $FullString
    
    # if $DebugLogToFile is $Ture store Output in the Logfile
    if ($DebugLogToFile){
        $Script:DebugLogCount++
        $Script:DebugLogBuffer+= $FullString
        if ($Script:DebugLogCount -ge $DebugLogCountMax) {
            write-host -ForegroundColor Yellow "Flushing DebugLogBuffer to $DebugLogPathFull"
            $Script:DebugLogBuffer | Out-File -FilePath $DebugLogPathFull -Append

            $Script:DebugLogCount= 0    # Reset DebugLogCount to 0
            $Script:DebugLogBuffer= @() # Reset DebugLogBuffer to empty String        
        }
    }
} # End of ShowProgress

# Checkout if the script runs as admin
function DoIRunAsAdmin{ 
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal `
                        ( [Security.Principal.WindowsIdentity]::GetCurrent() ) 
    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) { 
        return $true  
    } 
    else { 
       return $false 
    } 
} 

function CreateFolder { 
    # SYNOPSIS: a general function to create any folder, do some checks and do reporting
    Param(
        $HostName,
        $FolderPath
    )
    ShowProgress "Enter"
    $ErrorActionPreferenceSave =  $ErrorActionPreference # Save the current ErrorActionPreference
    $ErrorActionPreference = 'Stop'   # Change ErrorActionPreferrence to stop in order to prevent the cmdlet to handle the error on its own
    
    if (-not (Test-Path $FolderPath) ){ # if the folder does not already exist
        ShowProgress "...On Node:$HostName creating folder: $FolderPath"

        try{
            ShowProgress "try:CreateFolder: $FolderPath"
            Invoke-Command -ComputerName $HostName -ScriptBlock {		        # Make it all remote capable 
                New-Item -Path $Using:FolderPath -ItemType Directory | Out-Null	# Create folder, could be remote and suppress output
            }
            ShowProgress "Folder $FolderPath could be created successfully"  
            #ShowProgress "...On Node:$HostName finished creating folder: $FolderPath"    
        }
        Catch{ # since ErrorActionPreference is on 'Stop' we jump into the catch block if New-Item failed 
            ShowProgress -Fore red "Catch: Error during Folder Creation"  # we ran into an issue 
            ShowProgress -Fore red "Unable to create the Folder $FolderPath on $HostName " 
            ShowProgress -Fore Red "FullQualifiedErrorId: $($Error[0].FullyQualifiedErrorId)"
            ShowProgress -Fore Red "Full ErrorMessage:$_"
            If ($Error[0].FullyQualifiedErrorId -like "AccessDenied*"){ 
                ShowProgress -Fore Magenta "Please check if you are running the powershell host (window) with administrative privileges" 
            }
            If ($Error[0].FullyQualifiedErrorId -like "*server name cannot be resolved*"){                 
                $HostNameFQDN= [System.Net.Dns]::GetHostEntry($HostName).HostName  
                ShowProgress -Fore Magenta "Looks like the Server Name could not be resolved. [System.Net.Dns]::GetHostEntry(`$HostName):$HostNameFQDN "
            }
                        
            ShowProgress -ForeColor Yellow -BackColor Black "Aborting this script now " 
            EXIT           
        }        
    }   
    $ErrorActionPreference = $ErrorActionPreferenceSave
    ShowProgress "Exit"
}



function CreateLogFolderOnHosts { 
# SYNOPSIS: could be only one
    param(
        $ComputerNames,
        $LogPath
    )
    ShowProgress "...Start creating Log folder on Hosts: $ComputerNames"                
    foreach($ComputerName in $ComputerNames){
        ShowProgress "...Start creating Log folder on Host:$ComputerName"                
        $LogPathDollar = $LogPath.Replace(":","$")				# e.g. C:\MS-Data --> C$\MS-Data
        $LogPathUNC = "\\$($ComputerName)\$LogPathDollar"		# e.g. \\H16N2\c$\MS-Data                
        CreateFolder -HostName $ComputerName -FolderPath $LogPathUNC
    }
    ShowProgress "...Finished creating log folder on hosts"
}  

function MoveDataFromAllComputersToLocalComputer { 
# SYNOPSIS: move remotly collected data to local folder, e.g. C:\MS_DATA\180925-101214
    param(
        $ComputerNames        
    )
    ShowProgress "Enter"
    $LocalHost = $env:COMPUTERNAME    
    $LogPathLocal = $Script:LogPath   # LogPath e.g. c:\MS_DATA
    $ErrorActionPreferenceSave =  $ErrorActionPreference # Save the current ErrorActionPreference
    $ErrorActionPreference = 'Stop'   # Change ErrorActionPreferrence to stop in order to prevent the cmdlet to handle the error on its own
    $WaitSec = 10                     # Wait for a couple of seconds; default 10 seconds

    ShowProgress "...Start moving all data files from all Hosts:$ComputerNames to local Host:$LocalHost"                
    foreach($ComputerName in $ComputerNames){
        if (-not ($ComputerName -eq $LocalHost) ){            
            $LogPathDollar = $LogPath.Replace(":","$")                  # e.g. $LogPath = C:\MS_DATA --> C$\MS_DATA
            $LogPathRemoteUNC   = "\\$($ComputerName)\$LogPathDollar"   # e.g. \\H16N2\c$\MS_DATA               
            ShowProgress "...Start moving files from $LogPathRemoteUNC to $LogPathLocal"   

            # Sometimes the remote path is not reachable, so we check out and handle this one time
            # if it becomes a reoccuring issue we should run this in a loop and try several times 
            try{
                ShowProgress "...trying to reach LogPath: Get-ChildItem -Path $LogPathRemoteUNC "
                $RemoteFiles = Get-ChildItem -Path $LogPathRemoteUNC # Check if the remote path  $LogPathRemoteUNC is reachable
            }
            Catch{ # since ErrorActionPreference is on 'Stop' we jump into the catch block if Get-ChildItem reported an error
                ShowProgress -Fore DarkMagenta "Catch: Could not reach remote Path: $LogPathRemoteUNC"  # we had an issue - lets wait and do the move then
                ShowProgress -Fore DarkMagenta "Let´s wait for some seconds:$WaitSec ... and try again" 
                Start-Sleep -Seconds $WaitSec                
            }
            finally{
                ShowProgress "Finally: Moving Remote files to Local Host "                
                ShowProgress "...trying to collect all data files from all Hosts:$ComputerNames to local Host:$LocalHost ..."
                Move-Item -Path $LogPathRemoteUNC\* -Destination $LogPathLocal  # Move Files to Local Path       
            }
        }
    }
    $ErrorActionPreference = $ErrorActionPreferenceSave
    ShowProgress "...Finished moving all data files from all Hosts:$ComputerNames to local Host:$LocalHost"                
    ShowProgress "Exit"
}

#endregion ::::: Helper Functions :::::

#region ::::: Worker Functions ::::::

function GetEventLogs {
# SYNOPSIS: collect eventlogs from all machines
    param(
        $ComputerNames,                 # the name or a list of names of the computers, local or remote you want to gather Eventlogs from
        $HoursBack = $Script:HoursBack,  # Define how much hours we should look back in the logs; Default is script scope variable $HoursBack
        $LogNames                       # list of event log names; either you pass the full Event Log name like "System" or a mask like "*Hyper*"
                                        # Sample: $EventLogNames=("System", "Application", "*CSVFS*")
    )
    ShowProgress "Enter"
    foreach($ComputerName in $ComputerNames){
        # Gather all EventLogs from current ComputerName, extract only last # of hours
        # Walk through each LogName in LogNames e.g. ("System", "Application", "*CSVFS*")
        foreach($LogName in $LogNames){        
            $LogFamilyNames = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue  # $LogFamilyNames could be a mask representing several Logs - a LogFamily - e.g. *SMB*

            # if the LogName does not exist on this computer spew out a message
            If ( $LogFamilyNames -eq $Null) {
                ShowProgress -Fore DarkMagenta "Could not find the following Log on this Computer: $LogName"
            }

            # if a Pattern like *SMB* has been passed - walk through each Logname         
            foreach($LogFamilyName in $LogFamilyNames){ # Microsoft-Windows-SmbClient/Audit, Microsoft-Windows-SMBServer/Audit and so on
                $LogFileName = ($LogFamilyName.LogName).Replace("/","_") # Replace Forward Slash in EventLogNames with UnderScore

                $LogPathDollar = $LogPath.Replace(":","$")            # e.g. C:\MS-Data --> C$\MS-Data
                $LogPathUNC   = "\\$($ComputerName)\$LogPathDollar"  # e.g. \\H16N2\c$\MS-Data                
                    
                $LogFileNameXML =  "$LogPathUNC\$ComputerName" + "_" + $LogFileName + ".XML"
                $LogFileNameTXT =  "$LogPathUNC\$ComputerName" + "_" + $LogFileName + ".Log"
                $LogFileNameEvtx = "$LogPathUNC\$ComputerName" + "_" + $LogFileName + ".evtx"
                
                #Gather SystemEventlogs
                ShowProgress "...Start gathering EventLog:$($LogFamilyName.LogName) for Computer:$ComputerName"

                # Collecting EventLogs respecting HoursBack
                $StartTime = (Get-Date).AddHours(-$HoursBack) 
                # Using a Filter Hash Table to filter events that match $MinutesBack
                # More Info:  https://blogs.technet.microsoft.com/heyscriptingguy/2014/06/03/use-filterhashtable-to-filter-event-log-with-powershell/
                $Evts = Get-WinEvent -ComputerName $ComputerName -ErrorAction SilentlyContinue  -FilterHashtable @{Logname=$LogFamilyName.LogName; StartTime=$StartTime}

                #Sorting Events and selecting properties we really need
                $EvtsSorted = $Evts | Sort TimeCreated -Descending | Select TimeCreated, LevelDisplayName, ProviderName, Id,  Message 
                                      
                # Export Events to deserialized *.xml file
                $EvtsSorted | Export-CliXml -Path $LogFileNameXML
                # Export Events as simple *.txt file
                $EvtsSorted | Export-Csv -Path $LogFileNameTXT -NoTypeInformation
                            
                # Gathering Eventlogs in old style *.evtx with wevtutil.exe 
                ShowProgress "...Gathering *.evtx with Old-Style-Tool:wevtutil"
                $MilliSecondsBack = $HoursBack * 60 * 60 * 1000
                wevtutil.exe /remote:$ComputerName epl $LogFamilyName.LogName $LogFileNameEvtx /q:"*[System[TimeCreated[timediff(@SystemTime) <=$MilliSecondsBack]]]" /ow:true
                        
                ShowProgress "...Finished gathering $($LogFamilyName.LogName) for Computer:$ComputerName"
                ShowProgress "-----------------------------"
            }            
        }
    }
    ShowProgress "Exit"
}

 
function IfClusterGetNodeNames{ 
# SYNOPSIS: Test nodes connection and create a list of reachable nodes
    param(
        $ClusterName 
    )
    ShowProgress "Enter"
    $ErrorActionPreferenceNow= $ErrorActionPreference
    $ErrorActionPreference= 'Stop'
	$LocalComputerName = $env:COMPUTERNAME
    # Checkout if the cluster service is answering on this node
    try{ 
        # Check if the cluster service is running 
        if ( (Get-Service -Name ClusSvc).Status -eq "Running"  ){
            ShowProgress -Fore Green "Cluster Service is running on this computer: $LocalComputerName"
            $Script:IsClusSvcRunning = $True
        }
        else { # if we are on a cluster, but the cluster service is not running we land here
            $Script:IsClusSvcRunning= $False
            ShowProgress -Fore DarkMagenta "Cluster Service 'clussvc' is not running on this computer " 
            ShowProgress "Exit"
            RETURN $LocalComputerName # Return local ComputerName, if this computer is not running cluster service to gather Logs from this Host
        }
    } 
    
    catch{ # if we are not on a cluster at all we are landing here 
        ShowProgress -Fore DarkMagenta " 'Get-Service -Name ClusSvc' did not answer - looks if we have no Cluster Service on this computer " 
        ShowProgress "Exit"
        RETURN $LocalComputerName # Return local ComputerName, if this computer is not running cluster service to gather Logs from this Host
    }
    # if cluster service did not answer we do not reach the following code 

    # if cluster service answered we reached this code and will Test Network Connections to all Cluster Nodes
    ShowProgress "...Start testing if we can reach the Cluster Nodes over the network"
    $GoodNodeNames = @()  # Cluster Nodes we can reach over the network
    $BadNodeNames =  @()  # Cluster Nodes we can not reach over the network

    $ClusterNodeNames= (Get-ClusterNode).NodeName
    foreach($ClusterNodeName in $ClusterNodeNames){ 
        if (Test-Connection -ComputerName $ClusterNodeName -Count 1 -Quiet){ # test network connection
            $GoodNodeNames += $ClusterNodeName
        }
        else {
            $BadNodeNames += $ClusterNodeName
        }
    }
    $Nodes = [PSCustomObject]@{
        Good = $GoodNodeNames
        Bad =  $BadNodeNames
    }
        
    ShowProgress -Fore Green   "   - Could connect to Cluster Nodes: $($Nodes.Good)"
    if ($Nodes.Bad -ne $Null){
        ShowProgress -Fore Red "   - Could not connect to Cluster Nodes: $($Nodes.Bad)" 
    }
    else{
        ShowProgress "   - Could connect to all Cluster Nodes" -ForeColor "green"

    }
    ShowProgress "...Finished testing network connection to Cluster Nodes"
    $ErrorActionPreference= $ErrorActionPreferenceNow
    ShowProgress "Exit"
    Return $Nodes.Good # Return only the Good Nodes we can reach    
}


function GetNetInfoPerHost{
# SYNOPSIS: collect network related info on each host
    param(
            $ComputerNames           
    )
    ShowProgress "Enter"
    if ($Script:NetInfo -eq $false) { RETURN } # if the switch $NetInfo is false exit this function and do not collect any Net-data here
    $LogPathLocal = $Script:LogPath   # LogPath e.g. C:\MS_DATA
    foreach($ComputerName in $ComputerNames){          
        
        ShowProgress "...Start gathering network info on Computer:$ComputerName "

        $net = [PSCustomObject][ordered]@{  
            ComputerName =         $ComputerName
            NetIpconfig =      Get-NetIPConfiguration -CimSession $ComputerName
            Ipconfig =         Ipconfig /all

            SmbMultichannelConnection = Get-SmbMultichannelConnection -CimSession $ComputerName
            SmbServerConfiguration = Get-SmbServerConfiguration -CimSession $ComputerName
            SmbConnection = Get-SmbConnection -CimSession $ComputerName
            SmbSession = Get-SmbSession -CimSession $ComputerName
            SmbBandWidthLimit = Get-SmbBandWidthLimit -CimSession $ComputerName -ErrorAction SilentlyContinue
            SmbServerNetworkInterface = Get-SmbServerNetworkInterface -CimSession $ComputerName
            SmbMultichannelConstraint = Get-SmbMultichannelConstraint -CimSession $ComputerName
            SmbWitnessClient = Get-SmbWitnessClient -CimSession $ComputerName

            NIC = Get-NetAdapter -CimSession $ComputerName
            NICAdv = Get-NetAdapterAdvancedProperty -CimSession $ComputerName -Name *
            NICBind = Get-NetAdapterBinding -CimSession $ComputerName –Name *
            NICRxTx = Get-NetAdapterChecksumOffload -CimSession $ComputerName -Name *
            NICHW = Get-NetAdapterHardwareInfo -CimSession $ComputerName -Name *
            NICRIpsec = Get-NetAdapterIPsecOffload -CimSession $ComputerName -Name *
            NICLso = Get-NetAdapterLso -CimSession $ComputerName -Name *
            NICQos = Get-NetAdapterQos -CimSession $ComputerName –Name *

            NICREnc = Get-NetAdapterEncapsulatedPacketTaskOffload -CimSession $ComputerName -Name *
            NICRdma = Get-NetAdapterRdma -CimSession $ComputerName –Name *
            NICRsc = Get-NetAdapterRsc -CimSession $ComputerName –Name *
            NICRss = Get-NetAdapterRss -CimSession $ComputerName –Name *
            NICSriov = Get-NetAdapterSriov -CimSession $ComputerName –Name *
            NICVmqQueue = Get-NetAdapterVmqQueue -CimSession $ComputerName –Name *
            NICVmq = Get-NetAdapterVmq -CimSession $ComputerName –Name *
        }
        
        # Export Info from each Node in a Separate File
        $net | Export-CliXML -Path "$LogPathLocal\$($ComputerName)-NetInfoPerNode.xml"
        ShowProgress "...Finished gathering network Info per computer and stored in $LogPathLocal\$($ComputerName)-NetInfoPerNode.xml"        
        ShowProgress "Exit"
    }
}    


# Collect Computer specific Data from each Cluster Node
function GatherGeneralInfoPerNode{
    param(
        $ComputerNames
    )
    ShowProgress "Enter"
    $LogPathLocal = $Script:LogPath
    foreach($ComputerName in $ComputerNames){       
        # Read Current Windows Version from the Registry 
        $WinNTKey= Invoke-Command -ScriptBlock { Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" }
        $WinVer= $WinNTKey | Select ProductName, InstallationType, ReleaseId, CurrentMajorVersionNumber, CurrentMinorVersionNumber, CurrentBuild, UBR
        $WinVerGUI= "$($WinVer.ProductName) - Microsoft Windows $($WinVer.InstallationType) - Version $($WinVer.ReleaseId) (OS Build $($WinVer.CurrentBuild).$($WinVer.UBR)) "
        
        $GenInf= [PSCustomObject][ordered]@{  
            HostName=         $ClusterNode.Name
            Hotfix=           Get-Hotfix -ComputerName $ClusterNode            
            WinVer=           $WinVer
            WinVerGUI=        $WinVerGUI
            ComputerInfo=     Get-ComputerInfo
            PSVersionTable=   $PSVersionTable        

        }        
        # Export Info from each Node in a Separate File
        ShowProgress "Export General Info: HostName, Hotfix, Winver, ComputerInfo, PSVersionTable from Host: $ComputerName"
        $GenInf | Export-CliXML -Path "$LogPathLocal\$($ClusterNode.Name)-GeneralInfoPerNode.xml"
        ShowProgress "...Finished Gathering GeneralInfoPerNode - stored in $LogPathLocal\$($ClusterNode.Name)-GeneralInfoPerNode.xml"; write-host
                        
    }    
    ShowProgress "Exit"
}

function 5120 {
    # SYNOPSIS:  collect data for symptom System Event ID 5120
    ShowProgress "Enter"    
    $ComputerNames = IfClusterGetNodeNames # Check if Cluster Service answers on the current computer; if yes get the node names we can reach over network
    CreateLogFolderOnHosts -ComputerNames $ComputerNames -LogPath $LogPath # Create data folder on all computers - it could be only one

    GetNetInfoPerHost -ComputerNames $ComputerNames

    MoveDataFromAllComputersToLocalComputer -ComputerNames $ComputerNames

    # Do the work longer running parts
    GetEventLogs  -ComputerNames $ComputerNames -HoursBack $HoursBack -LogNames $EventLogNames
    ShowProgress "Exit"
}

#endregion ::::: Worker Functions ::::::


#region ::::: MAIN ::::::
# Preparations - Quick running functions
ShowProgress -Fore Green "Script Start..."
# Checkout if we are running with elevated privileges
$RunningAsAdmin= DoIRunAsAdmin
If ($RunningAsAdmin -eq $False){
    ShowProgress -Fore Red         "The script does not run in privileged (admin) mode"
    ShowProgress -Fore DarkMagenta "so we can´t query the cluster service, can´t create a log folder, debuglogfile and so on... "
    ShowProgress -Fore DarkMagenta "Please run again in privileged mode as admin"
    ShowProgress -Fore Red         "Exiting script now !"
    EXIT # Exit the script now as it doesn´t make sense to run this script in non privileged mode
}

ShowProgress -Fore Green "Running functions that should go quickly now ..."
$ComputerNames = IfClusterGetNodeNames # Check if Cluster Service answers on the current computer; if yes get the node names we can reach over network else return local computername

ShowProgress "...running data collection on ComputerNames: $ComputerNames"
if ($IsClusSvcRunning) { # if script runs on a cluster create the LogFolder $LogPath on all Cluster Nodes
    CreateLogFolderOnHosts -ComputerNames $ComputerNames -LogPath $LogPath 
}	
else { # else if the cluster service is not running create LogFolder $LogPath on local host
    CreateFolder -HostName "$env:ComputerName" -FolderPath $LogPath
}

# Do the work longer running parts
ShowProgress -Fore Green "Running functions that take longer now ..."
GetEventLogs  -ComputerNames $ComputerNames -HoursBack $HoursBack -LogNames $EventLogNames

GetNetInfoPerHost -ComputerNames $ComputerNames

MoveDataFromAllComputersToLocalComputer -ComputerNames $ComputerNames

# End of Script Messages
$ScriptDuration= ( (Get-Date) - $TimeStampScriptStart ) # Calculate how long the script ran
ShowProgress -Fore Green "Script ran for Min:Sec - $($ScriptDuration.Minutes):$($ScriptDuration.Seconds) "
$DebugLogCount= $DebugLogCountMax # to flush $DebugLogBuffer to the Logfile
ShowProgress -Fore Green "Exit Script - End of Script Logs can be found in $LogDir"


#endregion ::::: MAIN ::::::

#region  ::::: ToDo ::::::
<# //josefh - ShowProgress 
- Overwork add - Script Duration and Function Duration after Time Stamp - Make it short
- Document - What the columns mean SDur; FDur
- Sync with Walt
--> Done <-- 
#>

<# //Walt - Post Processing 
- e.g. xml --> txt 
- Check if we could gather Events as *.XML and afterwards create *.evtx and *.txt
#> 

<# Distribute Jobs across Hosts 
- 
#> 
#endregion 