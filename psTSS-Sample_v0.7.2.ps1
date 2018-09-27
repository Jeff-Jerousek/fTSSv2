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
	Sample: -EventLogNames "System", "Application", "*CSVFS*", "*Smb*", "*winrm*", "*wmi*", "*spaces*" 

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
    [bool]$IsCluster = $False						# define script scope variable, whether we are running the script on a cluster or not
    $TimeStampScriptStart = Get-Date				# get the timestamp, when this script starts
    $TimeStampStartSaved = $TimeStampScriptStart	# only first time save the script start timestamp
    
#endregion ::::: Define Global Variables ::::: 

#region ::::: Helper Functions :::::


function ShowProgress { #josefh
# SYNOPSIS: show what we are doing so far; should be placed on top of all other functions
    param(
        $MessageUser = "",		# pass your own message
        $ForeColor =  "White",	# default ForeGroundColor is White
        $BackColor =  "Blue"	# default BackGroundColor is Blue
    )
    # Get the function name, that was calling ShowProgress
    function GetFunctionName ([int]$StackNumber = 1) {
        # https://stackoverflow.com/questions/3689543/is-there-a-way-to-retrieve-a-powershell-function-name-from-within-a-function
        return [string]$(Get-PSCallStack)[$StackNumber].FunctionName
    }
    $TimeDisplay = [String](Get-Date -Format 'HH-mm-ss') + " - "	# time stamp to display on each action/function call. eg 'yyMMdd-HHmmss'
    $TimeStampCurrent = Get-Date
    $TimeDiffToStart = $TimeStampCurrent - $TimeStampScriptStart		# overall duration since start of script
    $TimeDiffToLast =  $TimeStampCurrent - $Script:TimeStampStartSaved	# time difference 
	$Script:TimeStampStartSaved = $TimeStampCurrent						# update/save timestamp to measure next progress duration
    $FuncName =  GetFunctionName -StackNumber 2							# Last Function Name
    [String]$DurScriptDisplay = "" + $TimeDiffToStart.Minutes + ":" + $TimeDiffToStart.Seconds	# " ;Script ran for Min:Sec  = " # display duration since script start
    [String]$DurFunctionDisplay = "" + $TimeDiffToLast.Minutes +  ":" + $TimeDiffToLast.Seconds	# " ;Last Action took Min:Sec= " # display duration of last action or function call
    if (-not ($TimeDiffToLast.TotalSeconds -ge 1) ) { $DurFunctionDisplay = "" }
    write-host -Fore $ForeColor $TimeDisplay $DurScriptDisplay $DurFunctionDisplay $FuncName $MessageUser
	
}
<#
function ShowProgress { #josefh:ShowProgress helper function
    param(
        $MessageUser = "",     # pass your own Message
        $ForeColor = "white",  # default ForeGround Color is white
        $BackColor = "blue"    # default BackGroundColor is Blue
    )
    # Get the Function name, that was calling ShowProgress
    function GetFunctionName ([int]$StackNumber = 1) {
        # https://stackoverflow.com/questions/3689543/is-there-a-way-to-retrieve-a-powershell-function-name-from-within-a-function
        return [string]$(Get-PSCallStack)[$StackNumber].FunctionName
    }

    $Message1 = [String](Get-Date -Format 'yyMMdd-HHmmss') + ": "
    $TimeStampCurrent = Get-Date
    $TimeDiffToStart = $TimeStampCurrent - $TimeStampScriptStart
    $TimeDiffToLast =  $TimeStampCurrent - $Script:TimeStampStartSaved

    $Script:TimeStampStartSaved = $TimeStampCurrent

    $Message2 =  GetFunctionName -StackNumber 2 # Last Function Name
    
    $Message3 = " ;Script ran for Min:Sec  = " + $TimeDiffToStart.Minutes + ":" + $TimeDiffToStart.Seconds
    $Message4 = " ;Last Action took Min:Sec = " + $TimeDiffToLast.Minutes +  ":" + $TimeDiffToLast.Seconds

    
    if (-not ($TimeDiffToLast.TotalSeconds -ge 1) ){ $Message4 = "" }
    write-host -Fore $ForeColor $Message1 $Message2 $MessageUser $Message3 $Message4
}
#>

function CreateFolder { #josefh
# SYNOPSIS: a general function to create any folder, do some checks and do reporting
    Param(
        $HostName,
        $FolderPath
    )
    if (-not (Test-Path $FolderPath) ){
        ShowProgress "...On Node:$HostName creating folder: $FolderPath"
        Invoke-Command -ComputerName $HostName -ScriptBlock {		# Make it all remote capable 
            New-Item -Path $Using:FolderPath -ItemType Directory	# Create folder, could be remote
        }  
        ShowProgress "...On Node:$HostName finished creating folder: $FolderPath"    
    }
    else{
        write-host -Fore Magenta "This Path: $FolderPath already exists; please pass another argument for -LogPath or delete this path"
        exit
    }
}


function CreateLogFolderOnHosts { #josefh
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

function MoveDataFromAllComputersToLocalComputer { # josefh 
# SYNOPSIS: move remotly collected data to local folder, e.g. C:\MS_DATA\180925-101214
    param(
        $ComputerNames        
    )
    $LocalHost = $env:COMPUTERNAME    
    $LogPathLocal = $Script:LogPath   # LogPath e.g. c:\MS_DATA
    $ErrorActionPreferenceSave =  $ErrorActionPreference # Save the current ErrorActionPreference
    $ErrorActionPreference = 'Stop'   # Change ErrorActionPreferrence to stop in order to prevent the cmdlet to handle the error on its own
    $WaitSec = 10                     # Wait for a couple of seconds; default 10 seconds

    ShowProgress "...Start moving all data files from all Hosts:$ComputerNames to local Host:$LocalHost"                
    foreach($ComputerName in $ComputerNames){
        if (-not ($ComputerName -eq $LocalHost) ){            
            $LogPathDollar = $LogPath.Replace(":","$")                  # e.g. $LogPath = C:\MS_DATA --> C$\MS_DATA
            $LogPathRemoteUNC   = "\\$($ComputerName)\$LogPathDollar"  # e.g. \\H16N2\c$\MS_DATA               
            ShowProgress "...Start moving files from $LogPathRemoteUNC to $LogPathLocal"   

            # Sometimes the remote path is not reachable, so we check out and handle this one time
            # if it becomes a reoccuring issue we should run this in a loop and try several times 
            try{
                "try:"
                $RemoteFiles = Get-ChildItem -Path $LogPathRemoteUNC # Check if the remote path  $LogPathRemoteUNC is reachable
            }
            Catch{ # since ErrorActionPreference is on 'Stop' we jump into the catch block if Get-ChildItem reported an error
                "Catch:"  # we had an issue - lets wait and do the move then
                "$LogPathRemoteUNC is currently not available - Let´s wait for some seconds:$WaitSec" 
                Start-Sleep -Seconds 10
                ShowProgress "...2nd time - Trying to move all data files from all Hosts:$ComputerNames to local Host:$LocalHost"                
            }
            finally{
                "Finally:"                
                Move-Item -Path $LogPathRemoteUNC\* -Destination $LogPathLocal  # Move Files to Local Path       
            }
        }
    }
    $ErrorActionPreference = $ErrorActionPreferenceSave
    ShowProgress "...Finished moving all data files from all Hosts:$ComputerNames to local Host:$LocalHost"                
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

    foreach($ComputerName in $ComputerNames){
        # Gather all EventLogs from current ComputerName, extract only last # of hours
        # Walk through each LogName in LogNames e.g. ("System", "Application", "*CSVFS*")
        foreach($LogName in $LogNames){        
            $LogFamilyNames = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue  # $LogFamilyNames could be a mask representing several Logs - a LogFamily - e.g. *SMB*
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
                        
                ShowProgress "...Finished gathering $($LogFamilyName.LogName) for Computer:$ComputerName";write-host
            }            
        }
    }
}

 
function IfClusterGetNodeNames{ #josefh, SergeG
# SYNOPSIS: Test nodes connection and create a list of reachable nodes
    param(
        $ClusterName 
    )
	$LocalComputerName = $env:COMPUTERNAME
    # Checkout if the cluster service is answering on this node
    try{ 
        $ClusterName = (Get-Cluster -ErrorAction SilentlyContinue).Name
        $Script:IsCluster = $True
    } 
    # If cluster service does not answer, get out of this function, return the LocalComputerName
    catch{ 
        Write-Host "Cluster Service did not answer Cmdlet Get-Cluster on this computer " 
        RETURN $LocalComputerName # Return local ComputerName, if this computer is not running cluster service to gather Logs from this Host
    }
    
    # if cluster service answered we reached this code and will Test Network Connections to all Cluster Nodes
    ShowProgress "...Start testing if we can reach the Cluster Nodes over the network"
    $GoodNodes = @()  # Cluster Nodes we can reach over the network
    $BadNodes =  @()  # Cluster Nodes we can not reach over the network
    foreach($ClusterNode in $ClusterNodes){ 
        if (Test-Connection -ComputerName $ClusterNode.Name -Count 1 -Quiet){ # test network connection
            $GoodNodes += $ClusterNode
        }
        else {
            $BadNodes += $ClusterNode
        }
    }
    $Nodes = [PSCustomObject]@{
        Good = $GoodNodes
        Bad =  $BadNodes
    }
        
    ShowProgress "   - Could     connect to Cluster Nodes: $($Nodes.Good)" -ForeColor "green"
    if ($Nodes.Bad -ne $Null){
        ShowProgress "   - Could not connect to Cluster Nodes: $($Nodes.Bad)" -ForeColor "red"
    }
    else{
        ShowProgress "   - Could connect to all Cluster Nodes" -ForeColor "green"

    }
    ShowProgress "...Finished testing network connection to Cluster Nodes"
    Return $Nodes.Good # Return only the Good Nodes we can reach
}


function GetNetInfoPerHost{
# SYNOPSIS: collect network related info on each host
    param(
            $ComputerNames           
    )
    "--------------Func:   [Switch]$NetInfo ----------------"
    if ($Script:NetInfo -eq $false) { RETURN } # if the swith $NetInfo is false exit this function and do not collect any Net-data here
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
        ShowProgress "...Finished gathering network Info per computer and stored in $LogPathLocal\$($ComputerName)-NetInfoPerNode.xml"; write-host                        
    }
}    

function 5120 {
# SYNOPSIS:  collect data for symptom System Event ID 5120
ShowProgress "...Script Start"
$ComputerNames = IfClusterGetNodeNames # Check if Cluster Service answers on the current computer; if yes get the node names we can reach over network
CreateLogFolderOnHosts -ComputerNames $ComputerNames -LogPath $LogPath # Create data folder on all computers - it could be only one

"--------------Script: [Switch]$NetInfo ----------------"
GetNetInfoPerHost -ComputerNames $ComputerNames

MoveDataFromAllComputersToLocalComputer -ComputerNames $ComputerNames

# Do the work longer running parts
GetEventLogs  -ComputerNames $ComputerNames -HoursBack $HoursBack -LogNames $EventLogNames

ShowProgress "...Script End"
}

#endregion ::::: Worker Functions ::::::


#region ::::: MAIN ::::::
# Preparations - Quick running functions
ShowProgress "...Script Start"
$ComputerNames = IfClusterGetNodeNames # Check if Cluster Service answers on the current computer; if yes get the node names we can reach over network
Write-host "...running data collection on ComputerNames: $ComputerNames"
if ($IsCluster) {CreateLogFolderOnHosts -ComputerNames $ComputerNames -LogPath $LogPath }	# Create data folder on all computers - it could be only one
else {CreateFolder -HostName "$env:ComputerName" -FolderPath $LogPath}							# Create data folder on local computer

# Do the work longer running parts
GetEventLogs  -ComputerNames $ComputerNames -HoursBack $HoursBack -LogNames $EventLogNames

"--------------Script: [Switch]$NetInfo ----------------"
GetNetInfoPerHost -ComputerNames $ComputerNames

MoveDataFromAllComputersToLocalComputer -ComputerNames $ComputerNames

ShowProgress "...Script End"
#endregion ::::: MAIN ::::::

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

<# Distribute Jobs across Hosts 
- 
#> 
#endregion 