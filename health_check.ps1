##############################
# CITRIX HEALTH CHECK SCRIPT #
##############################

# This health check script goes through the on-premise servers are performs checks to verify functionality

###################
#### VARIABLES ####
###################

# Variables 
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Finished list 
$list_stf = [System.Collections.ArrayList]@()
$list_cc = [System.Collections.ArrayList]@()
$list_pvs = [System.Collections.ArrayList]@()
$list_netscaler = [System.Collections.ArrayList]@()
$list_lic = [System.Collections.ArrayList]@()
$list_daas = [System.Collections.ArrayList]@()
$list_error = [System.Collections.ArrayList]@()



# Error counters
$counters = @{
    storefront = @{
            "network" = 0
            "compute" = 0
            "service" = 0
            "event" = 0
    }
    
    cloudconnector = @{
            "network" = 0
            "compute" = 0
            "service" = 0
            "event" = 0
    }

    provisioning = @{
            "network" = 0
            "compute" = 0
            "service" = 0
            "event" = 0
    }

    netscaler = @{
            "network" = 0
            "compute" = 0
            "service" = 0
            "event" = 0
    }

    license = @{
            "network" = 0
            "compute" = 0
            "service" = 0
            "event" = 0
    }
}




### Server Lists
$CCServers = @("", "", "")
$PVSServers = @("", "", "")
$STFServers = @("", "")
$LICServer = ""


###################
#### FUNCTIONS ####
###################

# These functions are passed in through the script block as arguements in the form of function blocks
# - Output 
# - Network 
# - Compute
# - Services
# - Events

####################
### Output Functions
####################

# Pads the string so that the total number of characters is 70
function output_padding {
    param(
        # entire string to have padding added
        [string]$input_string
    )
    
    # Padding to end up with 70 characters total
    $padding_counter = 70 - $input_string.Length
    
    if ($padding_counter -le 0) {
        return $input_string
    }

    return [string]($input_string + (' ' * $padding_counter))
}


# Prints out the direct value  
function output_direct {
    param(
        [string]$text,
        $value,
        $server
    )

    # Necessary to break into smaller pieces otherwise cant combine
    $string = output_padding($text)
    $result = $string + $value

    return $result
}



######################
### Utility Functions
######################

# Increments the counters by one
function utility_incrementValue($product, $counter) {
    $counters.$product.$counter += 1 
}



# Add to error log
function utility_error_log($error, $product, $counter, $server) {
    utility_incrementValue -product $product -counter $counter
    $list_error += $server + $error + "123"
}


# Add to log
function utility_log($message, $server) {
    return $server + " - " + $message + "`n"
}


# Returns the list of counters
function utility_debug_counters {
    param (
        [HashTable]$counters
    )
    
    Write-host " -- DEBUG COUNTER-- "
    $counters.Values | ForEach-Object {
        Write-host $_.Values
    }
    Write-host " -- DEBUG COUNTER -- "
}


# Reuturns all the items in a list
function utility_debug_lists {
    param (
        $lists
    )

    Write-Host " -- DEBUG LIST -- "
    foreach ($item in $lists) { 
        write-host $item
    }
    Write-Host " -- DEBUG LIST -- "
}


######################
### Network Functions
######################

# Check if the DNS record is present for a server hostname
function network_win_dns {(output_direct -text "Compute - CPU Usage %" -value (compute_win_cpu) -server $PVSServer)
        [string]$Port
    )

    $pass = "[PASS]"
    $fail = "[FAIL]"

    $pingResult = Test-NetConnection -ComputerName $Server_ping -Port $Port
    if ($pingResult.TcpTestSucceeded) {
            return $pass
        } else {
            return $fail
    }
}


######################
### Compute Functions
######################

# Returns the CPU Load % 
function compute_win_cpu {
    $cpuLoadPercentage = (Get-Counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 2 -MaxSamples 1).CounterSamples.CookedValue
    return [string][math]::Round($cpuLoadPercentage / 1, 0) 
}


# Returns Memory Usage %
function compute_win_mem {
    $physicalMemory = Get-WmiObject -class Win32_OperatingSystem | 
        ForEach-Object {
            $_.TotalVisibleMemorySize, $_.FreePhysicalMemory
        }
    $usedMemory = $physicalMemory[0] - $physicalMemory[1]
    $usedMemoryPercentage = ($usedMemory / $physicalMemory[0]) * 100
    return [string][math]::Round($usedMemoryPercentage /1, 0 )
}


# Returns Disk Usage %
function compute_win_disk_percent {
    param(
        # Server to check IP is present
        [string]$disk
    )

    $diskinfo = Get-WMIObject -class win32_logicaldisk -filter "DeviceID='$disk'"
    return [string][math]::Round($diskinfo.FreeSpace / 1GB, 0)
}


# Returns server Uptime
function compute_win_uptime {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $uptime = (Get-Date) - ($os.ConvertToDateTime($os.LastBootUpTime))
    return [string]$uptime.Days + " days " + [string]$uptime.Hours + " hours " + [string]$uptime.minutes + " min " + [string]$uptime.Seconds + " sec"
}


######################
### Service Functions
######################

# Returns if the registry value is present
function service_win_registry($Path, $Name, $ExpectedValue) {
    $pass = "[PASS]"
    $fail = "[FAIL]"

    if ((Get-ItemPropertyValue -Path $Path -Name $Name) -eq $ExpectedValue) {
        return $pass
    } else {
        return $fail  
    }         
}


# Returns if the Service is running
function service_win_Service {
    param(
        # Service to check running
        [string]$CxService
    )

    $status = (Get-Service -name $CxService).Status

    $pass = "[PASS]"
    $fail = "[FAIL]"

        if ($status -eq 'Running') {
            return $pass
        } else {
            return $fail
        }
}


        
           

######################
### Event Functions
######################


# Returns the events that are warning or error level
function event_win_events {
    $startTime = (Get-Date).AddDays(-1)
    $citrixlogs = get-winevent -logname application| where-object { $_.timecreated -ge $starttime -and $_.providername -like "*Citrix*"} | where-object { $_.leveldisplayname -eq "Error" -or $_.leveldisplayname -eq "Warning" }

    return $citrixlogs.Values
}






######################
### Helper Functions
######################

# return yellow or green based on counter
# product = citrix component
# counter = subcomponent
function greenOrYellow($product, $counter) {
    if ($counters.$product.$counter -eq 0) { 
        return "green" 
    } else {
        return "yellow"
    } 
}

# increment counters
# product = citrix component
# counter = subcomponent
function incrementValue($product, $counter) {
    $counters.$product.$counter += 1 
}

# Populate the error table
# populates list_error and increment counter 
function global:logError {
    param (
        [string]$serverName,
        [string]$serverType,
        [string]$category,
        [string]$message
    )

    # increment counter for serverType.category
    $counters[$serverType][$category] += 1


    $log_error = $serverName + " " + $message 

    return $log_error
}


######################
### DaaS
######################

function Get-DaaSInfo {
    param (
        [string]$customerId,
        [string]$client_id,
        [string]$client_secret,
        [string]$instanceId
    )

    # Token
    $tokenUrl = 'https://api-us.cloud.com/cctrustoauth2/root/tokens/clients'
    $response = Invoke-WebRequest $tokenUrl -Method POST -Body @{
      grant_type    = "client_credentials"
      client_id     = $client_id
      client_secret = $client_secret
    }
    $token = $response.Content | ConvertFrom-Json

    # Headers
    $headers = @{
        Authorization       = "CwsAuth Bearer=$($token.access_token)"
        'Citrix-CustomerId' = $customerId
        'Citrix-InstanceId' = $instanceId
        Accept              = 'application/json'
    }

    Write-Host "--- DaaS ---"

    # Uncomment if serviceStates endpoint is available
    # $response = Invoke-WebRequest "https://core.citrixworkspacesapi.net/$customerId/serviceStates" -Headers $headers
    # $serviceStates = $response | ConvertFrom-Json
    # $filteredStates = $serviceStates.items | Where-Object { ($_.serviceName -eq 'xendesktop' -or $_.serviceName -eq 'netscalergateway') }

    # Uncomment if filteredStates is available
    # foreach ($state in $filteredStates) {
    #    if ($state.daysToExpiration -lt 90) {
    #        Write-Host ""
    #        Write-Host "Service Name:".PadRight(50) $($state.serviceName)
    #        Write-Host "Days to Expiration:".PadRight(50) $($state.daysToExpiration)
    #        Write-Host ""
    #    }
    # }

    # System Logs
    $response = Invoke-WebRequest "https://api-us.cloud.com/systemlog/records" -Headers $headers

    $json = ConvertFrom-Json $response
    $items = $json.items | Where-Object { ([DateTime]::UtcNow - [DateTime]::Parse($_.utcTimestamp)).Days -lt 1 }
    $items | ForEach-Object {
      $eventType = $_.eventType
      $targetEmail = $_.targetEmail
      $actorDisplayName = $_.actorDisplayName
      $message = $_.message.'en-US'
      $utcTimestamp = $_.utcTimestamp
      Write-Host "`r`nEvent type: $eventType"
      Write-Host "Target email: $targetEmail"
      Write-Host "Actor display name: $actorDisplayName"
      Write-Host "Message: $message"
      Write-Host "UTC timestamp: $utcTimestamp`r`n"
    }

    Write-Host ""
}



######################
### NetScaler
######################

# Bypass Cert check needed
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}


# readonly user cofigured in commandset
$apiUser = "apiuser"
$apiPassword = "apiuserpassword123"

$NSIP = "170.11.37.26"

#JSON payload
$Login = ConvertTo-Json @{
    "login" = @{
        "username"=$apiUser
        "password"=$apiPassword
    }
}

# Login to the NetScaler and create a session (stored in $NSSession)
$invokeRestMethodParams = @{
    Uri             = "https://$NSIP/nitro/v1/config/login"
    Body            = $Login
    Method          = "Post"
    SessionVariable = "NSSession"
    ContentType     = "application/json"
}
$loginresponse = Invoke-RestMethod @invokeRestMethodParams

# Gets the stat objects for an input parameter 
function ReturnParameter {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputParameter
        )
    
    # Get HA node stats from NetScaler (no payload with GET)
    $invokeRestMethodParams = @{
        Uri         = "https://$NSIP/nitro/v1/stat/" + $InputParameter
        Method      = "Get"
        WebSession  = $NSSession
        ContentType = "application/json"
    }

    return Invoke-RestMethod @invokeRestMethodParams
}

function outputString($string1, $string2) {
        $paddedString = "`r`n" + [String]$string1.padRight(65) + [String]$string2
        return [String]$paddedString
}

function outputStringComparison($string1, $string2, $string3, $nsip, $category) {
    if ($String2 -eq $String3) {
        $paddedString = "`r`n" + [String]$string1.padRight(65) + "[PASS]"
        return [String]$paddedString
    } else {
        $paddedString = "`r`n" + [String]$string1.padRight(65) + "[FAIL]" + "Expected - " + [String]$string3
        $message = [String]$string3 + " Expected - " + [String]$string3
        $list_error += logError -servername $nsip -serverType "netscaler" -category $category -message [String]$message
        return [String]$paddedString
    }
}

function outputStringComparisonGT($string1, $string2, $string3, $nsip, $category) {
    if ($String2 -gt $String3) {
        $paddedString = "`r`n" + [String]$string1.padRight(65) + "[PASS]"
        return [String]$paddedString
    } else {
        $paddedString = "`r`n" + [String]$string1.padRight(65) + "[FAIL]" + " Expected - " + [String]$string3
        $message = [String]$string3 + " Expected - " + [String]$string3
        $list_error += logError -servername $nsip -serverType "netscaler" -category $category -message [String]$message 
        return [String]$paddedString
    }
}

$list_netscaler += "`r`n"
$list_netscaler += Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$list_netscaler += "`r`n`r`n--- Citrix NetScaler - $NSIP ---"


# System
$system = ReturnParameter("system")
$list_netscaler += outputString -string1 "Boot Time" -string2 $system.system.starttime
#$list_netscaler += outputString -string1 "CPU Usage %" -string2 $system.system.cpuusagepcnt
$list_netscaler += outputString -string1 "Memory Usage %" -string2 ([Math]::Round($system.system.memusagepcnt))
$list_netscaler += outputStringComparisonGT -string1 "Disk0 - Available - MB" -string2 ($system.system.disk0avail) -string3 "1000" -nsip $NSIP -category "compute"
$list_netscaler += outputStringComparisonGT -string1 "Disk1 - Available - MB" -string2 $system.system.disk1avail -string3 "6000" -nsip $NSIP -category "compute"




# HA
$hanode = ReturnParameter("hanode")
$list_netscaler += outputStringComparison -String1 "HA Configured" -String2 $hanode.hanode.hacurstatus -String3 "YES" -nsip $NSIP -category "compute" 
$list_netscaler += outputStringComparison -String1 "HA Current State" -String2 $hanode.hanode.hacurstate -String3 "UP" -nsip $NSIP -category "compute" 
$list_netscaler += outputStringComparison -String1 "HA Sync Failure" -String2 $hanode.hanode.haerrsyncfailure -String3 "0"  -nsip $NSIP -category "compute" 

# Interface
$interface = ReturnParameter("interface")
$list_netscaler += outputStringComparison -String1 "Interface Status - 0/1" -String2 $interface.interface.Item(0).curintfstate -String3 "UP" -nsip $NSIP -category "network"
$list_netscaler += outputString -String1 "Interface Uptime - 0/1" -String2 $interface.interface.Item(0).curlinkuptime -nsip $NSIP -category "network"
$list_netscaler += outputString -String1 "Interface Downtime - 0/1" -String2 $interface.interface.Item(0).curlinkdowntime -nsip $NSIP -category "network"


# LBVS
$service = ReturnParameter("service")
$servicegroup = ReturnParameter("servicegroup")
$lbvserver = ReturnParameter("lbvserver")

$list_netscaler += outputStringComparison -String1 "LBVS - $($lbvserver.lbvserver.Item(0).name) - State" -String2 $lbvserver.lbvserver.Item(0).state -String3 "UP" -nsip $NSIP -category "service"
$list_netscaler += outputStringComparison -String1 "LBVS - $($lbvserver.lbvserver.Item(0).name) - Server Health 100%" -String2 $lbvserver.lbvserver.Item(0).vslbhealth -String3 100 -nsip $NSIP -category "service"

$list_netscaler += outputStringComparison -String1 "LBVS - $($lbvserver.lbvserver.Item(1).name) - State" -String2 $lbvserver.lbvserver.Item(1).state -String3 "UP" -nsip $NSIP -category "service"
$list_netscaler += outputStringComparison -String1 "LBVS - $($lbvserver.lbvserver.Item(1).name) - Server Health 100%" -String2 $lbvserver.lbvserver.Item(1).vslbhealth -String3 100 -nsip $NSIP -category "service"

$list_netscaler += outputStringComparison -String1 "LBVS - $($lbvserver.lbvserver.Item(2).name) - State" -String2 $lbvserver.lbvserver.Item(2).state -String3 "UP" -nsip $NSIP -category "service"
$list_netscaler += outputStringComparison -String1 "LBVS - $($lbvserver.lbvserver.Item(2).name) - Server Health 100%" -String2 $lbvserver.lbvserver.Item(2).vslbhealth -String3 100 -nsip $NSIP -category "service"


# Auth vServer
$authenticationvserver = ReturnParameter("authenticationvserver")
$list_netscaler += outputStringComparison -String1 "Auth - $($authenticationvserver.authenticationvserver.Item(0).name) - State" -String2 $authenticationvserver.authenticationvserver.Item(0).state -String3 "UP" -nsip $NSIP -category "service"


# Auth Policy Hits
$authenticationpolicy = ReturnParameter("authenticationpolicy")
#outputString -String1 "Auth Policy Name" -String2 $authenticationpolicy.authenticationpolicy.Item(2).name
#outputString -String1 "Auth Policy Hits" -String2 $authenticationpolicy.authenticationpolicy.Item(2).pipolicyhits


# VPN vServer
$vpnvserver = ReturnParameter("vpnvserver")
$vpn = ReturnParameter("vpn")

$list_netscaler += outputStringComparison -String1 "VPN - $($vpnvserver.vpnvserver.Item(0).name) - State" -String2 $vpnvserver.vpnvserver.Item(0).state -String3 "UP" -nsip $NSIP -category "service"
$list_netscaler += outputStringComparison -String1 "VPN - $($vpnvserver.vpnvserver.Item(0).name) - No STA Connection Failure" -String2 $vpn.vpn.staconnfailure -String3 "0" -nsip $NSIP -category "service"



# Disconnect Nitro
$LogOut = @{
    "logout" = @{}
} | ConvertTo-Json

$invokeRestMethodParams = @{
    Uri             = "https://$NSIP/nitro/v1/config/logout"
    Body            = $LogOut
    Method          = "Post"
    WebSession      = $NSSession
    ContentType     = "application/json"
}
$logoutresponse = Invoke-RestMethod @invokeRestMethodParams


    
#######################
### Function Blocks ###
#######################

### Function blocks needed to pass into invoke-commands
$block_output_padding = ${function:output_padding}
$block_output_direct = ${function:output_direct}

$block_utility_incrementValue = ${function:utility_incrementValue}
$block_utility_error_log = ${function:utility_error_log}
$block_utility_debug_counters = ${function:utility_debug_counters}
$block_utility_log = ${function:utility_log}
$block_utility_debug_lists = ${function:utility_debug_lists}

$block_compute_win_cpu = ${function:compute_win_cpu}
$block_compute_win_mem = ${function:compute_win_mem}
$block_compute_win_disk_percent = ${function:compute_win_disk_percent}
$block_compute_win_uptime = ${function:compute_win_uptime}

$block_network_win_dns = ${function:network_win_dns}
$block_network_win_ping = ${function:network_win_ping}

$block_service_win_Service = ${function:service_win_Service}
$block_service_win_registry = ${function:service_win_registry}

$block_event_win_events = ${function:event_win_events}




#####################
### Script Blocks ###
#####################

# Cloud Connector script blocks
$CCScriptBlock = {
    # Step 1 - Declare functions passed in
    param($CCServer, $CCServers, $counters,
    [System.Collections.ArrayList]$list_cc,
    $block_output_padding, $block_output_direct, 
    $block_utility_incrementValue, $block_utility_error_log, $block_utility_debug_counters, $block_utility_log, $block_utility_debug_lists,
    $block_compute_win_cpu, $block_compute_win_mem, $block_compute_win_disk_percent, $block_compute_win_uptime, 
    $block_network_win_dns, $block_network_win_ping,
    $block_service_win_Service, $block_service_win_registry,
    $block_event_win_events)

    # Step 2 - set functions ready to be used from the function blocks
    Set-Item -Path function:output_padding -Value $block_output_padding
    Set-Item -Path function:output_direct -Value $block_output_direct

    Set-Item -Path function:utility_incrementValue -Value $block_utility_incrementValue
    Set-Item -Path function:utility_error_log -Value $block_utility_error_log
    Set-Item -Path function:utility_debug_counters -Value $block_utility_debug_counters
    Set-Item -Path function:utility_log -Value $block_utility_log
    Set-Item -Path function:utility_debug_lists -Value $block_utility_debug_lists

    Set-Item -Path function:compute_win_cpu -Value $block_compute_win_cpu
    Set-Item -Path function:compute_win_mem -Value $block_compute_win_mem
    Set-Item -Path function:compute_win_disk_percent -Value $block_compute_win_disk_percent
    Set-Item -Path function:compute_win_uptime -Value $block_compute_win_uptime

    Set-Item -Path function:network_win_dns -Value $block_network_win_dns
    Set-Item -Path function:network_win_ping -Value $block_network_win_ping

    Set-Item -Path function:service_win_Service -Value $block_service_win_Service
    Set-Item -Path function:service_win_registry -Value $block_service_win_registry

    Set-Item -Path function:event_win_events -Value $block_event_win_events

    # Variables
    # disk check
    cc_disk = "c:"

    # check network and dns working
    ccserver1 = "CC1"
    ccserver1ip = "10." 
    ccserver2 = "CC2"
    ccserver2ip = "10."
    ccserver3 = "CC3"
    ccserver3ip = "10."
    

    $list_return = [System.Collections.ArrayList]$()

    ## Start of items to monitor
    # Compute
    $list_return += utility_log -message (output_direct -text "Compute - CPU Usage %" -value (compute_win_cpu) -server $CCServer) -server $CCServer 
    $list_return += utility_log -message (output_direct -text "Compute - Memory Usage %" -value (compute_win_mem) -server $CCServer ) -server $CCServer 
    $list_return += utility_log -message (output_direct -text "Compute - Disk C: Usage %" -value (compute_win_disk_percent($cc_disk)) -server $CCServer ) -server $CCServer 
    $list_return += utility_log -message (output_direct -text "Compute - Server Uptime" -value (compute_win_uptime) -server $CCServer ) -server $CCServer


    # DNS Record Present
    switch ($CCServer) {
        $ccserver1 {
            $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $CCServer -IP $ccserver1ip)) -server $CCServer
        }
        $ccserver2 {
            $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $CCServer -IP $ccserver2ip)) -server $CCServer
        }
        $ccserver3 {
            $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $CCServer -IP $ccserver3ip)) -server $CCServer
        }
    }
     
    # Network Checks
    $list_return += utility_log -message (output_direct -text "Network - $ccserver1 Port 443" -value (network_win_ping -Server_ping $ccserver1 -Port 443)) -server $CCServer 
    $list_return += utility_log -message (output_direct -text "Network - $ccserver2 Port 443" -value (network_win_ping -Server_ping $ccserver2 -Port 443)) -server $CCServer
    $list_return += utility_log -message (output_direct -text "Network - $ccserver3 Port 443" -value (network_win_ping -Server_ping $ccserver3 -Port 443)) -server $CCServer
    $list_return += utility_log -message (output_direct -text "Network - $ccserver1 Port 80" -value (network_win_ping -Server_ping $ccserver1 -Port 80)) -server $CCServer 
    $list_return += utility_log -message (output_direct -text "Network - $ccserver2 Port 80" -value (network_win_ping -Server_ping $ccserver2 -Port 80)) -server $CCServer
    $list_return += utility_log -message (output_direct -text "Network - $ccserver3 Port 80" -value (network_win_ping -Server_ping $ccserver3 -Port 80)) -server $CCServer
    $list_return += utility_log -message (output_direct -text "Network -  Port 443" -value (network_win_ping -Server_ping "" -Port 443)) -server $CCServer

    

    # Windows Services
    $CCServices = @("cdfCaptureService", "Citrix Cloud Connector Metrics Service", "Citrix NetScaler Cloud Gateway", 
    "CitrixClxMtpService", "CitrixConfigSyncService", "CitrixHighAvailabilityService", "CitrixITSMAdapterProvider", 
    "CitrixWEMAuthSvc", "CitrixWemMsgSvc", "CitrixWorkspaceCloudADProvider", "CitrixWorkspaceCloudAgentDiscovery", 
    "CitrixWorkspaceCloudAgentLogger", "CitrixWorkspaceCloudAgentSystem", "CitrixWorkspaceCloudAgentWatchdog",
    "CitrixWorkspaceCloudCredentialProvider", "CitrixWorkspaceCloudWebRelayProvider", "RemoteHCLServer", "XaXdCloudProxy")

    foreach ($CCService in $CCServices) {
        $list_return += utility_log -message (output_direct -text "Service - $CCService" -value (service_win_Service -CxService $CCService)) -server $CCServer
    }


    # Registry
    $list_return += utility_log -message (output_direct -text "Registry - LHC NOT in Outage Mode" -value (service_win_registry -Path "HKLM:\Software\Citrix\Broker\Service\State\LHC" -Name "OutageModeEntered" -ExpectedValue 0 )) -server $CCServer
    $list_return += utility_log -message (output_direct -text "Registry - Agent Version" -value (service_win_registry -Path "HKLM:\Software\Citrix\CloudServices\Install\AgentSystem" -Name "ProductVersionBase" -ExpectedValue "6.76.0")) -server $CCServer
    $list_return += utility_log -message (output_direct -text "Registry - Upgrade NOT Pending" -value (service_win_registry -Path "HKLM:\Software\Citrix\CloudServices\AgentFoundation" -Name "ImmediateUpgrade" -ExpectedValue 0 )) -server $CCServer
    $list_return += utility_log -message (output_direct -text "Registry - NOT In Maintenance Mode" -value (service_win_registry -Path "HKLM:\Software\Citrix\CloudServices\AgentFoundation" -Name "InMaintenance" -ExpectedValue 0 )) -server $CCServer


    # Get Windows Events
    $list_return += event_win_events

    #utility_debug_counters -counters $counters
    #utility_debug_lists -lists $list_cc

    return $list_return
}



# PVS script blocks
$PVSScriptBlock = {
    # Step 1 -Declare functions passed in
    param($PVSServer, $PVSServers, $counters,
    [System.Collections.ArrayList]$list_pvs,
    $block_output_padding, $block_output_direct, 
    $block_utility_incrementValue, $block_utility_error_log, $block_utility_debug_counters, $block_utility_log, $block_utility_debug_lists,
    $block_compute_win_cpu, $block_compute_win_mem, $block_compute_win_disk_percent, $block_compute_win_uptime, 
    $block_network_win_dns, $block_network_win_ping,
    $block_service_win_Service, $block_service_win_registry,
    $block_event_win_events)

    # Step 2 - set functions ready to be used from the function blocks
    Set-Item -Path function:output_padding -Value $block_output_padding
    Set-Item -Path function:output_direct -Value $block_output_direct

    Set-Item -Path function:utility_incrementValue -Value $block_utility_incrementValue
    Set-Item -Path function:utility_error_log -Value $block_utility_error_log
    Set-Item -Path function:utility_debug_counters -Value $block_utility_debug_counters
    Set-Item -Path function:utility_log -Value $block_utility_log
    Set-Item -Path function:utility_debug_lists -Value $block_utility_debug_lists

    Set-Item -Path function:compute_win_cpu -Value $block_compute_win_cpu
    Set-Item -Path function:compute_win_mem -Value $block_compute_win_mem
    Set-Item -Path function:compute_win_disk_percent -Value $block_compute_win_disk_percent
    Set-Item -Path function:compute_win_uptime -Value $block_compute_win_uptime

    Set-Item -Path function:network_win_dns -Value $block_network_win_dns
    Set-Item -Path function:network_win_ping -Value $block_network_win_ping

    Set-Item -Path function:service_win_Service -Value $block_service_win_Service
    Set-Item -Path function:service_win_registry -Value $block_service_win_registry

    Set-Item -Path function:event_win_events -Value $block_event_win_events

    # Variables
    pvs_disk = "c:"
    pvsserver1 = "PVS1"
    pvsserver1ip = "10." 
    pvsserver2 = "PVS2"
    pvsserver2ip = "10."
    pvsserver3 = "PVS3"
    pvserver3ip = "10."
    licenseserver = ""
    sqlserver = ""

    # Step 2 - set functions ready to be used from the function blocks
    Set-Item -Path function:output_padding -Value $block_output_padding
    Set-Item -Path function:output_direct -Value $block_output_direct

    Set-Item -Path function:utility_incrementValue -Value $block_utility_incrementValue
    Set-Item -Path function:utility_error_log -Value $block_utility_error_log
    Set-Item -Path function:utility_debug_counters -Value $block_utility_debug_counters
    Set-Item -Path function:utility_log -Value $block_utility_log
    Set-Item -Path function:utility_debug_lists -Value $block_utility_debug_lists

    Set-Item -Path function:compute_win_cpu -Value $block_compute_win_cpu
    Set-Item -Path function:compute_win_mem -Value $block_compute_win_mem
    Set-Item -Path function:compute_win_disk_percent -Value $block_compute_win_disk_percent
    Set-Item -Path function:compute_win_uptime -Value $block_compute_win_uptime

    Set-Item -Path function:network_win_dns -Value $block_network_win_dns
    Set-Item -Path function:network_win_ping -Value $block_network_win_ping

    Set-Item -Path function:service_win_Service -Value $block_service_win_Service
    Set-Item -Path function:service_win_registry -Value $block_service_win_registry

    Set-Item -Path function:event_win_events -Value $block_event_win_events
    
    $list_return = [System.Collections.ArrayList]$()

    # Start of items to monitor
    # Compute
    $list_return += utility_log -message (output_direct -text "Compute - CPU Usage %" -value (compute_win_cpu) -server $PVSServer) -server $PVSServer 
    $list_return += utility_log -message (output_direct -text "Compute - Memory Usage %" -value (compute_win_mem) -server $PVSServer ) -server $PVSServer 
    $list_return += utility_log -message (output_direct -text "Compute - Disk C: Usage %" -value (compute_win_disk_percent($pvs_disk)) -server $PVSServer ) -server $PVSServer 
    $list_return += utility_log -message (output_direct -text "Compute - Server Uptime" -value (compute_win_uptime) -server $PVSServer ) -server $PVSServer


    # DNS Record Present
    switch ($PVSServer) {
        $pvsserver1 {
            $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $PVSServer -IP $pvsserver1ip)) -server $PVSServer
        }
        $pvsserver2 {
            $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $PVSServer -IP $pvsserver2ip)) -server $PVSServer
        }
        $pvsserver3 {
            $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $PVSServer -IP $pvsserver3ip)) -server $PVSServer
        }
    }
    
    # Network Checks
    $list_return += utility_log -message (output_direct -text "Network - $pvsserver1 Port 54321 (SOAP)" -value (network_win_ping -Server_ping $pvsserver1 -Port 54321)) -server $PVSServer 
    $list_return += utility_log -message (output_direct -text "Network - $pvsserver2 Port 54321 (SOAP)" -value (network_win_ping -Server_ping $pvsserver2 -Port 54321)) -server $PVSServer
    $list_return += utility_log -message (output_direct -text "Network - $pvsserver3 Port 54321 (SOAP)" -value (network_win_ping -Server_ping $pvsserver3 -Port 54321)) -server $PVSServer
    $list_return += utility_log -message (output_direct -text "Network - $pvsserver1 Port 445 (SMB)" -value (network_win_ping -Server_ping $pvsserver1 -Port 445)) -server $PVSServer 
    $list_return += utility_log -message (output_direct -text "Network - $pvsserver2 Port 445 (SMB)" -value (network_win_ping -Server_ping $pvsserver2 -Port 445)) -server $PVSServer
    $list_return += utility_log -message (output_direct -text "Network - $pvsserver3 Port 445 (SMB)" -value (network_win_ping -Server_ping $pvsserver3 -Port 445)) -server $PVSServer
    $list_return += utility_log -message (output_direct -text "Network - $licenseserver Port 27000 (License)" -value (network_win_ping -Server_ping $licenseserver -Port 27000)) -server $PVSServer
    $list_return += utility_log -message (output_direct -text "Network - $licenseserver Port 27000 (License)" -value (network_win_ping -Server_ping $licenseserver -Port 27000)) -server $PVSServer
    $list_return += utility_log -message (output_direct -text "Network - $licenseserver Port 7279 (License)" -value (network_win_ping -Server_ping $licenseserver -Port 7279)) -server $PVSServer
    $list_return += utility_log -message (output_direct -text "Network - $licenseserver Port 7279 (License)" -value (network_win_ping -Server_ping $licenseserver -Port 7279)) -server $PVSServer
    $list_return += utility_log -message (output_direct -text "Network - $sqlserver Port 1433 (SQL)" -value (network_win_ping -Server_ping $sqlserver  -Port 7279)) -server $PVSServer

    # Windows Services
    $pvsServices = @("CDFMonitor", "CDFSVC", "CitrixTelemetryService", "PVSAPI", "PVSTSB", "SOAPServer", "StreamService")

    foreach ($PVSService in $pvsServices) {
        $list_return += utility_log -message (output_direct -text "Service - $PVSService" -value (service_win_Service -CxService $PVSService)) -server $PVSService
    }

    # Get Windows Events
    $list_return += event_win_events

    return $list_return
}



# STF script blocks
$STFScriptBlock = {
    # Step 1 -Declare functions passed in
    param($STFServer, $STFServers, $counters,
    [System.Collections.ArrayList]$list_stf,
    $block_output_padding, $block_output_direct, 
    $block_utility_incrementValue, $block_utility_error_log, $block_utility_debug_counters, $block_utility_log, $block_utility_debug_lists,
    $block_compute_win_cpu, $block_compute_win_mem, $block_compute_win_disk_percent, $block_compute_win_uptime, 
    $block_network_win_dns, $block_network_win_ping,
    $block_service_win_Service, $block_service_win_registry,
    $block_event_win_events)

    # Step 2 - set functions ready to be used from the function blocks
    Set-Item -Path function:output_padding -Value $block_output_padding
    Set-Item -Path function:output_direct -Value $block_output_direct

    Set-Item -Path function:utility_incrementValue -Value $block_utility_incrementValue
    Set-Item -Path function:utility_error_log -Value $block_utility_error_log
    Set-Item -Path function:utility_debug_counters -Value $block_utility_debug_counters
    Set-Item -Path function:utility_log -Value $block_utility_log
    Set-Item -Path function:utility_debug_lists -Value $block_utility_debug_lists

    Set-Item -Path function:compute_win_cpu -Value $block_compute_win_cpu
    Set-Item -Path function:compute_win_mem -Value $block_compute_win_mem
    Set-Item -Path function:compute_win_disk_percent -Value $block_compute_win_disk_percent
    Set-Item -Path function:compute_win_uptime -Value $block_compute_win_uptime

    Set-Item -Path function:network_win_dns -Value $block_network_win_dns
    Set-Item -Path function:network_win_ping -Value $block_network_win_ping

    Set-Item -Path function:service_win_Service -Value $block_service_win_Service
    Set-Item -Path function:service_win_registry -Value $block_service_win_registry

    Set-Item -Path function:event_win_events -Value $block_event_win_events

    # Variables
    stf_disk = "c:"
    stfserver1 = "STF1"
    stfserver1ip = "10." 
    stfserver2 = "STF2"
    stfserver2ip = "10."
    ccserver1 = ""
    ccserver2 = ""
    ccserver3 = ""
    adcserver1 = ""
    adcserver2 = ""
    
    $list_return = [System.Collections.ArrayList]$()

    # Start of items to monitor
    # Compute
    $list_return += utility_log -message (output_direct -text "Compute - CPU Usage %" -value (compute_win_cpu) -server $STFServer) -server $STFServer 
    $list_return += utility_log -message (output_direct -text "Compute - Memory Usage %" -value (compute_win_mem) -server $STFServer ) -server $STFServer 
    $list_return += utility_log -message (output_direct -text "Compute - Disk C: Usage %" -value (compute_win_disk_percent($stf_disk)) -server $STFServer ) -server $STFServer 
    $list_return += utility_log -message (output_direct -text "Compute - Server Uptime" -value (compute_win_uptime) -server $STFServer ) -server $STFServer


    # DNS Record Present
    switch ($PVSServer) {
        $stfserver1 {
            $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $STFServer -IP $stfserver1ip)) -server $STFServer
        }
        $stfserver2 {
            $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $STFServer -IP $stfserver2ip)) -server $STFServer
        }
    }
    
    # Network Checks
    $list_return += utility_log -message (output_direct -text "Network - $stfserver1 Port 443" -value (network_win_ping -Server_ping $stfserver1 -Port 443)) -server $STFServer 
    $list_return += utility_log -message (output_direct -text "Network - $stfserver2 Port 443" -value (network_win_ping -Server_ping $stfserver2 -Port 443)) -server $STFServer

    $list_return += utility_log -message (output_direct -text "Network - $ccserver1 Port 443" -value (network_win_ping -Server_ping $ccserver1 -Port 443)) -server $STFServer 
    $list_return += utility_log -message (output_direct -text "Network - $ccserver2 Port 443" -value (network_win_ping -Server_ping $ccserver2 -Port 443)) -server $STFServer
    $list_return += utility_log -message (output_direct -text "Network - $ccserver3 Port 443" -value (network_win_ping -Server_ping $ccserver3 -Port 443)) -server $STFServer

    $list_return += utility_log -message (output_direct -text "Network - $adcserver1 Port 443" -value (network_win_ping -Server_ping $adcserver1 -Port 443)) -server $STFServer 
    $list_return += utility_log -message (output_direct -text "Network - $adcserver2 Port 443" -value (network_win_ping -Server_ping $adcserver2 -Port 443)) -server $STFServer


    # Windows Services
    $StfServices = @("CitrixConfigurationReplication", "CitrixCredentialWallet", "CitrixDefaultDomainService", "Citrix Peer Resolution Service", "CitrixServiceMonitor", 
    "CitrixSubscriptionsStore", "CitrixTelemetryService")

    foreach ($StfService in $StfServices) {
        $list_return += utility_log -message (output_direct -text "Service - $StfService" -value (service_win_Service -CxService $StfService)) -server $STFServer
    }

    # Get Windows Events
    $list_return += event_win_events
    
    return $list_return
}



# LIC script blocks
$LICScriptBlock = {
    # Step 1 -Declare functions passed in
    param($LICServer, counters,
    [System.Collections.ArrayList]$list_stf,
    $block_output_padding, $block_output_direct, 
    $block_utility_incrementValue, $block_utility_error_log, $block_utility_debug_counters, $block_utility_log, $block_utility_debug_lists,
    $block_compute_win_cpu, $block_compute_win_mem, $block_compute_win_disk_percent, $block_compute_win_uptime, 
    $block_network_win_dns, $block_network_win_ping,
    $block_service_win_Service, $block_service_win_registry,
    $block_event_win_events)

    # Step 2 - set functions ready to be used from the function blocks
    Set-Item -Path function:output_padding -Value $block_output_padding
    Set-Item -Path function:output_direct -Value $block_output_direct

    Set-Item -Path function:utility_incrementValue -Value $block_utility_incrementValue
    Set-Item -Path function:utility_error_log -Value $block_utility_error_log
    Set-Item -Path function:utility_debug_counters -Value $block_utility_debug_counters
    Set-Item -Path function:utility_log -Value $block_utility_log
    Set-Item -Path function:utility_debug_lists -Value $block_utility_debug_lists

    Set-Item -Path function:compute_win_cpu -Value $block_compute_win_cpu
    Set-Item -Path function:compute_win_mem -Value $block_compute_win_mem
    Set-Item -Path function:compute_win_disk_percent -Value $block_compute_win_disk_percent
    Set-Item -Path function:compute_win_uptime -Value $block_compute_win_uptime

    Set-Item -Path function:network_win_dns -Value $block_network_win_dns
    Set-Item -Path function:network_win_ping -Value $block_network_win_ping

    Set-Item -Path function:service_win_Service -Value $block_service_win_Service
    Set-Item -Path function:service_win_registry -Value $block_service_win_registry

    Set-Item -Path function:event_win_events -Value $block_event_win_events

    # Variables
    lic_disk = "c:"
    licserver1 = "STF1"
    licenseserverip = ""

    
    $list_return = [System.Collections.ArrayList]$()

    # Start of items to monitor
    # Compute
    $list_return += utility_log -message (output_direct -text "Compute - CPU Usage %" -value (compute_win_cpu) -server $LICServer) -server $LICServer 
    $list_return += utility_log -message (output_direct -text "Compute - Memory Usage %" -value (compute_win_mem) -server $LICServer ) -server $LICServer 
    $list_return += utility_log -message (output_direct -text "Compute - Disk C: Usage %" -value (compute_win_disk_percent($lic_disk)) -server $LICServer ) -server $LICServer 
    $list_return += utility_log -message (output_direct -text "Compute - Server Uptime" -value (compute_win_uptime) -server $LICServer ) -server $LICServer
    
    # DNS Record Present
    $list_return += utility_log -message (output_direct -text "Network - DNS Record" -value (network_win_dns -Server_ping $LICServer -IP $licenseserverip)) -server $LICServer

    # Network Checks
    $list_return += utility_log -message (output_direct -text "Network - $LICServer Port 27000" -value (network_win_ping -Server_ping $LICServer -Port 27000)) -server $LICServer 
    $list_return += utility_log -message (output_direct -text "Network - $LICServer Port 7279" -value (network_win_ping -Server_ping $LICServer -Port 7279)) -server $LICServer
    $list_return += utility_log -message (output_direct -text "Network - $LICServer Port 8083" -value (network_win_ping -Server_ping $LICServer -Port 8083)) -server $LICServer
    $list_return += utility_log -message (output_direct -text "Network - cis.citrix.com Port 443" -value (network_win_ping -Server_ping "cis.citrix.com" -Port 443)) -server $LICServer
    $list_return += utility_log -message (output_direct -text "Network - trust.citrixnetworkapi.net Port 443" -value (network_win_ping -Server_ping "trust.citrixnetworkapi.net" -Port 443)) -server $LICServer



    # Services
    $licServices = @("Citrix Licensing", "CtxLSPortSvc", "Citrix_GTLicensingProv", "CitrixWebServicesforLicensing")
    foreach ($licService in $licServices) {
        $list_return += utility_log -message (output_direct -text "Service - $licService" -value (service_win_Service -CxService $licService)) -server $licService
    }

    # Get Windows Events
    $list_return += event_win_events

    return $list_return
}





### Invoke Commands

# Cloud Connectors
ForEach ($CCServer in $CCServers) {
    $list_cc += "`n-- " + $CCServer + ' - ' + $date + " --`n"

    $list_cc += Invoke-Command -ComputerName $CCServer -ScriptBlock $CCScriptBlock -ArgumentList $CCServer, $CCServers, $counters, $list_cc,
    $block_output_padding, $block_output_direct, 
    $block_utility_incrementValue, $block_utility_error_log, $block_utility_debug_counters, $block_utility_log, $block_utility_debug_lists, 
    $block_compute_win_cpu, $block_compute_win_mem, $block_compute_win_disk_percent, $block_compute_win_uptime, 
    $block_network_win_dns, $block_network_win_ping,
    $block_service_win_Service, $block_service_win_registry,
    $block_event_win_events
}

# PVS Servers
ForEach ($PVSServer in $PVSServers) {
    $list_pvs += "`n-- " + $PVSServer + ' - ' + $date + " --`n"

    $list_pvs += Invoke-Command -ComputerName $PVSServer -ScriptBlock $PVSScriptBlock -ArgumentList $PVSServer, $PVSServers, $counters, $list_pvs,
    $block_output_padding, $block_output_direct, 
    $block_utility_incrementValue, $block_utility_error_log, $block_utility_debug_counters, $block_utility_log, $block_utility_debug_lists, 
    $block_compute_win_cpu, $block_compute_win_mem, $block_compute_win_disk_percent, $block_compute_win_uptime, 
    $block_network_win_dns, $block_network_win_ping,
    $block_service_win_Service, $block_service_win_registry,
    $block_event_win_events
}

# StoreFront Servers
ForEach ($STFServer in $STFServers) {
    $list_pvs += "`n-- " + $STFServer + ' - ' + $date + " --`n"

    $list_pvs += Invoke-Command -ComputerName $STFServer -ScriptBlock $STFScriptBlock -ArgumentList $STFServer, $STFServers, $counters, $list_stf,
    $block_output_padding, $block_output_direct, 
    $block_utility_incrementValue, $block_utility_error_log, $block_utility_debug_counters, $block_utility_log, $block_utility_debug_lists, 
    $block_compute_win_cpu, $block_compute_win_mem, $block_compute_win_disk_percent, $block_compute_win_uptime, 
    $block_network_win_dns, $block_network_win_ping,
    $block_service_win_Service, $block_service_win_registry,
    $block_event_win_events
}

# License Servers
$list_lic += "`n-- " + $STFServer + ' - ' + $date + " --`n"
$list_lic += Invoke-Command -ComputerName $LICServer -ScriptBlock $LICScriptBlock -ArgumentList $LICServer, $counters, $list_lic,
$block_output_padding, $block_output_direct, 
$block_utility_incrementValue, $block_utility_error_log, $block_utility_debug_counters, $block_utility_log, $block_utility_debug_lists, 
$block_compute_win_cpu, $block_compute_win_mem, $block_compute_win_disk_percent, $block_compute_win_uptime, 
$block_network_win_dns, $block_network_win_ping,
$block_service_win_Service, $block_service_win_registry,
$block_event_win_events

# DaaS
$list_daas += Get-DaaSInfo 



# OUTPUT ALL DEBUG
$list_cc.ForEach( {
    write-host $_ 
})

$list_pvs.ForEach( {
    write-host $_ 
})

$list_stf.ForEach( {
    write-host $_ 
})

$list_lic.ForEach( {
    write-host $_ 
})

$list_daas.ForEach( {
    write-host $_ 
})




########################
# FILE SYSTEM OPERATIONS
########################

# Archive existing files
function moveAndRenameFile($file) {
    $date = Get-Date -Format "yyyy-MM-dd"

    switch ($file) {
        'cc' {
            $newName = "cc_$date.txt"
            if (Test-Path 'C:\data\Health Check\cc_latest.txt') {
                Get-Content -Path "C:\data\Health Check\cc_latest.txt" | Add-Content -Path "C:\data\Health Check\Archive\$newName"
                Remove-Item "C:\data\Health Check\cc_latest.txt"
            }
        }

        'pvs' {
            $newName = "pvs_$date.txt"
            if (Test-Path 'C:\data\Health Check\pvs_latest.txt') {
                Get-Content -Path "C:\data\Health Check\pvs_latest.txt" | Add-Content -Path "C:\data\Health Check\Archive\$newName"
                Remove-Item "C:\data\Health Check\pvs_latest.txt"
            }            
        }

        'stf' {
            $newName = "stf_$date.txt"
            if (Test-Path 'C:\data\Health Check\stf_latest.txt') {
                Get-Content -Path "C:\data\Health Check\stf_latest.txt" | Add-Content -Path "C:\data\Health Check\Archive\$newName"
                Remove-Item "C:\data\Health Check\stf_latest.txt"
            }            
        }

        'lic' {
            $newName = "lic_$date.txt"
            if (Test-Path 'C:\data\Health Check\lic_latest.txt') {
                Get-Content -Path "C:\data\Health Check\lic_latest.txt" | Add-Content -Path "C:\data\Health Check\Archive\$newName"
                Remove-Item "C:\data\Health Check\lic_latest.txt"
            }            
        }

        'ns' {
            $newName = "netscaler_$date.txt"
            if (Test-Path 'C:\data\Health Check\netscaler_latest.txt') {
                Get-Content -Path "C:\data\Health Check\netscaler_latest.txt" | Add-Content -Path "C:\data\Health Check\Archive\$newName"
                Remove-Item "C:\data\Health Check\netscaler_latest.txt"
            }            
        }

        'daas' {
            $newName = "daas_$date.txt"
            if (Test-Path 'C:\data\Health Check\daas_latest.txt') {
                Get-Content -Path "C:\data\Health Check\daas_latest.txt" | Add-Content -Path "C:\data\Health Check\Archive\$newName"
                Remove-Item "C:\data\Health Check\daas_latest.txt"
            }            
        }

        default {
            write-host 'no action applied'
        }
    }
}

# Create CC File Summary
moveAndRenameFile('cc')
foreach ($item in $list_cc) {
    Add-Content -Path "C:\data\Health Check\cc_latest.txt" -Value $item
}

# Create PVS File Summary
moveAndRenameFile('pvs')
foreach ($item in $list_pvs) {
    Add-Content -Path "C:\data\Health Check\pvs_latest.txt" -Value $item
}

# Create STF File Summary
moveAndRenameFile('stf')
foreach ($item in $list_stf) {
    Add-Content -Path "C:\data\Health Check\stf_latest.txt" -Value $item
}

# Create LIC File Summary
moveAndRenameFile('lic')
foreach ($item in $list_lic) {
    Add-Content -Path "C:\data\Health Check\lic_latest.txt" -Value $item
}

# Create NetScaler File Summary
moveAndRenameFile('ns')
foreach ($item in $list_netscaler) {
    Add-Content -Path "C:\data\Health Check\netscaler_latest.txt" -Value $item
}

# Create DaaS Summary
moveAndRenameFile('daas')
foreach ($item in $list_daas) {
    Add-Content -Path "C:\data\Health Check\daas_latest.txt" -Value $item
}



#######
# HTML
#######

# Create the overall status table
function ConvertTo-ProductStatusHTML {
    param(
        [Parameter(Mandatory=$true)]
        [psobject[]] $ProductList
    )


    # Loop through each product and generate the HTML table rows
    $htmlRows = @()
    foreach ($product in $ProductList) {
        # $product.StatusNetwork
        $statusClassNetwork = "statusRed" # Default to red
        if ($product.StatusNetwork -eq "Yellow") {
            $statusClassNetwork = "statusYellow"
        }
        elseif ($product.StatusNetwork -eq "Green") {
            $statusClassNetwork = "statusGreen"
        }


        # $product.StatusCompute
        $statusClassCompute = "statusRed" # Default to red
        if ($product.StatusCompute -eq "Yellow") {
            $statusClassCompute = "statusYellow"
        }
        elseif ($product.StatusCompute -eq "Green") {
            $statusClassCompute = "statusGreen"
        }


        # $product.StatusService
        $statusClassService = "statusRed" # Default to red
        if ($product.StatusService -eq "Yellow") {
            $statusClassService = "statusYellow"
        }
        elseif ($product.StatusService -eq "Green") {
            $statusClassService = "statusGreen"
        }


        # $product.StatusEvent
        $statusClassEvent = "statusRed" # Default to red
        if ($product.StatusEvent -eq "Yellow") {
            $statusClassEvent = "statusYellow"
        }
        elseif ($product.StatusEvent -eq "Green") {
            $statusClassEvent = "statusGreen"
        }


        $htmlRows += "<tr><td>$($product.Name)</td>
        <td class=`"$statusClassNetwork`"></td>
        <td class=`"$statusClassCompute`"></td>
        <td class=`"$statusClassService`"></td>
        <td class=`"$statusClassEvent`"></td>
        </tr>"
    }


$htmlTable = @"
<table class='table'>
    <tr>
        <th class='th_70'>Product Name</th>
        <th class='th_7_5'>Network Status</th>
        <th class='th_7_5'>Compute Status</th>
        <th class='th_7_5'>Service Status</th>
        <th class='th_7_5'>Event Status</th>
    </tr>
    $($htmlRows -join "`r`n")
</table>
"@


    return $htmlTable
}



$products = @(
    @{ Name = "Cloud Connector"; StatusNetwork = greenOrYellow -product "cc" -counter "network";  StatusCompute = greenOrYellow -product "cc" -counter "compute";  StatusService = greenOrYellow -product "cc" -counter "service";  StatusEvent = greenOrYellow -product "cc" -counter "event"; },
    @{ Name = "DaaS"; StatusNetwork = "Green";  StatusCompute = "Green";  StatusService = "Green";  StatusEvent = "Green"; },
    @{ Name = "License Server"; StatusNetwork = greenOrYellow -product "license" -counter "network";  StatusCompute = greenOrYellow -product "license" -counter "compute";  StatusService = greenOrYellow -product "license" -counter "service";  StatusEvent = greenOrYellow -product "license" -counter "event"; },
    @{ Name = "NetScaler"; StatusNetwork = greenOrYellow -product "netscaler" -counter "network";  StatusCompute = greenOrYellow -product "netscaler" -counter "compute";  StatusService = greenOrYellow -product "netscaler" -counter "service";  StatusEvent = greenOrYellow -product "netscaler" -counter "event"; },
    @{ Name = "Provisioning Server"; StatusNetwork = greenOrYellow -product "pvs" -counter "network";  StatusCompute = greenOrYellow -product "pvs" -counter "compute";  StatusService = greenOrYellow -product "pvs" -counter "service";  StatusEvent = greenOrYellow -product "pvs" -counter "event"; },
    @{ Name = "StoreFront"; StatusNetwork = greenOrYellow -product "storefront" -counter "network";  StatusCompute = greenOrYellow -product "storefront" -counter "compute";  StatusService = greenOrYellow -product "storefront" -counter "service";  StatusEvent = greenOrYellow -product "storefront" -counter "event"; },
    @{ Name = "VDA"; StatusNetwork = "Green";  StatusCompute = "Green";  StatusService = "Green";  StatusEvent = "Green"; }
) | ForEach-Object { New-Object PSObject -Property $_ }


# Define a CSS for the status colors
$html = @"
<head>
<style>
    .statusRed { background-color: red; }
    .statusYellow { background-color: yellow; }
    .statusGreen { background-color: green; }

    .table { width: 800px; }
    .th_70 { width: 70%; }
    .th_7_5 { width: 7.5%; }
</style>
</head>
<body>
"@

$html += ConvertTo-ProductStatusHTML -ProductList $products

$li_list = foreach ($err in $list_error) {
    "<li>$err</li>"
}

$html += "
<p>ENVIRONMENT: PROD</p>
<p>EXECUTED ON: $date</p>
<br>

<h3>Important Events</h3>
<ul>
    $($li_list -join "`r`n")
<ul>
"

$html | out-file -FilePath ""



########
# EMAIL
########

# Send Email
$NoServersMessage = @{
    To = ""
    From = ""
    Subject = ""
    Body = $html
    Smtpserver = ""
    Attachments = @(
        "C:\data\Health Check\cc_latest.txt",
        "C:\data\Health Check\lic_latest.txt",
        "C:\data\Health Check\netscaler_latest.txt",
        "C:\data\Health Check\pvs_latest.txt",
        "C:\data\Health Check\stf_latest.txt",
        "C:\data\Health Check\daas_latest.txt"
        )
}

#Send-MailMessage @NoServersMessage -BodyAsHtml -ErrorAction Stop

