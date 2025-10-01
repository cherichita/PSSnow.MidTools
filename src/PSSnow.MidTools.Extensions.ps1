function Get-SNOWMidPodmanContainer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerName,
        [string]$ConnectionName
    )
    $PodmanCommand = "podman"
    $PodmanParams = @()
    if ( $ConnectionName) {
        $PodmanParams += "--connection"
        $PodmanParams += $ConnectionName
    }
    $PsParams = @(
        "ps",
        "--filter", "name=$ContainerName",
        "--format", "json"
    )
    $ContainerJson = & $PodmanCommand $PodmanParams $PsParams | Out-String | ConvertFrom-Json
    if ($ContainerJson.count -eq 0) {
        Write-Host "No Podman containers found with name '$ContainerName' on connection '$ConnectionName'"
        return @()
    }
    else {
        $ContainerInfo = & $PodmanCommand $PodmanParams inspect $ContainerJson[0].Id --format json | Out-String | ConvertFrom-Json
        return $ContainerInfo
    }
}

function ConvertFrom-CliXmlCustom {
    param([string]$Text)
    
    # Find all CLIXML tags
    $cliXmlPattern = '#< CLIXML'
    $cliXmlMatches = [regex]::Matches($Text, $cliXmlPattern)
    
    if ($cliXmlMatches.Count -eq 0) {
        Write-Warning "No CLIXML tags found in the input."
        return $null
    }
    
    # Get the position of the last CLIXML tag
    $lastMatch = $cliXmlMatches[$cliXmlMatches.Count - 1]
    $lastCliXmlPosition = $lastMatch.Index
    
    # Extract everything after the last CLIXML tag
    $xmlContent = $Text.Substring($lastCliXmlPosition)
    
    # Clean up the content - remove the CLIXML marker line
    $xmlLines = $xmlContent -split "`n"
    $xmlWithoutMarker = ($xmlLines | Select-Object -Skip 1) -join "`n"
    
    # Remove any trailing whitespace/newlines
    $xmlWithoutMarker = $xmlWithoutMarker.Trim()
    $xmlWithoutMarkerRoots = $xmlWithoutMarker -replace '/Objs>', '/Objs>XMLSPLIT_2234_NOW'
    $xmlStreams = $xmlWithoutMarkerRoots -split 'XMLSPLIT_2234_NOW'
    if ( $xmlStreams.Count -eq 0) {
        Write-Warning "No XML content found after the last CLIXML tag. `"$($Text.Substring(0, 100))`""
        return $null
    }
    $Streams = @{}
    $CodedStreams = @{
        Errors = @()
    }
    $idx = 0
    foreach ( $xmlStream in $xmlStreams) {
        $Streams[$idx] = $null
        
        if ([string]::IsNullOrWhiteSpace($xmlStream)) {
            continue
        }
        try {
            $StreamXml = [xml]$xmlStream
            $Streams[$idx] = ($xmlStream | ConvertFrom-CliXml)
            $StreamType = $StreamXml.Objs.ChildNodes[0].S ?? 'Output'
            $CodedStreams[$StreamType] = $Streams[$idx]
        }
        catch {
            $CodedStreams.Errors += $xmlStream
            Write-Host "Raw XML content (first 500 chars):" -ForegroundColor Yellow
        }
        $idx++
    }
    return $CodedStreams
}

function Invoke-SNOWMidRemoteCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MidServerName,
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(ParameterSetName = 'Azure')]
        [switch]$UseAzureExec,
        [switch]$UsePodmanExec
    )
    
    if ($UseAzureExec.IsPresent) {
        $ContainerRecord = Get-SNOWMidAzContainerRecord -ContainerName $MidServerName
        if (-not $ContainerRecord) {
            Write-Error "Container group '$MidServerName' not found."
            return
        }
        $AzExecResults = (az container exec --exec-command $Command --name $MidServerName --resource-group $ContainerRecord.resourceGroup --subscription $ContainerRecord.subscriptionId) -join "`n"
        $Result = @{
            Original = $AzExecResults
            StdOut   = $AzExecResults
        }
    }
    elseif ($UsePodmanExec.IsPresent) {
        $PodmanContainer = Search-SNOWMidPodmanContainer -ContainerName $MidServerName
        if ( -not $PodmanContainer.Container) {
            Write-Error "Podman container '$MidServerName' not found."
            return
        }
        $PodmanCommand = "podman"
        $PodmanParams = @()
        if ( $PodmanContainer.Connection) {
            $PodmanParams += "--connection"
            $PodmanParams += $PodmanContainer.Connection
        }
        
        $TempFile = [System.IO.Path]::GetTempFileName()
        $TempErrorFile = [System.IO.Path]::GetTempFileName()
        # Split the command for podman exec
        $CommandParts = $Command -split ' ', 0, 'SimpleMatch'
        Write-Host "Executing command in Podman container $CommandParts"
        $PodmanParams += @(
            '--out', $TempFile,
            "exec",
            $PodmanContainer.Container.Id
        ) + $CommandParts
        $StringCommand = "$PodmanCommand " + ($PodmanParams -join ' ')
        $Global:PodmanExecResults = (Invoke-Expression $StringCommand 2> $TempErrorFile) 3>&1

        $StdOutContent = Get-Content -Path $TempFile -Raw
        $StdErrContent = Get-Content -Path $TempErrorFile -Raw
        
        $Result = @{
            Original = $StdOutContent
            StdOut   = $StdOutContent
            StdErr   = $StdErrContent
            Warning  = $WarningOut
        }
        
        # Clean up temp files
        Remove-Item -Path $TempFile -ErrorAction SilentlyContinue
        Remove-Item -Path $TempErrorFile -ErrorAction SilentlyContinue
    }
    else {
        $EccResult = Invoke-SNOWMidCommand -Command $Command -MidServerName $MidServerName
        $Result = @{
            StdOut   = $EccResult.StdOut
            StdErr   = $EccResult.StdErr
            Original = $EccResult
        }
    }
    return $Result
}

function Invoke-SNOWMidPowerShellCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MidServerName,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command,
        [switch]$UseAzureExec,
        [switch]$UsePodmanExec,
        [hashtable]$Variables = @{
            RunStart = (Get-Date).ToString("o")
        }
    )
    
    # Encode the PowerShell command
    $BaseCommand = $Command.ToString()
    foreach($v in $Variables.GetEnumerator()){
        $BaseCommand = "`$$($v.Key) = `"$($v.Value)`"`n" + $BaseCommand
    }
    $EncodedContent = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($BaseCommand))
    $MidCommand = "/usr/bin/pwsh -NonInteractive -OutputFormat XML -EncodedCommand {0}" -f $EncodedContent
    Write-PSFMessage -Level Important "Executing PowerShell command on Mid Server '$MidServerName'"
    # Use the base function to execute the command
    $RemoteResult = Invoke-SNOWMidRemoteCommand -MidServerName $MidServerName -Command $MidCommand -UseAzureExec:$UseAzureExec -UsePodmanExec:$UsePodmanExec
    
    if (-not $RemoteResult) {
        return $null
    }
    
    # Process the XML output for PowerShell commands
    if ($UseAzureExec.IsPresent) {
        $Result = @{
            Original = $RemoteResult
        }
        $Result += (ConvertFrom-CliXmlCustom -Text $RemoteResult.Original)
    }
    elseif ($UsePodmanExec.IsPresent) {
        $Streams = ConvertFrom-CliXmlCustom -Text $RemoteResult.Original
        $Result = @{
            Original = $RemoteResult
        } + $Streams
    }
    else {
        $OutStreams = (ConvertFrom-CliXmlCustom -Text $RemoteResult.StdOut)
        $ErrorStreams = (ConvertFrom-CliXmlCustom -Text $RemoteResult.StdErr)
        $Result = @{
            Original     = $RemoteResult.Original
            Output       = $OutStreams.Output
            Error        = $ErrorStreams.Error
            Warning      = $ErrorStreams.Warning
            ErrorStreams = $ErrorStreams
            OutStreams   = $OutStreams
        }
    }
    return $Result
}


function Search-SNOWMidPodmanContainer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )
    $Out = [ordered]@{}
    $SystemConnections = podman system connection list --format json | ConvertFrom-Json | Sort-Object -Property 'Default' -Descending
    if ($SystemConnections.count -gt 0) {
        foreach ( $conn in $SystemConnections) {
            Write-PSFMessage -Level Verbose "Searching for container '$ContainerName' on connection: $($conn.Name)"
            $Containers = Get-SNOWMidPodmanContainer -ContainerName $ContainerName -ConnectionName $conn.Name
            if ( $Containers.count -gt 0) {
                $Out.Container = $Containers[0]
                $Out.Connection = $conn.Name
                break
            }
        }
    }
    else {
        $Out.Container = Get-SNOWMidPodmanContainer -ContainerName $ContainerName
    }
    if($Out.Container){
        if(-not ($Out.Container.Config.Env -contains "SN_MID_ENVIRONMENT_NAME=$($Script:SN_MID_ENVIRONMENT_NAME)")){
            Write-PSFMessage -Level Warning "Container '$ContainerName' found, but SN_MID_ENVIRONMENT tag does not match '$($Script:SN_MID_ENVIRONMENT_NAME)'"
        }
    }
    return $Out
}