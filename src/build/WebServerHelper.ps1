[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingWriteHost', '')]
param()

<#
.SYNOPSIS
    Web server helper functions for PODE and NGROK functionality
.DESCRIPTION
    This module provides functions for managing PODE web servers and NGROK tunnels
    for testing and development purposes.
#>

function Get-NgrokTunnel {
    <#
    .SYNOPSIS
        Gets information about running NGROK tunnels
    .PARAMETER LocalAddress
        The local address to look for tunnels for
    .PARAMETER PodePort
        The port number for the PODE server
    #>
    param(
        [string]$LocalAddress,
        [int]$PodePort = 8099
    )
    
    if (-not $LocalAddress) {
        $LocalAddress = "http://localhost:${PodePort}"
    }
    $NgrokProcess = Get-Process -Name ngrok -ErrorAction SilentlyContinue
    if ($NgrokProcess) {
        Write-Host "Ngrok is already running on $($NgrokProcess.Id)"
    
        $endTime = (Get-Date).AddSeconds(20)
        do {
            try {
                $Tunnels = Invoke-RestMethod 'http://localhost:4040/api/tunnels'
                break
            }
            catch {
                Start-Sleep -Seconds 0.5
            }
        } while ((Get-Date) -lt $endTime)
        
        $Tunnels.tunnels | ForEach-Object {
            Write-Verbose "$($_ | ConvertTo-Json -Depth 5)"
            if ($_.config.addr -eq $LocalAddress) {
                Write-Host "Ngrok tunnel $($PSItem.name) is running on $($_.public_url)"
                return $_
            }
        }
    }
    else {
        Write-Host 'Ngrok is not running'
    }
    
    return $null
}

function Initialize-NgrokEnvironment {
    <#
    .SYNOPSIS
        Initializes the NGROK environment and checks for existing tunnels
    .PARAMETER PodePort
        The port number for the PODE server
    .OUTPUTS
        Hashtable containing NgrokPath, NgrokTunnel, and NgrokRunning status
    #>
    param(
        [int]$PodePort = 8099
    )
    
    $result = @{
        NgrokRunning = $false
        NgrokPath    = $null
        NgrokTunnel  = $null
    }
    
    $NgrokCommand = Get-Command ngrok -ErrorAction SilentlyContinue
    if (-not $NgrokCommand) {
        Write-Error 'Ngrok not found. Go To https://dashboard.ngrok.com/get-started/setup to download and install it.'
        return $result
    }
    
    Write-Host "Ngrok found at $($NgrokCommand.Source)"
    $result.NgrokPath = $NgrokCommand.Source
    
    $result.NgrokTunnel = Get-NgrokTunnel -PodePort $PodePort
    if ($result.NgrokTunnel) {
        $result.NgrokRunning = $true
    }
    
    return $result
}

function Start-NgrokTunnel {
    <#
    .SYNOPSIS
        Starts an NGROK tunnel if not already running
    .PARAMETER NgrokPath
        Path to the NGROK executable
    .PARAMETER PodePort
        The port number for the PODE server
    .PARAMETER NgrokRunning
        Whether NGROK is already running
    .OUTPUTS
        Hashtable containing updated NgrokTunnel and NgrokRunning status
    #>
    param(
        [string]$NgrokPath = (Get-Command ngrok -ErrorAction Continue).Source,
        [int]$PodePort = 8099,
        [bool]$NgrokRunning = (Get-Process -Name ngrok -ErrorAction SilentlyContinue).Count -gt 0
    )
    
    $result = @{
        NgrokTunnel  = $null
        NgrokRunning = $NgrokRunning
    }
    
    if (-not $NgrokRunning) {
        $NgrokParams = @(
            'http',
            $PodePort
        )
        Write-Host "Running ngrok server... with $($NgrokParams -join ' ')"
        $Job = Start-Job -Name 'NgrokServer' -ScriptBlock {
            param($NgrokPath, $NgrokParams)
            $Process = Start-Process -NoNewWindow -FilePath $NgrokPath -ArgumentList $NgrokParams 
            $Process
        } -ArgumentList $NgrokPath, $NgrokParams
        $Job
    }
    # Wait for NGROK to start
    $endTime = (Get-Date).AddSeconds(5)
    do {
        $NgrokProcess = Get-Process -Name ngrok -ErrorAction SilentlyContinue
        if ($NgrokProcess) { break }
        Start-Sleep -Seconds 0.5
    } while ((Get-Date) -lt $endTime)
    $result.NgrokTunnel = Get-NgrokTunnel -PodePort $PodePort
    if ($result.NgrokTunnel) {
        $result.NgrokRunning = $true
    }
    
    return $result
}

function Stop-NgrokTunnel {
    <#
    .SYNOPSIS
        Stops the NGROK tunnel
    .PARAMETER NgrokRunning
        Whether NGROK is currently running
    #>
    param(
        [bool]$NgrokRunning = (Get-Process -Name ngrok -ErrorAction SilentlyContinue).Count -gt 0
    )
    
    if ($NgrokRunning) {
        Stop-Process -Name 'ngrok' -Force
        Write-Host 'Ngrok tunnel stopped'
    }
    else {
        Write-Host 'Ngrok server is not running'
    }
}

function Get-PodeServerStatus {
    <#
    .SYNOPSIS
        Checks the status of the PODE server
    .PARAMETER PodePort
        The port number for the PODE server
    .OUTPUTS
        Hashtable containing PodeJob and running status
    #>
    param(
        [int]$PodePort = 8099
    )
    
    $result = @{
        PodeJob   = $null
        IsRunning = $false
    }
    
    $PodeJobs = Get-Job -Name 'PodeServer' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    if ($PodeJobs) {
        $result.PodeJob = $PodeJobs[0]
        $result.IsRunning = $true
        Write-Host "Pode server is already running on port ${PodePort}"
        $result.status = Invoke-RestMethod -Uri "http://localhost:${PodePort}/status" -ErrorAction SilentlyContinue
    }
    else {
        Write-Host 'Pode server is not running'
    }
    
    return $result
}

function Start-PodeServer {
    <#
    .SYNOPSIS
        Starts a PODE server with predefined routes
    .PARAMETER ScriptTemplatePaths
        Hashtable of template paths for static routes
    .PARAMETER PodePort
        The port number for the PODE server
    .PARAMETER PodeJob
        Existing PODE job if any
    .OUTPUTS
        The started job object
    #>
    param(
        [hashtable]$ScriptTemplatePaths,
        [int]$PodePort = 8099,
        [System.Management.Automation.Job]$PodeJob = (Get-PodeServerStatus -PodePort $PodePort).PodeJob
    )
    if (-not (Get-Module -Name 'Pode' -ErrorAction SilentlyContinue -ListAvailable)) {
        Install-Module -Name 'Pode' -Scope CurrentUser -Force
    }
    if (-not $ScriptTemplatePaths) {
        Write-Host "No ScriptTemplatePaths provided, using defaults"
        $ScriptTemplatePaths = @{
            'midtools'  = (Resolve-Path "$PSScriptRoot/.." -ErrorAction SilentlyContinue).Path
            'templates' = (Resolve-Path "$PSScriptRoot/../arm_out" -ErrorAction SilentlyContinue).Path
        }
    }
    if (-not $PodeJob) {
        Write-Host "Script Template Paths: $($ScriptTemplatePaths | ConvertTo-Json -Depth 3)"
        $Job = Start-Job -Name 'PodeServer' -ScriptBlock {
            param($ScriptTemplatePaths, $PodePort)
            Start-PodeServer {
                Set-PodeState -Name 'StartTime' -Value (Get-Date).ToString("o")
                Set-PodeState -Name 'ScriptTemplatePaths' -Value $ScriptTemplatePaths
                Add-PodeMiddleware -Name 'AccessControl' -ScriptBlock {
                    Add-PodeHeader -Name 'Access-Control-Allow-Origin' -Value '*'
                    return $true
                }
                New-PodeLoggingMethod -Terminal | Enable-PodeRequestLogging
                Add-PodeEndpoint -Address 'localhost' -Port $PodePort -Protocol Http
                Add-PodeRoute -Method Post -Path '/test_hook' -ScriptBlock {
                    # if using the above parser, .Data here will just be a plain string
                    $Payload = @{
                        Body        = $WebEvent.Request.Body
                        Headers     = $WebEvent.Request.Headers
                        QueryString = $WebEvent.Request.QueryString
                        Form        = $WebEvent.Request.Form
                    }
                    Write-PodeJsonResponse -Value $Payload
                }
                Add-PodeRoute -Method Get -Path '/ping' -ScriptBlock {
                    Write-PodeJsonResponse -Value @{ 'value' = 'pong'; }
                }
                Add-PodeRoute -Method Get -Path '/status' -ScriptBlock {
                    $Status = @{
                        Time                = (Get-Date).ToString("o")
                        ScriptTemplatePaths = Get-PodeState -Name 'ScriptTemplatePaths'
                        StartTime           = Get-PodeState -Name 'StartTime'
                    }
                    Write-PodeJsonResponse -Value $Status
                }
                foreach ($key in $ScriptTemplatePaths.Keys) {
                    Add-PodeStaticRoute -Path "/${key}" -Source $ScriptTemplatePaths[$key] -FileBrowser
                }
            }
        } -ArgumentList $ScriptTemplatePaths, $PodePort
        
        Write-Host "Started PODE server on port ${PodePort}"
        $endTime = (Get-Date).AddSeconds(15)
        do {
            $PodeStatus = Invoke-RestMethod -Uri "http://localhost:${PodePort}/status" -ErrorAction SilentlyContinue -SkipHttpErrorCheck
            if ($PodeStatus) { break }
            Write-Progress -Activity "Waiting for PODE server to start..." -Status "Checking..." -SecondsRemaining ((New-TimeSpan -Start (Get-Date) -End $endTime).TotalSeconds)
            Start-Sleep -Seconds 0.5
        } while ((Get-Date) -lt $endTime)
        return $Job
    }
    
    return $PodeJob
}

function Stop-PodeServer {
    <#
    .SYNOPSIS
        Stops the PODE server
    #>
    param()
    
    $PodeJobs = Get-Job -Name 'PodeServer' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    if ($PodeJobs) {
        $PodeJobs | Stop-Job 
        $PodeJobs | Remove-Job
        Write-Host 'Pode server stopped'
    }
    else {
        Write-Host 'Pode server is not running'
    }
}

function Test-PodeHookRoute {
    <#
    .SYNOPSIS
        Tests the PODE server hook route through NGROK tunnel
    .PARAMETER NgrokTunnel
        The NGROK tunnel object containing the public URL
    .OUTPUTS
        Boolean indicating if the test passed
    #>
    param(
        [object]$NgrokTunnel = (Get-NgrokTunnel -ErrorAction SilentlyContinue)
    )
    
    if (-not $NgrokTunnel) {
        Write-Error 'NGROK tunnel not available for testing'
        return $false
    }
    
    $Endpoint = $NgrokTunnel.public_url
    $TestCredentials = [PSCredential]::new('admin', (ConvertTo-SecureString 'password' -AsPlainText -Force))
    $TestBody = @{
        'testguid' = [guid]::NewGuid().Guid
    }
    $TestPayload = @{
        Method         = 'POST'
        Uri            = "${Endpoint}/test_hook"
        Body           = $TestBody | ConvertTo-Json
        Credential     = $TestCredentials
        Authentication = 'Basic'
    }
    
    try {
        $TestResponse = Invoke-RestMethod @TestPayload
        $ResponseBody = ($TestResponse.Body | ConvertFrom-Json)
        if ($ResponseBody.testguid -eq $TestBody.testguid) {
            Write-Host "Test passed: $($ResponseBody.testguid)"
            return $true
        }
        else {
            Write-Error "Test failed: $($ResponseBody.testguid) vs $($TestBody.testguid)"
            return $false
        }
    }
    catch {
        Write-Warning "Test failed with error: $($_.Exception.Message)"
        return $false
    }
}

function Initialize-WebServerEnvironment {
    <#
    .SYNOPSIS
        Initializes both PODE and NGROK environments
    .PARAMETER PodePort
        The port number for the PODE server
    .PARAMETER ScriptTemplatePaths
        Hashtable of template paths for static routes
    .OUTPUTS
        Hashtable containing all server states and objects
    #>
    param(
        [int]$PodePort = 8099,
        [hashtable]$ScriptTemplatePaths = @{}
    )
    
    $result = @{
        PodePort            = $PodePort
        ScriptTemplatePaths = $ScriptTemplatePaths
    }
    
    # Initialize NGROK
    $ngrokState = Initialize-NgrokEnvironment -PodePort $PodePort
    $result += $ngrokState
    
    # Initialize PODE
    $podeState = Get-PodeServerStatus -PodePort $PodePort
    $result += $podeState
    
    return $result
}
