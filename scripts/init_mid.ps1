#!/usr/bin/env pwsh

Write-Host "Running init_mid.ps1"
Write-Output "Running init_mid.ps1"

Write-Host "Running in MID Server Context - $($env:MID_SERVER_NAME)"
if ((Test-Path /opt/snc_mid_server/agent) -and $env:MID_SERVER_CUSTOM_CERT_PATH) {
    Write-Host "MID Server Custom Certificate Path: $($env:MID_SERVER_CUSTOM_CERT_PATH)"
    $CurrentPath = Get-Location
    # try {
    Set-Location /opt/snc_mid_server/agent
    $CertDetails = (./bin/scripts/manage-certificates.sh -g 'defaultsecuritykeypairhandle' 2>&1)
    
    if ($CertDetails -match 'DC=service-now') {
        Write-Host 'Certificate already exists in the mid server. Removing it.'
        ./bin/scripts/manage-certificates.sh -d defaultsecuritykeypairhandle
        ./bin/scripts/manage-certificates.sh -a defaultsecuritykeypairhandle $env:MID_SERVER_CUSTOM_CERT_PATH
    }
    elseif ($CertDetails -match $env:MID_SERVER_NAME) {
        Write-Host 'Certificate already installed in the mid server. Skipping installation.'
    }
    else {
        ./bin/scripts/manage-certificates.sh -a defaultsecuritykeypairhandle $env:MID_SERVER_CUSTOM_CERT_PATH
    }
    Set-Location /opt/snc_mid_server/
    try{
        /opt/snc_mid_server/init start
    }catch{
        Write-Host "Error starting MID server: $($_.Exception.Message)"
    }
    finally {
        Write-Host "MID server Docker process ended."
    }
}