# === CONFIGURATION ===
[CmdletBinding()]
param (
    # [Parameter(Mandatory)]
    # [ValidateScript(
    #     { $_ -in (Get-SNOWObject -Table 'ecc_agent' -Fields 'name').name },
    #     ErrorMessage = 'Please specify a valid MID Server name from the ServiceNow instance.'
    # )]
    # [ArgumentCompleter(
    #     {
    #         param($cmd, $param, $wordToComplete)
    #         # This is the duplicated part of the code in the [ValidateScipt] attribute.
    #         [array] $validValues = (Get-SNOWObject -Table 'ecc_agent' -Fields 'name').name
    #         $validValues -like "$wordToComplete*"
    #     }
    # )]
    [String] $MidServerName
)
$ErrorActionPreference = 'Stop'
function LoadBouncyCastle {
    
    try {
        $null = [System.Reflection.Assembly]::GetAssembly([Org.BouncyCastle.X509.X509CertificateParser])
        return
    }
    catch {
        Write-Warning "BouncyCastle not loaded, installing..."
    }
    $AzKvModule = Get-Module -Name Az.KeyVault -ListAvailable
    if ($AzKvModule) {
        Import-Module -Name $AzKvModule -Force
        Write-Host "Az.KeyVault module loaded successfully. BouncyCastle should exist there."
        $null = [System.Reflection.Assembly]::GetAssembly([Org.BouncyCastle.X509.X509CertificateParser])
        return
    }
    # Step 1: Ensure NuGet provider is available
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    }

    # Step 2: Install BouncyCastle if not already installed
    $bcPackage = Get-Package -Name BouncyCastle.Cryptography -ErrorAction SilentlyContinue
    if (-not $bcPackage) {
        Install-Package -Name BouncyCastle.Cryptography -Source nuget.org -Force -Scope CurrentUser
    }
    if (-not (Get-Command 'Import-Package' -ErrorAction SilentlyContinue)) {
        Install-Module -Name 'Import-Package' -Force -Scope CurrentUser
    }
    Import-Package -Name 'BouncyCastle.Cryptography'
    Write-Host "BouncyCastle loaded successfully."
}
function Get-MIDServerPublicKey {
    [CmdletBinding(DefaultParameterSetName = 'AzureContainerInstance')]
    param (
        # Parameters for PodmanContainer
        [Parameter(ParameterSetName = 'PodmanContainer', Mandatory)]
        [string]$PodmanContainerName,

        # Parameters for AzureContainerInstance
        [Parameter(ParameterSetName = 'AzureContainerInstance', Mandatory)]
        [string]$ContainerGroupName,
        [Parameter(ParameterSetName = 'AzureContainerInstance', Mandatory)]
        [string]$ResourceGroupName
    )

    # Common variables
    $KeytoolPath = '/opt/snc_mid_server/agent/jre/bin/keytool'
    $KeystorePath = '/opt/snc_mid_server/agent/security/agent_keystore'
    $PemPath = '/opt/snc_mid_server/current_cert.pem'
    $CopyCommand = "$KeytoolPath -exportcert -rfc -keystore $KeystorePath -protected -alias defaultsecuritykeypairhandle -file ${PemPath}"
    $CatCommand = "openssl x509 -pubkey -noout -in $PemPath"
    $PemContentCommand = "cat $PemPath"
    
    switch ($PSCmdlet.ParameterSetName) {
        'PodmanContainer' {
            $MidServerName = $PodmanContainerName
            # Execute commands in Podman container
            Write-Host $CopyCommand
            podman exec $PodmanContainerName bash -c "$CopyCommand" 
            $CertPem = podman exec $PodmanContainerName bash -c "$CatCommand"
            $PemBase = podman exec $PodmanContainerName bash -c "$PemContentCommand"
        }
        'AzureContainerInstance' {
            $MidServerName = $ContainerGroupName
            # Execute commands in Azure Container Instance
            Write-Host $CopyCommand
            $CopyResult = Invoke-AzContainerInstanceCommand -ResourceGroupName $ResourceGroupName -ContainerName $ContainerGroupName -ContainerGroupName $ContainerGroupName -Command $CopyCommand -TerminalSizeCol 80 -TerminalSizeRow 200 -PassThru 2>$null | Out-Null
            $CertPem = Invoke-AzContainerInstanceCommand -ResourceGroupName $ResourceGroupName -ContainerName $ContainerGroupName -ContainerGroupName $ContainerGroupName -Command $CatCommand -TerminalSizeCol 80 -TerminalSizeRow 200 -PassThru 2>$null
            $PemBase = Invoke-AzContainerInstanceCommand -ResourceGroupName $ResourceGroupName -ContainerName $ContainerGroupName -ContainerGroupName $ContainerGroupName -Command $PemContentCommand -TerminalSizeCol 80 -TerminalSizeRow 200 -PassThru 2>$null
        }
    }
    Write-Host "Certificate PEM Content:`n$($PemBase -join "`n")"
    $MidRecord = Get-SNOWObject -Table 'ecc_agent' -Query "name=${MidServerName}"
    $Out = [ordered]@{
        CertPem        = $CertPem
        PemBase        = $PemBase
        LocalPublicKey = $null
        MidRecord      = $MidRecord
        Valid          = $false
    }
    if ($PemBase) {
        $base64 = ($PemBase -replace "-----BEGIN CERTIFICATE-----", "") `
            -replace "-----END CERTIFICATE-----", "" `
            -replace "\s", ""
        $certBytes = [Convert]::FromBase64String($base64)
        # Step 6: Extract the public key using BouncyCastle
        $certParser = New-Object Org.BouncyCastle.X509.X509CertificateParser
        $bcCert = $certParser.ReadCertificate($certBytes)
        $publicKey = $bcCert.GetPublicKey()

        # Step 7: Convert public key to PEM format
        $sw = New-Object System.IO.StringWriter
        $pemWriter = New-Object Org.BouncyCastle.OpenSsl.PemWriter($sw)
        $pemWriter.WriteObject($publicKey)
        $pemWriter.Writer.Flush()

        # Step 8: Output
        
        $Out.PemBaseKey = ($sw.ToString() -replace "-----BEGIN PUBLIC KEY-----", "") `
            -replace "-----END PUBLIC KEY-----", "" `
            -replace "\s", ""
    }
    # Process the certificate to extract the public key
    if ($Out.PemBaseKey) {
        $Out.LocalPublicKey = $Out.PemBaseKey
        $Out.Valid = $Out.LocalPublicKey -eq $MidRecord.public_key
        Write-PSFMessage -Level Significant -Message "Mid Server ${MidServerName} Public Key: $($Out.LocalPublicKey) (Valid: $($Out.Valid))"
    }
    else {
        Write-Host "No certificate found in the MID server."
    }
    return $Out
}

LoadBouncyCastle
[hashtable]$Outputs = [ordered]@{}
$PodmanContainers = (podman ps --format '{{.Names}}') -as [string[]]
Write-Host "Available Podman Containers: $($PodmanContainers -join ', ')"
if ($PodmanContainers -contains $MidServerName) {
    Write-Host "Found Podman container $MidServerName"
    $R = Get-MIDServerPublicKey -PodmanContainerName $MidServerName
    $Outputs["PublicKey"] = $R
}
else {
    $Global:mm = $kbc
    $Containers = Get-AzContainerGroup
    if ($Containers.Name -contains $MidServerName) {
        $AzContainer = $Containers | Where-Object { $_.Name -eq $MidServerName }
        Write-Host "Found Azure Container Instance $MidServerName"
        $R = Get-MIDServerPublicKey -ContainerGroupName $MidServerName -ResourceGroupName $AzContainer.ResourceGroupName
        $Outputs["PublicKey"] = $R
    }
    else {
        Write-Error "No Podman container found with name $MidServerName. Available containers: $($PodmanContainers -join ', ')"
        return
    }
}
$Outputs
# if ($MR = $R.MidRecord) {
    
#     if ("$($MR.validated)" -ne 'true') {
#         Invoke-SNOWMIDValidate -MidServerName "podmid01"
#     }
#     elseif ($MR.validated -eq 'true' -and !$R.LocalPublicKey) {
#         Invoke-SNOWMIDInvalidate -MidServerName "podmid01"
#         Invoke-SNOWMIDValidate -MidServerName "podmid01"
#     }else{
#         Write-Host "MID server is already validated."
#         Write-Host ($MR | ConvertTo-Json -Depth 5)
#     }
# }

# For AzureContainerInstance
# Get-MIDServerPublicKey -ContainerGroupName "azmidunit04" -ResourceGroupName "snmid-rg-acs-unittest"

