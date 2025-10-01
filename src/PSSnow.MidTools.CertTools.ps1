#!/usr/bin/env pwsh

using namespace System.Collections.Generic
using namespace System.Formats.Asn1
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates


function Resolve-SNOWMidAzCertificate {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        [Parameter(Mandatory = $true)]
        [string]$CertName,
        [System.IO.FileInfo]$OutputPath,
        [switch]$SavePem,
        [switch]$SavePfx
    )
    $Out = @{}
    $Collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $Cert = (Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -ErrorAction SilentlyContinue)
    if ($Cert -and $Cert.SecretId) {
        $CertSecret = Get-AzKeyVaultSecret -SecretId $Cert.SecretId -ErrorAction SilentlyContinue
        switch ($CertSecret.ContentType) {
            'application/x-pem-file' {
                $CertPem = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($CertSecret.SecretValue | ConvertFrom-SecureString -AsPlainText)))
                $Collection.ImportFromPem($CertPem)
            }
            'application/x-pkcs12' {
                $CertPfx = [Convert]::FromBase64String(($CertSecret.SecretValue | ConvertFrom-SecureString -AsPlainText))
                $Collection.Import($CertPfx, '', [X509KeyStorageFlags]::Exportable)
            }
        }
    }
    if ($Collection.Count -eq 0) {
        Write-Host "Certificate $CertName not found in Key Vault $VaultName. Skipping export."
        return $Out
    }
    $PemSecretName = "${CertName}-mid-pem"
    $CurrentPemSecret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $PemSecretName -AsPlainText -ErrorAction SilentlyContinue
    $PEMContent = @($Collection[0].PrivateKey.ExportPkcs8PrivateKeyPem(), $Collection.ExportCertificatePems()) -join "`n"
    $PEMSecretContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(( $PEMContent )))
    
    if ($CurrentPemSecret -eq $PEMSecretContent) {
        Write-Host "PEM secret $PemSecretName in Key Vault $VaultName is up to date"
    }
    else {
        Write-Host "Updating PEM secret $PemSecretName in Key Vault $VaultName"
        $PemSecret = Set-AzKeyVaultSecret -VaultName $VaultName -Name $PemSecretName -SecretValue (ConvertTo-SecureString -String $PEMSecretContent -AsPlainText -Force) -ErrorAction SilentlyContinue
    }
    $Out.PemSecret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $PemSecretName -ErrorAction SilentlyContinue
    $Out.Collection = $Collection
    $Out.Certificate = $Collection[0]
    $Out.Thumbprint = $Collection[0].Thumbprint
    $Out.PublicKeyInfo = [Convert]::ToBase64String($Collection[0].PublicKey.ExportSubjectPublicKeyInfo())
    Write-Host "Certificate $CertName found in Key Vault $VaultName with thumbprint $($Collection[0].Thumbprint)"
    if ($OutputPath) {
        $Out += @{
            PfxPath     = Join-Path -Path $OutputPath -ChildPath "${CertName}.pfx"
            PemPath     = Join-Path -Path $OutputPath -ChildPath "${CertName}.pem"
            CertPemPath = Join-Path -Path $OutputPath -ChildPath "${CertName}-cert.pem"
        }
        if ($SavePfx) {
            $Pfx = $Collection.Export([X509ContentType]::Pkcs12)
            Write-Host "Exporting certificate to $($Out.PfxPath)"
            Set-Content -Path $Out.PfxPath -Value $Pfx -AsByteStream
        }
        if ($SavePem) {
            $PEMContent = @($Collection[0].PrivateKey.ExportPkcs8PrivateKeyPem(), $Collection.ExportCertificatePems()) -join "`n"
            Write-Host "Exporting certificates to $($Out.PemPath)"
            $CertPemContent = $Collection.ExportCertificatePems() -join "`n"
            $PEMContent | Set-Content -Path $Out.PemPath -Encoding utf8
            $CertPemContent | Set-Content -Path $Out.CertPemPath -Encoding utf8
        }
    }
    return $Out
}


function Get-VaultCertificateCommon {
    Param(
        [string]$VaultName,
        [string]$CertificateName
    )
    $Out = @{}
    $Collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $SecretVault = Get-SecretVault -Name $VaultName -ErrorAction Stop
    if ($SecretVault.ModuleName -eq 'Az.KeyVault') {
        $Cert = Get-AzKeyVaultCertificate -VaultName $SecretVault.VaultParameters.AZKVaultName -Name $CertificateName -ErrorAction SilentlyContinue
        if ($Cert -and $Cert.SecretId) {
            $CertSecret = Get-AzKeyVaultSecret -SecretId $Cert.SecretId -ErrorAction SilentlyContinue
            switch ($CertSecret.ContentType) {
                'application/x-pem-file' {
                    $CertPem = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($CertSecret.SecretValue | ConvertFrom-SecureString -AsPlainText)))
                    $Collection.ImportFromPem($CertPem)
                }
                'application/x-pkcs12' {
                    $CertPfx = [Convert]::FromBase64String(($CertSecret.SecretValue | ConvertFrom-SecureString -AsPlainText))
                    $Collection.Import($CertPfx, '', [X509KeyStorageFlags]::Exportable)
                }
            }
        }
    }
    else {
        $CertificateSecretName = "$CertificateName"
        $Certificate = Get-Secret -Vault $VaultName -Name $CertificateSecretName -ErrorAction SilentlyContinue
        if ($Certificate) {
            $CertPem = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($Certificate | ConvertFrom-SecureString -AsPlainText)))
            $Collection.ImportFromPem($CertPem)
        }
    }
    if ($Collection.Count -eq 0) {
        Write-Host "Certificate $CertificateName not found in Vault $VaultName."
        return $null
    }
    $Out.Collection = $Collection
    $Out.Certificate = $Collection[0]
    $Out.Thumbprint = $Collection[0].Thumbprint
    $Out.PublicKeyInfo = [Convert]::ToBase64String($Collection[0].PublicKey.ExportSubjectPublicKeyInfo())
    $PemSecretName = "${CertificateName}-mid-pem"
    $CurrentPemSecret = Get-Secret -Vault $VaultName -Name $PemSecretName -AsPlainText -ErrorAction SilentlyContinue
    $PEMSecretContent = getCertificateCollectionPEM -Collection $Collection -AsBase64 -IncludePrivateKey
    if ($CurrentPemSecret -and $CurrentPemSecret -eq $PEMSecretContent) {
        
        Write-PSFMessage -Level Verbose "PEM secret $PemSecretName in Key Vault $VaultName is up to date"
    }
    else {
        Write-Host "Updating PEM secret $PemSecretName in Key Vault $VaultName"
        Set-Secret -Vault $VaultName -Name $PemSecretName -Secret $PEMSecretContent -ErrorAction Stop
        Write-PSFMessage -Level Verbose "PEM secret $PemSecretName in Key Vault $VaultName has been updated"
    }
    $Out.PemSecret = Get-SecretInfo -Vault $VaultName -Name $PemSecretName -ErrorAction SilentlyContinue
    return $Out
}
    


function Set-VaultCertificateCommon {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        [Parameter(Mandatory = $true)]
        [string]$CertificateName,
        [Parameter(Mandatory = $true)]
        $Collection
    )
    $CurrentCertificate = Get-VaultCertificateCommon -VaultName $VaultName -CertificateName $CertificateName
    $SecretVault = Get-SecretVault -Name $VaultName -ErrorAction Stop
    if ($SecretVault.ModuleName -eq 'Az.KeyVault') {
        if ($CurrentCertificate -and $CurrentCertificate.Thumbprint -eq $Collection[0].Thumbprint) {
            Write-PSFMessage -Level Verbose "Certificate $CertificateName in Key Vault $($SecretVault.VaultParameters.AZKVaultName) is up to date"            
            return $CurrentCertificate
        }
        else {
            Import-AzKeyVaultCertificate -VaultName $SecretVault.VaultParameters.AZKVaultName -Name $CertificateName -CertificateCollection $Collection | Out-Null
        }
        return Get-VaultCertificateCommon -VaultName $VaultName -CertificateName $CertificateName
    }
    else {
        if ($CurrentCertificate -and $CurrentCertificate.Thumbprint -eq $Collection[0].Thumbprint) {
            Write-PSFMessage -Level Verbose "Certificate $CertificateName in Key Vault $($SecretVault.VaultParameters.AZKVaultName) is up to date"
            return $CurrentCertificate
        }
        else {
            $PEMSecretContent = getCertificateCollectionPEM -Collection $Collection -AsBase64 -IncludePrivateKey
            Set-Secret -Vault $VaultName -Name $CertificateName -Secret $PEMSecretContent -ErrorAction Stop | Out-Null
            return Get-VaultCertificateCommon -VaultName $VaultName -CertificateName $CertificateName
        }
    }
}

# Check if the leaf certificate is signed by the root certificate
function Test-CertificateSignedBy {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Leaf,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Root
    )
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.ExtraStore.Add($Root) | Out-Null
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        $isValid = $chain.Build($Leaf)
        # Check if the root is in the chain and is the issuer
        $rootInChain = $chain.ChainElements | Where-Object { $_.Certificate.Thumbprint -eq $Root.Thumbprint }
        return ($isValid -and $rootInChain)
    }
    catch {
        Write-Warning "Error verifying certificate chain: $_"
        return $false
    }
}

function getCertificateCollectionPEM($Collection, [switch]$AsBase64, [switch]$IncludePrivateKey) {
    $PEMContent = @()
    if ($IncludePrivateKey) {
        $PEMContent += $Collection[0].PrivateKey.ExportPkcs8PrivateKeyPem()
    }
    $PEMContent += $Collection.ExportCertificatePems()
    if ($AsBase64) {
        return [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($PEMContent -join "`n")))
    }
    return $PEMContent -join "`n"
}

function Set-BoundAzCertificate {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        [Parameter(Mandatory = $true)]
        [string]$CertName,
        [Parameter(Mandatory = $true)]
        $Collection
    )
    $Cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -ErrorAction SilentlyContinue
    if ($Cert -and $Cert.Thumbprint -eq $Collection[0].Thumbprint) {
        $Cert
    }
    else {
        Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificateCollection $Collection
    }
}

function Set-SNOWMidRootCertificate {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        [Parameter(Mandatory = $true)]
        [string]$RootCN,
        [switch]$ForceRecreate
    )
    $AzCert = Get-VaultCertificateCommon -VaultName $VaultName -CertificateName $RootCN
    if ($AzCert -and $AzCert['Collection'] -and !$ForceRecreate.IsPresent) {
        return $AzCert
    }
    [System.DateTimeOffset]$NotBefore = [System.DateTimeOffset]::Now.AddDays(-5)
    [System.DateTimeOffset]$NotAfter = [System.DateTimeOffset]::Now.AddDays(9001)
    $Subject = [X500DistinguishedName]::new("CN=${RootCN}")
    $KeyUsage = [X509KeyUsageExtension]::new(
        [X509KeyUsageFlags]::DigitalSignature +
        [X509KeyUsageFlags]::KeyCertSign,
        $true)
    # Create Basic Constraints
    $BasicConstraints = [X509BasicConstraintsExtension]::new(
        <# certificateAuthority #> $true,
        <# hasPathLengthConstraint #> $true,
        <# pathLengthConstraint #> 1,
        <# critical #> $true)

    $Extensions = [System.Collections.Generic.List[X509Extension]]::new()
    $Extensions.Add($KeyUsage)
    $Extensions.Add($BasicConstraints)

    $PrivateKey = [RSA]::Create(2048)

    # Create Certificate Request
    $CertRequest = [CertificateRequest]::new(
        $Subject,
        $PrivateKey,
        [HashAlgorithmName]::SHA256,
        [RSASignaturePadding]::Pkcs1)

    # Create the Subject Key Identifier extension
    $SubjectKeyIdentifier = [X509SubjectKeyIdentifierExtension]::new(
        $CertRequest.PublicKey,
        <# critical #> $false)
    $Extensions.Add($SubjectKeyIdentifier)

    foreach ($Extension in $Extensions) {
        $CertRequest.CertificateExtensions.Add($Extension)
    }

    $CertificateWithKey = $CertRequest.CreateSelfSigned($NotBefore, $NotAfter)
    if ($AzureCert = Set-VaultCertificateCommon -VaultName $VaultName -CertificateName $RootCN -Collection $CertificateWithKey) {
        Write-Host "Created new root certificate $RootCN in Key Vault $VaultName with thumbprint $($AzureCert.Thumbprint)"
        return $AzureCert
    }
    else {
        throw "Failed to create root certificate $RootCN in Key Vault $VaultName"
    }
}
function Set-SNOWMidServerCertificate {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        [Parameter(Mandatory = $true)]
        [string]$LeafCN,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Signer,
        [switch]$Renew,
        [switch]$ForceRecreate,
        [int]$ValidityDays = 365
    )
    [System.DateTimeOffset]$NotAfter = [System.DateTimeOffset]::Now.AddDays($ValidityDays)
    [System.DateTimeOffset]$NotBefore = [System.DateTimeOffset]::Now.AddDays(-1)
    $AzCert = Get-VaultCertificateCommon -VaultName $VaultName -CertificateName $LeafCN
    if ($AzCert -and $AzCert.Collection -and !$ForceRecreate.IsPresent) {
        # Check if the existing leaf certificate is signed by the current root
        $existingLeaf = $AzCert.Collection[0]
        if (Test-CertificateSignedBy -Leaf $existingLeaf -Root $Signer) {
            Write-PSFMessage "Existing leaf certificate $LeafCN is signed correctly. Expires: $($existingLeaf.NotAfter)"
            if ($Renew.IsPresent) {
                Write-PSFMessage "Current secret is valid until $($existingLeaf.NotAfter). Not renewing."
            }
            elseif ($existingLeaf.NotAfter -lt $([System.DateTime]::Now.AddDays(30))) {
                Write-PSFMessage "Current secret is expiring soon on $($existingLeaf.NotAfter). Renewing certificate."
            }
            else {
                return $AzCert
            }
        }
        else {
            Write-Host "Existing leaf certificate $LeafCN is NOT signed by the current root certificate. Recreating..."
        }
    }
    $Subject = [X500DistinguishedName]::new("CN=${LeafCN}")
    # EKU
    $EkuOidCollection = [OidCollection]::new()
    $EkuOidCollection.Add([Oid]::new('1.3.6.1.5.5.7.3.1', 'Server Authentication')) | Out-Null
    $EkuOidCollection.Add([Oid]::new('1.3.6.1.5.5.7.3.2', 'Client Authentication')) | Out-Null
    $EnhancedKeyUsages = [X509EnhancedKeyUsageExtension]::new($EkuOidCollection, <# critical #> $true)

    $KeyUsage = [X509KeyUsageExtension]::new(
        [X509KeyUsageFlags]::DigitalSignature +
        [X509KeyUsageFlags]::DataEncipherment +
        [X509KeyUsageFlags]::NonRepudiation,
        $true)

    # Create Basic Constraints
    $BasicConstraints = [X509BasicConstraintsExtension]::new(
        <# certificateAuthority #> $false,
        <# hasPathLengthConstraint #> $false,
        <# pathLengthConstraint #> 0,
        <# critical #> $true)

    $SanBuilder = [SubjectAlternativeNameBuilder]::new()
    $SanBuilder.AddDnsName($LeafCN)

    $Extensions = [System.Collections.Generic.List[X509Extension]]::new()
    $Extensions.Add($SanBuilder.Build())
    $Extensions.Add($KeyUsage)
    $Extensions.Add($EnhancedKeyUsages)
    $Extensions.Add($BasicConstraints)

    $PrivateKey = if ($AzCert -and $AzCert.Collection -and !$ForceRecreate.IsPresent) {
        $AzCert.Collection[0].PrivateKey
    }
    else { 
        Write-Host "Creating new private key for leaf certificate."
        [RSA]::Create(2048) 
    }

    # Create Certificate Request
    $CertRequest = [CertificateRequest]::new(
        $Subject,
        $PrivateKey,
        [HashAlgorithmName]::SHA256,
        [RSASignaturePadding]::Pkcs1)

    # Create the Subject Key Identifier extension
    $SubjectKeyIdentifier = [X509SubjectKeyIdentifierExtension]::new(
        $CertRequest.PublicKey,
        <# critical #> $false)
    $Extensions.Add($SubjectKeyIdentifier)

    foreach ($Extension in $Extensions) {
        $CertRequest.CertificateExtensions.Add($Extension)
    }

    $Serial = [byte[]]::new(16)
    $Random = [System.Random]::new()
    $Random.NextBytes($Serial)

    $Cert = $CertRequest.Create($Signer, $NotBefore, $NotAfter, $Serial)
    $LeafCert = [RSACertificateExtensions]::CopyWithPrivateKey($Cert, $PrivateKey)
    $Collection = [X509Certificate2Collection]::new()
    $Collection.Add($LeafCert) | Out-Null
    $Collection.Import($Signer.rawData)
    return Set-VaultCertificateCommon -VaultName $VaultName -CertificateName $LeafCN -Collection $Collection
}

function Set-SNOWMidUserCertificate {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$CertificatePemPath,
        [Parameter(Mandatory = $true)]
        [string]$CertificateName,
        [string]$UserName 
    )
    if (!(Get-SNOWAuth)) {
        throw "Not authenticated to ServiceNow. Please run Connect-SNOW first."
    }
    $User = Get-SNOWObject -Table 'sys_user' -Query "user_name=$UserName" | Select-Object -First 1
    if (!$User) {
        Write-Error "User $UserName not found in ServiceNow."
        return
    }
    $CertificateProperties = @{
        active                  = 'true'
        name                    = $CertificateName
        sys_id                  = ([guid]::NewGuid().ToString('N'))
        type                    = 'client_cert'
        short_description       = 'Imported CA For Mutual Auth DT'
        sys_class_name          = 'sys_user_certificate'
        format                  = 'pem'
        expiration_notification = 'false'
        user                    = $User.sys_id
    }
    $CACertificate = Get-SNOWObject -Table 'sys_user_certificate' -Query "name=$CertificateName"
    $ExistingAttachments = Get-SNOWObject -Table 'sys_attachment' -Query "file_name=$($CertificateName).pem"
    if ($ExistingAttachments) {
        Write-Host "Removing existing attachment $($ExistingAttachments.sys_id)"
        $ExistingAttachments | Remove-SNOWObject -PassThru
    }
    if (!$CACertificate) {
        $Attachment = New-SNOWAttachment -File $CertificatePemPath -Sys_Class_Name 'sys_user_certificate' -Sys_ID $CertificateProperties.sys_id -AttachedFilename "${CertificateName}.pem" -PassThru
        $CACertificate = New-SNOWObject -Table 'sys_user_certificate' -Properties $CertificateProperties -PassThru
        Write-Host "Certificate $($CertificateName) created with sys_id $($CACertificate.sys_id)"
    }
    else {
        Write-Warning "Certificate $($CertificateName) already exists in ServiceNow. Skipping creation."
        if ($CACertificate.user -ne $User.sys_id) {
            Set-SNOWObject -Table 'sys_user_certificate' -Properties @{user = $User.sys_id } -Sys_ID $CACertificate.sys_id
        }
    }
}