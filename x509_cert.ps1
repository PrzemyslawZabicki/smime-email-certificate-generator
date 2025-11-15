################################################################################################################################################################   
# S\MIME EMAIL X.509 CERTIFICATE FOR WINDOWS 
################################################################################################################################################################


################################################################################################################################################################   
# SETUP
################################################################################################################################################################

# Import utils
. "$PSScriptRoot\utils.ps1"

# Setup PowerShell console [Optional]
Set-PowerShell_Console


################################################################################################################################################################
# LOAD CONFIGURATION
################################################################################################################################################################

# Load config.json file  for creating cert. via PowerShell PKI API 
$configJSON = Get-Content -Path "$PSScriptRoot\config.json" -Raw | ConvertFrom-Json

# Load smime-request.inf for creating cert. via cert.request
$configINF = Get-Content -Path "$PSScriptRoot\smime-certreq.inf"

# Import AES-256
. "$PSScriptRoot\aes_256.ps1"

# 1. Save AES key to SecretStore (only once)
Save-AesKeyToSecretManager -SecretName "pfxKey"

# 2. Save encrypted PFX password blob
Save-PfxPasswordBlob -SecretName "pfxKey" -BlobPath "$PSScriptRoot\pfxPass"


################################################################################################################################################################
# 1. CREATE CERTIFICATE                                                                                       
################################################################################################################################################################
#                                                                                                                                                              #
#                                                                                                                                                              #
#                                                                                                                 Note: .PFX <=> .PCKS12 <=> .p12 (Unix, macOS)#
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# This step generates the certificate and private key using New-SelfSignedCertificate function from PKI PowerShell mod. or a certificate request via certreq.exe
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Create Personal Information Exchange (.pfx) container with crypto data in data structure: private key, certificate .cer (.X509), password, and certs chain (CA)
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# File .pfx (Windows) is technically equivalent to PKCS#12 or .p12 (Unix/macOS) - they represent the same format and structure, differing only by file extension
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Return: Function generates .pfx file, and saves it in User Local Personal Certificates Storage Location.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Set-PFX_Personal_Information_Exchange_Crypto_Container {
    param (
        [Parameter(Mandatory=$true)]
        [pscustomobject]$configJSON
    )

    $PFX_Crypto_Data_Container = New-SelfSignedCertificate `
        -Type $configJSON.type `
        -Subject "CN=$($configJSON.userName), E=$($configJSON.userEmail)" `
        -DnsName $configJSON.dnsName `
        -CertStoreLocation $configJSON.certStoreLocation `
        -KeyAlgorithm $configJSON.keyAlgorithm `
        -KeyLength $configJSON.keyLength `
        -HashAlgorithm $configJSON.hashAlgorithm `
        -KeyExportPolicy $configJSON.keyExportPolicy `
        -KeyUsage $configJSON.keyUsage `
        -TextExtension $configJSON.textExtension

    return $PFX_Crypto_Data_Container
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
$PFX_Crypto_Data_Container = Set-PFX_Personal_Information_Exchange_Crypto_Container -configJSON $configJSON
$PFX_Crypto_Data_Container | Format-List Subject, Issuer, FriendlyName, Thumbprint

################################################################################################################################################################
# 2. EXPORT CERTIFICATE 
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Once the certificate is created, you export it to .pfx  (private + public key) and .cer (public key only) files.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# This export is from Personal Store to Local File System (.cert directory)   
# --------------------------------------------------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def. 
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Export-CertificateBundle {
    param (
        [Parameter(Mandatory=$true)]
        [string]$pfxPath,

        [Parameter(Mandatory=$true)]
        [string]$cerPath,

        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,

        [Parameter(Mandatory=$true)]
        [securestring]$pfxPassword
    )

    try {
        # EXPORT FROM STORE TO LOCAL FILE SYSTEM TO GET .PFX (PKCS#12) 
        # Purpose: Export private key and certificate
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword
        
        # EXPORT FROM STORE TO LOCAL FILE SYSTEM TO GET .CER (X.509) 
        # Purpose: Export public key only
        Export-Certificate -Cert $cert -FilePath $cerPath

        # Confirmation
        Write-Host "Certificate exported successfully:" -ForegroundColor Cyan
        Write-Host "→ Subject:       $($cert.Subject)" 
        Write-Host "→ FriendlyName:  $($cert.FriendlyName)"
        Write-Host "→ PFX Path:      $pfxPath"
        Write-Host "→ CER Path:      $cerPath"
    }
    catch {
        Write-Host "Error during export: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Load PFX password blob and use in export
$securePassword = Get-PfxPasswordForExport -SecretName "pfxKey" -BlobPath "$PSScriptRoot\pfxPass"
Export-CertificateBundle -pfxPath $configJSON.pfxPath -cerPath $configJSON.cerPath -cert $PFX_Crypto_Data_Container -pfxPassword $securePassword

################################################################################################################################################################
# 3. IMPORT CERTIFICATE
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Import cer. from Local File System to Local Store
# --------------------------------------------------------------------------------------------------------------------------------------------------------------

<#--------------------------------------------------------------------------------------------------------------------------------------------------------------
Store Name             |           Display Name
----------------------------------------------------------------------------------------------------------------------------------------------------------------
My	                   |           Personal
Root	               |           Trusted Root Certification Authorities
CA	                   |           Intermediate Certification Authorities
TrustedPeople	       |           Trusted People
TrustedPublisher       |           Trusted Publishers
AddressBook	           |           Other People
AuthRoot	           |           Third-Party Root Certification Authorities
Disallowed	           |           Untrusted Certificates
--------------------------------------------------------------------------------------------------------------------------------------------------------------#>

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Import-Certificate_To_Stores {    
    $stores    = @("My", "Root",  "CA", "TrustedPeople", "TrustedPublisher", "AddressBook")
    $locations = @("CurrentUser")  #$locations = @("CurrentUser", "LocalMachine")
    foreach ($location in $locations) {
        foreach ($store in $stores) {
            $certLocalStorePath = "Cert:\$location\$store"
            if (Test-Path $certLocalStorePath) {
                $certLocalFileSystemPath = $configJSON.cerPath
                if (Test-Path -LiteralPath $certLocalFileSystemPath) {
                    Write-Host "Importing certificate   |   $certLocalFileSystemPath   |   $certLocalStorePath" -ForegroundColor Cyan
                    try {
                        $cert = Import-Certificate -FilePath $certLocalFileSystemPath -CertStoreLocation $certLocalStorePath
                        if ($cert) {
                            Write-Host "Certificate imported successfully:" -ForegroundColor Cyan
                        } else {
                            Write-Host "Certificate import failed" -ForegroundColor DarkRed
                        }
                    }
                    catch {
                        Write-Host "Error during import: $($_.Exception.Message)" -ForegroundColor DarkRed
                    }            
                } 
            }
        }
    }
}


# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Import-Certificate_To_Stores

