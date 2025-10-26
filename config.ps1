################################################################################################################################################################
# GLOBAL CONFIGURATION
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# X.509 Certificate Settings
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Set the user name, email address, DNS names - optional - may be @(""), and other attributes as needed.
$type                = "Custom"
$userName            = "X Y ♕Limited♕ [＠ROOT CERTIFICATE AUTHORITY]"
$userEmail           = "X.Y@users.noreply.github.com"
$dnsNames            = @("github.com")
$dnsName             = ($dnsNames -join ", ")
$certStoreLocation   = "Cert:\CurrentUser\My"
$localTrustedRootCA  = "Cert:\CurrentUser\Root"
$keyAlgorithm        = "RSA"
$keyLength           = 4096
$hashAlgorithm       = "SHA256"
$keyExportPolicy     = "Exportable"
$keyUsage            = @("DigitalSignature", "KeyEncipherment")
$textExtension       = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.3,1.3.6.1.5.5.7.3.4,1.3.6.1.5.5.7.3.8,1.3.6.1.4.1.311.10.3.12")
$pfxPassword         = Read-Host -Prompt "Enter PFX password:" -AsSecureString
<# 
2.5.29.37 : OID for Extended Key Usage (EKU)
EKU Purpose	                OID	Description             Description
Server Authentication	    1.3.6.1.5.5.7.3.1	        Allows certificate to authenticate a server (e.g., HTTPS/TLS)
Client Authentication	    1.3.6.1.5.5.7.3.2	        Allows certificate to authenticate a client (e.g., mutual TLS)
Code Signing	            1.3.6.1.5.5.7.3.3	        Allows signing of executables and scripts
Secure Email	            1.3.6.1.5.5.7.3.4	        Enables S/MIME email signing and encryption
IP Security End System	    1.3.6.1.5.5.7.3.5	        Used for IPsec end systems (hosts)
IP Security Tunnel Endpoint	1.3.6.1.5.5.7.3.6	        Used for IPsec VPN tunnel endpoints
IP Security User	        1.3.6.1.5.5.7.3.7	        Used for IPsec user authentication
Time Stamping	            1.3.6.1.5.5.7.3.8	        Allows signing of timestamps
OCSP Signing	            1.3.6.1.5.5.7.3.9	        Allows signing of OCSP responses
DVCS Signing	            1.3.6.1.5.5.7.3.10	        Data validation and certification service signing
Document Signing	        1.3.6.1.4.1.311.10.3.12	    Microsoft-specific EKU for document signing
Smart Card Logon	        1.3.6.1.4.1.311.20.2.2	    Microsoft-specific EKU for smart card authentication
Enrollment Agent	        1.3.6.1.4.1.311.20.2.1	    Allows certificate enrollment on behalf of other users
Any Extended Key Usage	    2.5.29.37.0	                Wildcard EKU - allows all usages (not recommended for strict environments)
#>
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Paths def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------

$certFolder = "$PSScriptRoot\.cert"
$pfxPath    = "$certFolder\S_MIME_Personal_Information_Exchange-$userName.pfx"
$cerPath    = "$certFolder\S_MIME_X.509_Certificate-$userName.cer"
$configPath = "$PSScriptRoot\config.json"
$infPath    = "$PSScriptRoot\smime-certreq.inf"

################################################################################################################################################################
# CREATE JSON FILE
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def. JSON Configuration
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Set-ConfigJSONFile {
    # Ensure .cert folder exists
    if (-not (Test-Path $certFolder)) {
        New-Item -Path $certFolder -ItemType Directory | Out-Null
    }

    # Create config object
    $config = [ordered]@{
    type               = $type
    userName           = $userName
    userEmail          = $userEmail
    dnsName            = $dnsName
    certStoreLocation  = $certStoreLocation
    localTrustedRootCA = $localTrustedRootCA
    keyAlgorithm       = $keyAlgorithm
    keyLength          = $keyLength
    hashAlgorithm      = $hashAlgorithm 
    keyExportPolicy    = $keyExportPolicy
    keyUsage           = $keyUsage
    textExtension      = $textExtension
    pfxPassword        = $pfxPassword
    pfxPath            = $pfxPath
    cerPath            = $cerPath
    infPath            = $infPath
}
    # Convert to JSON and save
    $json = $config | ConvertTo-Json 
    Set-Content -Path $configPath -Value $json -Encoding UTF8
    Write-Host "File config.json has been created at $configPath" -ForegroundColor Cyan
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe. JSON Configuration
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
Set-ConfigJSONFile


################################################################################################################################################################
# CREATE INF FILE
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def. INF Configuration
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Set-ConfigINFFile {
    
    # Build SAN string (trim whitespace for safety)
    $sanString = ($dnsNames | ForEach-Object { "dns=$($_.Trim())" }) -join "&"
    $infContent = @"
[Version]
Signature="\$Windows NT\$"

[NewRequest]
KeyAlgorithm   = "$keyAlgorithm"
KeyLength      =  $keyLength
HashAlgorithm  = "$hashAlgorithm"
KeyExportPolicy= "$keyExportPolicy"
ProviderName   = "$providerName"
KeyContainer   = "$keyContainer"
RequestType    = "PKCS10"
Subject        = "CN=$userName, E=$userEmail"
KeySpec        =  1

[Extensions]
2.5.29.15 = "{text}"
_continue_ = "KeyUsage=0xA0"

2.5.29.17 = "{text}"
_continue_ = "$sanString"

2.5.29.37 = "{text}"
_continue_ = "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.3,1.3.6.1.5.5.7.3.4,1.3.6.1.5.5.7.3.8,1.3.6.1.4.1.311.10.3.12"

[RequestAttributes]
CertificateTemplate = User
SubjectAltName = "$sanString"
"@

    Set-Content -Path $infPath -Value $infContent -Encoding UTF8
    Write-Host "File smime-certreq.inf has been created at $infPath" -ForegroundColor Cyan
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe. INF Configuration
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
Set-ConfigINFFile

