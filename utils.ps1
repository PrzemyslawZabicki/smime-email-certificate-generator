################################################################################################################################################################ 
# UTILS FILE
################################################################################################################################################################     


################################################################################################################################################################
# CONFIGURATION OF MICROSOFT OUTLOOK TRUST CENTER SECURITY
################################################################################################################################################################


# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Objective: Prevent the hash algorithm from being overwritten by MS Trust Center.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Set SHA-256 hash as default hash algorithm for signing emails with Outlook.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------

# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Set-SHA256_Email_Security_Settings {

    # Get the latest installed version of Microsoft Office
    
    # Define registry path
    $officeKey = "HKLM:\Software\Microsoft\Office"

    # Get all subkeys that match version numbers
    $officeVersions = Get-ChildItem -Path $officeKey | Where-Object { $_.PSChildName -match '^\d+\.\d+$' }

    # Sort and select the highest version
    $latestOfficeVersion = ($officeVersions | Sort-Object PSChildName -Descending | Select-Object -First 1).PSChildName

    # Output the result
    Write-Host "Microsoft Office Version: $latestOfficeVersion"

    # Set hash algorithm to SHA-256 for the latest installed version of Microsoft Office.
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$latestOfficeVersion\Outlook\Security" -Name "DefaultSigningAlgOID" -Value "2.16.840.1.101.3.4.2.1"
                                                        # Key: DefaultSigningAlgOID | Value: 2.16.840.1.101.3.4.2.1 (It means set DefaultSigningAlg to SHA-256)

    Write-Host "SHA-256 hash is the signing algorithm for Outlook emails." -ForegroundColor Cyan
}


# Load config.json file  for creating cert. via PowerShell PKI API 
$configJSON = Get-Content -Path "$PSScriptRoot\config.json" | ConvertFrom-Json


################################################################################################################################################################
# CONFIGURATION OF POWERSHELL CONSOLE (OPTIONAL)
################################################################################################################################################################ 

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Set-PowerShell_Console {
    # Set console buffer size to (width = 4096, height = 512) for getting the scrollable area 
    $host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(0x1000, 0x200) #0x1000 (in hex) = 4096 (in dec), 0x200 (in hex) = 512 (in dec)

    # Set window size to (width = 270, height = 70)  
    $host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size(0x100, 0x40)   #0x100  (in hex) = 256  (in dec), 0x40  (in hex) = 64  (in dec)

    # Set window position (top-left corner)
    $host.UI.RawUI.WindowPosition = New-Object Management.Automation.Host.Coordinates(0, 0)

    # Optional: Set window title
    $host.UI.RawUI.WindowTitle = "S/MIME Email Certificate Creator"

    # Set console to UTF-8 encoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 

    # Set console colors
    $host.UI.RawUI.BackgroundColor = 'Black' 
    $host.UI.RawUI.ForegroundColor = 'Cyan' 
    
    # Set console font on Consolas
    Set-ItemProperty -Path "HKCU:\Console" -Name "FaceName" -Value "Consolas"
    
    # Set console font size to 14 pt.(0x000E0000 in hexadecimal)
    Set-ItemProperty -Path "HKCU:\Console" -Name "FontSize" -Value 0x000E0000
}

################################################################################################################################################################
# Add Contact to Outlook Contact List
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Add-Outlook_Contact {

# Load Personal Information Exchange (.pfx) container
$pfx = Get-PfxCertificate -FilePath $configJSON.pfxPath

# Load Outlook COM object
$outlook = New-Object -ComObject Outlook.Application
$namespace = $outlook.GetNamespace("MAPI")

# Get default Contacts dir | 10 = olFolderContacts
$contactsFolder = $namespace.GetDefaultFolder(10)  

# Create new contact item in contact list
$contact = $contactsFolder.Items.Add("IPM.Contact")

# Set contact details
$contact.FullName = $configJSON.userName
$contact.EmailAddress = $configJSON.userMail   

# Save contact
$contact.Save()

# Confirmation
Write-Host "Contact $($contact.FullName) is created and added to the Outlook contact list." -ForegroundColor Green
}

################################################################################################################################################################
# Delete Outlook Contact
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Remove-Outlook_Contact {
    param ([string]$EmailAddress)

    $outlook = New-Object -ComObject Outlook.Application
    $namespace = $outlook.GetNamespace("MAPI")

    # 10 = olFolderContacts
    $contactsFolder = $namespace.GetDefaultFolder(10) 

    $found = $false

    foreach ($contact in $contactsFolder.Items) {
        if ($contact.Email1Address -eq $userMail) {
            $contact.Delete()
            Write-Host "Contact removed: $userMail" -ForegroundColor Green
            $found = $true
            break
        }
    }

    if (-not $found) {
        Write-Host "No contact found for $userMail" -ForegroundColor Green
    }
}      

################################################################################################################################################################
# PowerShell PKI Module 
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Get-PowerShell_PKI_API {
    
    Get-Command New-SelfSignedCertificate
    
    Get-Module PKI | Select-Object -ExpandProperty ExportedCommands
    
    Write-Host "PKI Module invokes Windows Cryptographic API CNG(Cryptography Next Generation), CSP(Cryptographic Service Providers) and others."
    
    # Define Windows cryptographic libraries as custom objects
    $cryptoLibs = @(
        [PSCustomObject]@{
            DLLName     = 'bcrypt.dll'
            Type        = 'CNG'
            Location    = 'C:\Windows\System32\bcrypt.dll'
            Description = 'Primary CNG library - handles algorithms, keys, and signatures'
        }
        [PSCustomObject]@{
            DLLName     = 'ncrypt.dll'
            Type        = 'CNG'
            Location    = 'C:\Windows\System32\ncrypt.dll'
            Description = 'Interface for Key Storage Providers (KSP)'
        }
        [PSCustomObject]@{
            DLLName     = 'crypt32.dll'
            Type        = 'CSP'
            Location    = 'C:\Windows\System32\crypt32.dll'
            Description = 'Legacy CSP library - manages certificates and stores'
        }
        [PSCustomObject]@{
            DLLName     = 'rsaenh.dll'
            Type        = 'CSP'
            Location    = 'C:\Windows\System32\rsaenh.dll'
            Description = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
        }
        [PSCustomObject]@{
            DLLName     = 'ncryptprov.dll'
            Type        = 'CNG'
            Location    = 'C:\Windows\System32\ncryptprov.dll'
            Description = 'Key storage provider for CNG'
        }
        [PSCustomObject]@{
            DLLName     = 'cryptui.dll'
            Type        = 'UI Utility'
            Location    = 'C:\Windows\System32\cryptui.dll'
            Description = 'Certificate user interface - used for dialogs and visual tools'
        }

    )

    $cryptoLibs | Format-Table DLLName, Type, Location, Description -AutoSize
}

################################################################################################################################################################
# Get user personal certificates from store
################################################################################################################################################################
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Get-UserPersonalCerts {
    Get-ChildItem -Path $($configJSON.certStoreLocation) | Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter | Format-Table -AutoSize
}

################################################################################################################################################################
# Get certificates from Local Trusted Root Certification Authorities
################################################################################################################################################################
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Get-LocalTrustedRootCA {
    Get-ChildItem -Path $($configJSON.localTrustedRootCA) | Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter | Format-Table -AutoSize
}

###################################################################################################################################################################
# SIGN POWERSHELL FILE 
###################################################################################################################################################################

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# -----------------------------------------------------------------------------------------------------------------------------------------------------------------
function Sign_PSFile { param (
        [Parameter(Mandatory=$true)]
        [string]$filePath,

        [Parameter(Mandatory=$true)]
        [string]$timestampServer,

        [Parameter(Mandatory=$true)]
        [string]$hash
    )

    # Define expected subject components
    $userName    = "CN = $configJSON.userName"
    $userEmail   = "E  = $configJSON.userEmail"
    
    $fullSubject = "$userName, $userEmail"
    
    # Normalize subject for comparison
    $normalizedSubject = $fullSubject -replace '\s+', ' ' -replace '\*$', ''

    # Try exact match first
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        ($_.Subject -replace '\s+', ' ') -eq $normalizedSubject
    }

    # Validate certificate
    if (-not $cert) {
        Write-Error "Certificate not found. Tried subject: $normalizedSubject"
        return
    }

    # --------------------------------------------------------------------------------------------------------------------------------------
    #        Extension	 Description
    # --------------------------------------------------------------------------------------------------------------------------------------
    #             .ps1	 PowerShell script file
    #            .psm1	 PowerShell module file
    #            .psd1	 PowerShell module manifest
    #          .ps1xml   PowerShell type and format definitions (XML)
    #           .cdxml	 Cmdlet definition XML (used in CIM cmdlets)
    # --------------------------------------------------------------------------------------------------------------------------------------
    # Sign PowerShell file
    # --------------------------------------------------------------------------------------------------------------------------------------
    
    if (Test-Path $filePath) {
        Set-AuthenticodeSignature -FilePath $filePath -Certificate $cert -TimestampServer $timestampServer -HashAlgorithm $hash
        Write-Host "Signed PowerShell file: $fileName"
    } else {
        Write-Warning "PowerShell file not found: $filePath" 
    }
}

# -------------------------------------------------------------------------------------------------------------------------------------------
# Function call example
# -------------------------------------------------------------------------------------------------------------------------------------------
# Sign_PSFile -filePath "$env:UserProfile\Downloads\aes_256.ps1" -TimestampServer "http://timestamp.digicert.com" -hash "sha256"


#############################################################################################################################################
# SIGN ANY FILE
#############################################################################################################################################
# -------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# -------------------------------------------------------------------------------------------------------------------------------------------
function Sign_ANYFile { param (
        [Parameter(Mandatory=$true)]
        [string]$filePath
    )

    # Load the file bytes
    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)

    # Compute SHA256 hash
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hash = $hasher.ComputeHash($fileBytes)

    # Get .PFX password 
    $pfxPassword = Read-Host -Prompt "Enter PFX password:" -AsSecureString
    
    # Get certificate with Document Signing EKU
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $configJSON.pfxPath,
        $pfxPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    )

    Add-Type -AssemblyName System.Security
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

    if (-not $rsa) {
        Write-Error "RSA private key could not be retrieved."
        return
    }

    # Hash + Sign Hash
    $signedHash = $rsa.SignHash(
        $hash,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    # Save signature to .sig file
    $sigPath = "$filePath.sig"
    [System.IO.File]::WriteAllBytes($sigPath, $signedHash)

    Write-Host "Signature saved to: $sigPath"
}

# -------------------------------------------------------------------------------------------------------------------------------------------
# Function call example
# -------------------------------------------------------------------------------------------------------------------------------------------
# Sign_ANYFile -filePath "$env:UserProfile\Downloads\doc.pdf"



