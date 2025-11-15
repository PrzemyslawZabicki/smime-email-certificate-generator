################################################################################################################################################################   
# CREATE ENCRYPTION KEY
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def. Create aes-256 key and initialization vector iv and save both key+iv to disk
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Set-AES256Key {
    # Create AES instance
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.GenerateKey()
    $aes.GenerateIV()

    # Save raw key and IV as binary files
    [System.IO.File]::WriteAllBytes("$PSScriptRoot\aes_256.key", $aes.Key)
    [System.IO.File]::WriteAllBytes("$PSScriptRoot\aes_256.iv",  $aes.IV)

    # Save raw key and IV as Base64 String
    # [System.IO.File]::WriteAllText("$PSScriptRoot\aes_256.key", [Convert]::ToBase64String($aes.Key))
    # [System.IO.File]::WriteAllText("$PSScriptRoot\aes_256.iv",  [Convert]::ToBase64String($aes.IV))


    Write-Host "AES-256 key saved to aes_256.key" -ForegroundColor Cyan
    Write-Host "AES IV saved to aes_256.iv" -ForegroundColor Cyan
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def. Create AES-256 key and saves it to Windows Credential Manager
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Save-AesKeyToSecretManager {
    param(
        [string]$SecretName = "pfxKey"
    )

    # Ensure SecretManagement and SecretStore modules are available
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) {
        Write-Host "Installing SecretManagement..."
        Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser -Force
    }
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretStore)) {
        Write-Host "Installing SecretStore..."
        Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force
    }

    Import-Module Microsoft.PowerShell.SecretManagement
    Import-Module Microsoft.PowerShell.SecretStore

    # Register SecretStore as default vault if none exists
    if (-not (Get-SecretVault)) {
        Register-SecretVault -Name MySecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
        Write-Host "SecretStore registered as default vault."
    }

    # Generate random 256-bit AES key (32 bytes)
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $key = New-Object byte[] 32
    $rng.GetBytes($key)

    # Save key as a secret
    Set-Secret -Name $SecretName -Secret $key

    Write-Host "AES key saved in SecretStore under name '$SecretName'"
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def. Save - Encrypt PFX password blob
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Save-PfxPasswordBlob {
    param(
        [string]$SecretName = "pfxKey",
        [string]$BlobPath = "$PSScriptRoot\pfxPass"
    )

    Import-Module Microsoft.PowerShell.SecretManagement

    # Retrieve AES key from SecretStore
    $key = Get-Secret -Name $SecretName
    if (-not $key) {
        throw "Secret '$SecretName' not found. Run Save-AesKeyToSecretManager first."
    }

    # Prompt for PFX password securely
    $securePassword = Read-Host "Enter PFX password" -AsSecureString

    # Save encrypted blob to file
    $securePassword | ConvertFrom-SecureString -Key $key | Out-File $BlobPath

    Write-Host "PFX password encrypted and saved to $BlobPath"
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def. Load - Decrypt PFX password blob
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Get-PfxPasswordForExport {
    param(
        [string]$SecretName = "pfxKey",
        [string]$BlobPath = "$PSScriptRoot\pfxPass"
    )

    Import-Module Microsoft.PowerShell.SecretManagement

    # Retrieve AES key from SecretStore
    $key = Get-Secret -Name $SecretName
    if (-not $key) {
        throw "Secret '$SecretName' not found."
    }

    # Load encrypted blob and decrypt
    $securePassword = Get-Content $BlobPath | ConvertTo-SecureString -Key $key

    return $securePassword
}


