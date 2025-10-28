################################################################################################################################################################   
# ENCRYPT FILE
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Lock-FileAES256 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # Validate input file
    if (-not (Test-Path $Path)) {
        Write-Error "File not found: $Path"
        return
    }

    # Load AES key
    $keyPath = "$PSScriptRoot\aes_256.key"
    if (-not (Test-Path $keyPath)) {
        Write-Error "Encryption key not found at $keyPath"
        return
    }
    $key = [System.IO.File]::ReadAllBytes($keyPath)
    # If key was saved as Base64 instead of raw bytes:
    # $key = [Convert]::FromBase64String((Get-Content $keyPath -Raw))
    
    # Load AES IV
    $ivPath = "$PSScriptRoot\aes_256.iv"
    if (-not (Test-Path $ivPath)) {
        Write-Error "IV file not found at $ivPath"
        return
    }
    $iv = [System.IO.File]::ReadAllBytes($ivPath)
    # If iv was saved as Base64 instead of raw bytes:
    # $iv = [Convert]::FromBase64String((Get-Content $ivPath -Raw))
    
    # Read file content
    $plainText = Get-Content $Path -Raw
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)

    # Create AES encryptor
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV  = $iv

    $encryptor = $aes.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

    # Save encrypted data only (IV is already stored separately)
    [System.IO.File]::WriteAllBytes($Path, $encryptedBytes)

    Write-Host "File encrypted in-place using external IV: $Path" -ForegroundColor Cyan
}


# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
Lock-FileAES256 -Path "$PSScriptRoot\config.json"
Lock-FileAES256 -Path "$PSScriptRoot\smime-certreq.inf"