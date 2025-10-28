################################################################################################################################################################   
# DECRYPT FILE
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Unlock-FileAES256 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    # Validate encrypted file
    if (-not (Test-Path $Path)) {
        Write-Error "Encrypted file not found: $Path"
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

    # Read encrypted file
    $cipherBytes = [System.IO.File]::ReadAllBytes($Path)

    # Decrypt
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV  = $iv
    $decryptor = $aes.CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
    $plainText = [System.Text.Encoding]::UTF8.GetString($plainBytes)

    # Write result to output file
    [System.IO.File]::WriteAllText($OutputPath, $plainText)

    Write-Host "Decryption complete. Output saved to: $OutputPath" -ForegroundColor Cyan
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
Unlock-FileAES256 -Path "$PSScriptRoot\config.json" -OutputPath "$PSScriptRoot\config.json"
Unlock-FileAES256 -Path "$PSScriptRoot\smime-certreq.inf"  -OutputPath "$PSScriptRoot\smime-certreq.inf"
