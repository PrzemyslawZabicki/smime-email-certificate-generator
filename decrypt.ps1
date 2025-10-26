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

    # Read encrypted file
    $allBytes = [System.IO.File]::ReadAllBytes($Path)

    # Extract IV and encrypted data
    $iv = $allBytes[0..15]
    $data = $allBytes[16..($allBytes.Length - 1)]

    # Decrypt
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $decryptor = $aes.CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($data, 0, $data.Length)
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
