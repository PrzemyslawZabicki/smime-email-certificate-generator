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

    # Read file content
    $plainText = Get-Content $Path -Raw
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)

    # Create AES encryptor
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.GenerateIV()
    $iv = $aes.IV

    $encryptor = $aes.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

    # Combine IV + encrypted data
    $finalBytes = $iv + $encryptedBytes

    # Overwrite original file with encrypted content
    [System.IO.File]::WriteAllBytes($Path, $finalBytes)

    Write-Host "File encrypted in-place: $Path" -ForegroundColor Cyan
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
Lock-FileAES256 -Path "$PSScriptRoot\config.json"
Lock-FileAES256 -Path "$PSScriptRoot\smime-certreq.inf"