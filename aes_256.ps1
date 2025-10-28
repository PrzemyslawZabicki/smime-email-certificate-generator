################################################################################################################################################################   
# CREATE ENCRYPTION KEY
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
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
# Exe. 
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
Set-AES256Key
