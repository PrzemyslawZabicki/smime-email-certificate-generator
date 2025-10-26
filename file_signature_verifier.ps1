################################################################################################################################################################
# FILE SIGNATURE VERIFIER
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Security
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Create the window
$form = New-Object System.Windows.Forms.Form
$form.Text = "File Signature Verification"
$form.Size = '500,360'
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(40,40,40)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.FormBorderStyle = 'FixedDialog'

# Variables to store file paths
$global:filePath = $global:sigPath = $global:certPath = $null

# Standard button size
$buttonSize = New-Object System.Drawing.Size(180,40)
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Create styled button
function New-StyledButton($text, $x, $y) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.Location = New-Object System.Drawing.Point($x, $y)
    $btn.Size = $buttonSize
    $btn.BackColor = [System.Drawing.Color]::FromArgb(50,50,50)
    $btn.ForeColor = [System.Drawing.Color]::White
    $btn.FlatStyle = 'Flat'
    $btn.FlatAppearance.BorderColor = [System.Drawing.Color]::Cyan
    $btn.FlatAppearance.BorderSize = 2
    $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(90,90,90)
    $btn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand

    # Optional: simulate 3D with slight padding
    $btn.Padding = '4,2,4,2'

    # Hover effects (manual override)
    $btn.Add_MouseEnter({
        $form.Cursor = [System.Windows.Forms.Cursors]::Hand
    })
    $btn.Add_MouseLeave({
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    })

    return $btn
}
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Create styled label
function New-StyledLabel($x, $y) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point($x, $y)
    $lbl.Size = '260,40'
    $lbl.ForeColor = [System.Drawing.Color]::White
    $lbl.BackColor = [System.Drawing.Color]::Transparent
    return $lbl
}
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Button + Label: Select file
$btnFile = New-StyledButton "Select file" 30 30
$lblFile = New-StyledLabel 220 30
$form.Controls.AddRange(@($btnFile, $lblFile))

# Button + Label: Select .sig file
$btnSig = New-StyledButton "Select .sig file" 30 80
$lblSig = New-StyledLabel 220 80
$form.Controls.AddRange(@($btnSig, $lblSig))

# Button + Label: Select certificate
$btnCert = New-StyledButton "Select certificate (.cer)" 30 130
$lblCert = New-StyledLabel 220 130
$form.Controls.AddRange(@($btnCert, $lblCert))

# Button: Verify signature
$btnVerify = New-StyledButton "Verify signature" 30 180
$form.Controls.Add($btnVerify)

# Result label
$resultBox = New-StyledLabel 30 230
$resultBox.Size = '440,60'
$form.Controls.Add($resultBox)

# Button actions
$btnFile.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Files (All)|*.*"
    if ($dialog.ShowDialog() -eq "OK") {
        $global:filePath = $dialog.FileName
        $lblFile.Text = [System.IO.Path]::GetFileName($filePath)
    }
})

$btnSig.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Signature files (*.sig)|*.sig"
    if ($dialog.ShowDialog() -eq "OK") {
        $global:sigPath = $dialog.FileName
        $lblSig.Text = [System.IO.Path]::GetFileName($sigPath)
    }
})

$btnCert.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Certificate files (*.cer)|*.cer"
    if ($dialog.ShowDialog() -eq "OK") {
        $global:certPath = $dialog.FileName
        $lblCert.Text = [System.IO.Path]::GetFileName($certPath)
    }
})

$btnVerify.Add_Click({
    if (-not ($global:filePath -and $global:sigPath -and $global:certPath)) {
        $resultBox.Text = "Please select all required files."
        return
    }

    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($global:filePath)
        $signedHash = [System.IO.File]::ReadAllBytes($global:sigPath)
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $hash = $hasher.ComputeHash($fileBytes)

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($global:certPath)
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)

        $isValid = $rsa.VerifyHash(
            $hash,
            $signedHash,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        $resultBox.Text = if ($isValid) {
            "Signature is valid."
            $resultBox.ForeColor = [System.Drawing.Color]::White
        } else {
            "Signature is NOT valid."
            $resultBox.ForeColor = [System.Drawing.Color]::White
        }
    } catch {
        $resultBox.Text = "❗ Error during verification: $_"
        $resultBox.ForeColor = [System.Drawing.Color]::White
    }
})

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
[void]$form.ShowDialog()
