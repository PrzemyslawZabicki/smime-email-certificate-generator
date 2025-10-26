################################################################################################################################################################
# MICROSOFT WINDOWS API DOCUMENTATION
################################################################################################################################################################

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Def.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
function Get-Microsoft_Windows_API() {
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

################################################################################################################################################################
# LINKS DEFINITION
################################################################################################################################################################
$links = @(
    "https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate",
    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1",
    "https://learn.microsoft.com/en-us/powershell/module/",
    "https://learn.microsoft.com/en-us/windows/win32/api/",
    "https://learn.microsoft.com/en-us/windows/win32/api/_security/",
    "https://www.microsoft.com/en-us/msrc/"
)

################################################################################################################################################################
# CREATE WINDOWS
################################################################################################################################################################
$form = New-Object Windows.Forms.Form
$form.Text = "MICROSOFT WINDOWS SECURITY API"
$form.Size = New-Object Drawing.Size(720,520)
$form.BackColor = [Drawing.Color]::FromArgb(20,20,20)
$form.StartPosition = "CenterScreen"

################################################################################################################################################################
# CREATE LIST VIEW OBJECT
################################################################################################################################################################
$listView = New-Object Windows.Forms.ListView
$listView.View = 'Details'
$listView.FullRowSelect = $true
$listView.HeaderStyle = 'None'

$listView.Size = New-Object Drawing.Size(675,320)
$listView.Location = New-Object Drawing.Point(14,14)
$listView.Font = New-Object Drawing.Font("Tahoma", 11, [Drawing.FontStyle]::Regular)
$listView.BackColor = [Drawing.Color]::Black
$listView.ForeColor = [Drawing.Color]::White
$listView.Columns.Add("Links", 680)

################################################################################################################################################################
# ADD LINK TO LISTVIEW OBJECT
################################################################################################################################################################
foreach ($link in $links) {
    $item = New-Object Windows.Forms.ListViewItem($link)
    $listView.Items.Add($item)
}

$form.Controls.Add($listView)

################################################################################################################################################################
# BUTTON DEFINITION
################################################################################################################################################################
$button = New-Object Windows.Forms.Button
$button.Text = "CLOSE"
$button.Size = New-Object Drawing.Size(675,50)
$button.Location = New-Object Drawing.Point(15,380)
$button.Font = New-Object Drawing.Font("Tahoma", 13, [Drawing.FontStyle]::Bold)
$button.FlatStyle = 'Flat'
$button.BackColor = [Drawing.Color]::Black
$button.ForeColor = [Drawing.Color]::DeepPink
$button.FlatAppearance.BorderColor = [Drawing.Color]::Peru
$button.FlatAppearance.BorderSize = 2
$form.Controls.Add($button)

################################################################################################################################################################
# MOUSE CLICK EVENT
################################################################################################################################################################
$button.Add_Click({
    $selected = $listView.SelectedItems
    if ($selected.Count -gt 0) {
        Start-Process $selected[0].Text
        
    } 
    $form.Close()  
      #else 
      #{
      #[Windows.Forms.MessageBox]::Show("Please select a link first.","No Selection",[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Warning)
      #}
})

# Mouse hover ON: change to hand cursor
$button.Add_MouseEnter({
    $form.Cursor = [System.Windows.Forms.Cursors]::Hand
})

# Mouse hover OFF: reset to default cursor
$button.Add_MouseLeave({
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
})

################################################################################################################################################################
# MOUSE MOVE EVENT ON HOVER
################################################################################################################################################################
$listView.Add_MouseClick({
    param($source, $e)

    # Use HitTest to get the exact item under the cursor
    $hit = $listView.HitTest($e.Location)

    # Open the link only if a valid item was clicked
    if ($hit -and $null -ne $hit.Item) {
        $url = $hit.Item.Text
        if ($url -match '^https?://') {
            Start-Process $url
        }
    }
})

$listView.Add_MouseMove({
    param($source, $e)
    $hovering = $false

    foreach ($item in $listView.Items) {
        $rect = $item.GetBounds('Entire')
        if ($rect.Contains($e.Location)) {
            $item.ForeColor = [System.Drawing.Color]::DeepPink
            $hovering = $true
        } else {
            $item.ForeColor = [System.Drawing.Color]::White
        }
    }

# Change cursor based on hover state
if ($hovering) {
    $form.Cursor = [System.Windows.Forms.Cursors]::Hand
} else {
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
}
})

################################################################################################################################################################
# RUN WINDOWS FORM
################################################################################################################################################################
$form.TopMost = $true
$form.Activate()
$form.ShowDialog()
}

# --------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exe.
# --------------------------------------------------------------------------------------------------------------------------------------------------------------
Get-Microsoft_Windows_API
