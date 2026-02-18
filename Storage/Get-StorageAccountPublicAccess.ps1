# Check Azure Storage Accounts for public blob access
param([string]$SubscriptionId, [string]$ResourceGroupName)

if ($SubscriptionId) { Set-AzContext -SubscriptionId $SubscriptionId | Out-Null }

$params = @{}
if ($ResourceGroupName) { $params.ResourceGroupName = $ResourceGroupName }

Get-AzStorageAccount @params | ForEach-Object {
    [PSCustomObject]@{
        StorageAccount = $_.StorageAccountName
        ResourceGroup = $_.ResourceGroupName
        AllowBlobPublicAccess = $_.AllowBlobPublicAccess
        Risk = if ($_.AllowBlobPublicAccess) { "HIGH" } else { "LOW" }
    }
} | Format-Table -AutoSize
