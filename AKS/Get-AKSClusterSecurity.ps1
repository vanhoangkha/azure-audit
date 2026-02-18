# Check AKS clusters for security configurations
param([string]$SubscriptionId, [string]$ResourceGroupName)

if ($SubscriptionId) { Set-AzContext -SubscriptionId $SubscriptionId | Out-Null }

$params = @{}
if ($ResourceGroupName) { $params.ResourceGroupName = $ResourceGroupName }

Get-AzAksCluster @params | ForEach-Object {
    $issues = @()
    if (-not $_.EnableRBAC) { $issues += "RBAC disabled" }
    if (-not $_.NetworkProfile.NetworkPolicy) { $issues += "No network policy" }
    if (-not $_.ApiServerAccessProfile.EnablePrivateCluster) { $issues += "Public API" }
    
    [PSCustomObject]@{
        Cluster = $_.Name
        ResourceGroup = $_.ResourceGroupName
        RBAC = $_.EnableRBAC
        NetworkPolicy = $_.NetworkProfile.NetworkPolicy
        PrivateCluster = $_.ApiServerAccessProfile.EnablePrivateCluster
        Issues = ($issues -join ", ")
        Risk = if ($issues.Count -gt 1) { "HIGH" } elseif ($issues.Count -eq 1) { "MEDIUM" } else { "LOW" }
    }
} | Format-Table -AutoSize
