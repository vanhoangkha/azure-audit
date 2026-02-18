# Check NSG rules for dangerous open ports (22, 3389, 445)
param([string]$SubscriptionId, [string]$ResourceGroupName)

if ($SubscriptionId) { Set-AzContext -SubscriptionId $SubscriptionId | Out-Null }

$dangerousPorts = @(22, 3389, 445, 23, 3306, 1433, 5432)
$params = @{}
if ($ResourceGroupName) { $params.ResourceGroupName = $ResourceGroupName }

Get-AzNetworkSecurityGroup @params | ForEach-Object {
    $nsg = $_
    $_.SecurityRules | Where-Object { 
        $_.Direction -eq "Inbound" -and $_.Access -eq "Allow" -and
        ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "Internet")
    } | ForEach-Object {
        $port = $_.DestinationPortRange
        if ($port -eq "*" -or $dangerousPorts -contains [int]$port) {
            [PSCustomObject]@{
                NSG = $nsg.Name
                Rule = $_.Name
                Port = $port
                Source = $_.SourceAddressPrefix
                Risk = "HIGH"
            }
        }
    }
} | Format-Table -AutoSize
