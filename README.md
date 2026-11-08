# Azure Audit

PowerShell and shell scripts that collect Azure resource configuration to support security and compliance audits.

Each script reads configuration through the Azure APIs and exports it as a report you can review or attach to audit evidence. Most scripts only need **Reader** access to the subscriptions in scope.

## Contents

| Folder | Purpose |
| --- | --- |
| [`AppService/`](AppService) | Export App Service settings (minimum TLS version, HTTPS-only, FTPS state, local Git deployment) |
| [`AzureSecurityCenter/`](AzureSecurityCenter) | Export Microsoft Defender for Cloud (Security Center) pricing tiers, security contacts, auto-provisioning, workspace settings and connected security solutions |
| [`AzureSqlServer/`](AzureSqlServer) | Export SQL Server vulnerability assessment settings |
| [`KeyVault/`](KeyVault) | Purge soft-deleted Key Vaults (lab clean-up) |
| [`RoleAssignment/`](RoleAssignment) | List role assignments granted to VM managed identities |
| [`Subscription/`](Subscription) | Apply tags to subscriptions with a script or ARM template |
| [`VirtualMachine/`](VirtualMachine) | Export VM configuration, retrieve managed identity details, start/stop VMs in bulk |
| [`VirtualMachine/CVE-2020-0601/`](VirtualMachine/CVE-2020-0601) | Verify the CVE-2020-0601 (CryptoAPI spoofing) patch on Windows VMs via DSC |
| [`VirtualMachine/CVE-2020-0796/`](VirtualMachine/CVE-2020-0796) | Check and apply the CVE-2020-0796 (SMBv3 compression) mitigation |
| [`VirtualMachine/CustomScript/`](VirtualMachine/CustomScript) | Decode and inspect Custom Script Extension payloads |

## Prerequisites

- [Azure PowerShell](https://learn.microsoft.com/powershell/azure/install-azure-powershell) (some older scripts use the AzureRM module and are marked as such in their header)
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) for the `.sh` scripts
- An account with Reader access to the target subscriptions; write access only for scripts that change resources (tagging, VM start/stop, Key Vault purge)

## Usage

Sign in, then run a script with its required parameters. For example:

```powershell
Connect-AzAccount
./AppService/Get-AzureAppServiceInfo.ps1 -FileName AzureAppAudit -Path C:\Audit
```

Every script documents its parameters in the comment-based help at the top of the file:

```powershell
Get-Help ./AppService/Get-AzureAppServiceInfo.ps1 -Full
```

> **Warning:** `KeyVault/purge_all_keyvaults.sh` and `VirtualMachine/stop_start_all_vms.sh` change resources. Review them and run them only against subscriptions you intend to modify.

## Credits

Many of these scripts were originally written by [AzSec](https://azsec.azurewebsites.net/), as noted in each script's header. The CVE folders accompany the articles published there.

## License

Released under the MIT License. See [LICENSE](LICENSE).
