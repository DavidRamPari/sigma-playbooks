# Sigma playbooks (ES/EN)

Investigation playbooks in Spanish and English, plus test events, for 3,141 of the 3,161 detection rules in the main `rules/` folder of [SigmaHQ](https://github.com/SigmaHQ/sigma) (commit `05d1031f`, 2026-10-21).

Each file in `content/` covers one rule (`content/<rule-id>.json`):

- `playbook.es` and `playbook.en`: summary, what the rule detects, why it matters, triage steps, false positives, response steps and why its level fits.
- `fixtures.positive` and `fixtures.negative`: events that should match the rule, and near misses that should not.
- `rule`: id, title, level, status, author, link and license, so every file keeps its attribution.

`index.csv` lists every file with its title, level, SigmaHQ path and ATT&CK techniques.

## How it was made

- Generated on 2026-10-25 with `claude-opus-5-5` (effort `high`) through the Message Batches API, with the generator in [Centinela](https://github.com/DavidRamPari/centinela) (`tools/content-pack`).
- Each rule had up to two attempts. Total cost: about $135.
- 20 rules have no file: Anthropic's safety filter stopped the answer in both attempts (`stop_reason: refusal`). Those rules detect offensive techniques, so their test events would have to contain attack command lines; they were left out instead of working around the filter.
- The content is AI-generated and has not been reviewed by a person. The test events are being checked with Centinela's Sigma engine; until that report is published, treat them as unverified.

## Rules without content

| Rule | SigmaHQ path | Reason |
| --- | --- | --- |
| Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | safety filter |
| Potential PHP Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.yml` | safety filter |
| Potential Ruby Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml` | safety filter |
| Invoke-Obfuscation VAR+ Launcher - PowerShell Module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_var.yml` | safety filter |
| AMSI Bypass Pattern Assembly GetType | `rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml` | safety filter |
| Invoke-Obfuscation Via Stdin - Powershell | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_stdin.yml` | safety filter |
| DMSA Link Attributes Modified | `rules/windows/powershell/powershell_script/posh_ps_modification_of_dmsa_link_attribute.yml` | safety filter |
| Potential Persistence Via Security Descriptors - ScriptBlock | `rules/windows/powershell/powershell_script/posh_ps_susp_ace_tampering.yml` | safety filter |
| Veeam Backup Servers Credential Dumping Script Execution | `rules/windows/powershell/powershell_script/posh_ps_veeam_credential_dumping_script.yml` | safety filter |
| HackTool - DInjector PowerShell Cradle Execution | `rules/windows/process_creation/proc_creation_win_hktl_dinjector.yml` | safety filter |
| HKTL - SharpSuccessor Privilege Escalation Tool Execution | `rules/windows/process_creation/proc_creation_win_hktl_sharpsuccessor_execution.yml` | safety filter |
| Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call | `rules/windows/process_creation/proc_creation_win_powershell_base64_reflection_assembly_load_obfusc.yml` | safety filter |
| Assembly Loading Via CL_LoadAssembly.ps1 | `rules/windows/process_creation/proc_creation_win_powershell_cl_loadassembly.yml` | safety filter |
| Potential Powershell ReverseShell Connection | `rules/windows/process_creation/proc_creation_win_powershell_reverse_shell_connection.yml` | safety filter |
| Potential Privilege Escalation via Service Permissions Weakness | `rules/windows/process_creation/proc_creation_win_registry_privilege_escalation_via_service_key.yml` | safety filter |
| Suspicious NTLM Authentication on the Printer Spooler Service | `rules/windows/process_creation/proc_creation_win_rundll32_ntlmrelay.yml` | safety filter |
| Registry Modification of MS-settings Protocol Handler | `rules/windows/process_creation/proc_creation_win_susp_registry_modification_of_ms_setting_protocol_handler.yml` | safety filter |
| UAC Bypass Using Disk Cleanup | `rules/windows/process_creation/proc_creation_win_uac_bypass_cleanmgr.yml` | safety filter |
| UAC Bypass Using Event Viewer RecentViews | `rules/windows/process_creation/proc_creation_win_uac_bypass_eventvwr_recentviews.yml` | safety filter |
| Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG | `rules/windows/registry/registry_set/registry_set_provisioning_command_abuse.yml` | safety filter |

## License

The rules are © their authors and licensed under the Detection Rule License (DRL) 1.1. These playbooks and test events are derived from them and are shared under the same license (`LICENSE.Detection.Rules.md`). Every file names the rule's author and links to the rule.
