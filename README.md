# Sigma playbooks (ES/EN)

Investigation playbooks in Spanish and English, with test events validated by a Sigma engine, for **3,759 of the 3,779 detection rules** in the `rules`, `rules-emerging-threats`, `rules-threat-hunting` and `rules-compliance` folders of [SigmaHQ](https://github.com/SigmaHQ/sigma) (commit `05d1031f`, 2026-10-21). They were made with the generator of [Centinela](https://github.com/DavidRamPari/centinela), a small open-source SIEM, and every test event was run through Centinela's engine.

## Coverage

| Folder | Rules | With a playbook | Fixtures passing | Rules whose fixtures all pass |
| --- | ---: | ---: | ---: | ---: |
| `rules` | 3,161 | 3,141 | 12,274 / 12,275 (99.9%) | 3,139 / 3,140 (99.9%) |
| `rules-emerging-threats` | 474 | 474 | 1,821 / 1,821 (100%) | 472 / 472 (100%) |
| `rules-threat-hunting` | 141 | 141 | 553 / 553 (100%) | 141 / 141 (100%) |
| `rules-compliance` | 3 | 3 | 12 / 12 (100%) | 3 / 3 (100%) |
| **Total** | **3,779** | **3,759** | **14,660 / 14,661 (99.9%)** | **3,755 / 3,756 (99.9%)** |

Fixtures are the test events that come with each playbook: positives must match the rule and negatives must not. 3 rules with a playbook use Sigma features Centinela's engine does not support, so their test events were not checked. One failing fixture cannot be fixed by rewriting it: the SigmaHQ rule *COM Object Execution via Xwizard.EXE* asks for a `CommandLine` that equals `RunWizard` and also contains a GUID, which no event can satisfy (it needs `CommandLine|contains`). The validation report of each folder, with every failing fixture and its reason, is in [`reports/`](reports).

## What each file contains

Each file in `content/` covers one rule (`content/<rule-id>.json`):

- `playbook.es` and `playbook.en`: summary, what the rule detects, why it matters, triage steps, false positives, response steps and why its level fits.
- `fixtures.positive` and `fixtures.negative`: events that should match the rule, and near misses that should not.
- `rule`: id, title, level, status, author, path, link and license, so every file keeps its attribution; `folder` names the SigmaHQ folder when it is not `rules`.
- `generated`: the tool, the model, the date and `"review": "unreviewed"`.

`index.csv` lists every file with its title, level, status, SigmaHQ folder and path, and ATT&CK techniques.

## How it was made

- Generated from 2026-10-25 to 2026-10-30 with `claude-opus-5-5` (effort `high`) through the Message Batches API, with Centinela's generator ([`tools/content-pack`](https://github.com/DavidRamPari/centinela/tree/main/tools/content-pack)).
- Rules whose answer failed got one retry. Fixtures that failed validation got one repair pass, which sends the rule, the failing fixture and the engine's error back to the model.
- Every fixture was validated with Centinela's Sigma engine (`npm run content:validate`).
- Total cost: about $162.
- 20 rules have no file. For 20 of them, Anthropic's safety filter stopped the answer (`stop_reason: refusal`): those rules detect offensive techniques, so their test events would have to contain attack command lines, and they were left out instead of working around the filter.
- The content is AI-generated and has not been reviewed by a person.

## Rules without content

| Rule | SigmaHQ path | Reason |
| --- | --- | --- |
| Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | safety filter (2 attempts) |
| Potential PHP Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.yml` | safety filter (2 attempts) |
| Potential Ruby Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml` | safety filter (2 attempts) |
| Invoke-Obfuscation VAR+ Launcher - PowerShell Module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_var.yml` | safety filter (2 attempts) |
| AMSI Bypass Pattern Assembly GetType | `rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml` | safety filter (2 attempts) |
| Invoke-Obfuscation Via Stdin - Powershell | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_stdin.yml` | safety filter (2 attempts) |
| DMSA Link Attributes Modified | `rules/windows/powershell/powershell_script/posh_ps_modification_of_dmsa_link_attribute.yml` | safety filter (2 attempts) |
| Potential Persistence Via Security Descriptors - ScriptBlock | `rules/windows/powershell/powershell_script/posh_ps_susp_ace_tampering.yml` | safety filter (2 attempts) |
| Veeam Backup Servers Credential Dumping Script Execution | `rules/windows/powershell/powershell_script/posh_ps_veeam_credential_dumping_script.yml` | safety filter (2 attempts) |
| HackTool - DInjector PowerShell Cradle Execution | `rules/windows/process_creation/proc_creation_win_hktl_dinjector.yml` | safety filter (2 attempts) |
| HKTL - SharpSuccessor Privilege Escalation Tool Execution | `rules/windows/process_creation/proc_creation_win_hktl_sharpsuccessor_execution.yml` | safety filter (2 attempts) |
| Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call | `rules/windows/process_creation/proc_creation_win_powershell_base64_reflection_assembly_load_obfusc.yml` | safety filter (2 attempts) |
| Assembly Loading Via CL_LoadAssembly.ps1 | `rules/windows/process_creation/proc_creation_win_powershell_cl_loadassembly.yml` | safety filter (2 attempts) |
| Potential Powershell ReverseShell Connection | `rules/windows/process_creation/proc_creation_win_powershell_reverse_shell_connection.yml` | safety filter (2 attempts) |
| Potential Privilege Escalation via Service Permissions Weakness | `rules/windows/process_creation/proc_creation_win_registry_privilege_escalation_via_service_key.yml` | safety filter (2 attempts) |
| Suspicious NTLM Authentication on the Printer Spooler Service | `rules/windows/process_creation/proc_creation_win_rundll32_ntlmrelay.yml` | safety filter (2 attempts) |
| Registry Modification of MS-settings Protocol Handler | `rules/windows/process_creation/proc_creation_win_susp_registry_modification_of_ms_setting_protocol_handler.yml` | safety filter (2 attempts) |
| UAC Bypass Using Disk Cleanup | `rules/windows/process_creation/proc_creation_win_uac_bypass_cleanmgr.yml` | safety filter (2 attempts) |
| UAC Bypass Using Event Viewer RecentViews | `rules/windows/process_creation/proc_creation_win_uac_bypass_eventvwr_recentviews.yml` | safety filter (2 attempts) |
| Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG | `rules/windows/registry/registry_set/registry_set_provisioning_command_abuse.yml` | safety filter (2 attempts) |

## License

The rules are © their authors and licensed under the Detection Rule License (DRL) 1.1. These playbooks and test events are derived from them and are shared under the same license (`LICENSE.Detection.Rules.md`). Every file names the rule's author and links to the rule.
