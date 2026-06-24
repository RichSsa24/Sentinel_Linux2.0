# Sentinel Detection Coverage

Mapping of Sentinel-Linux detections to MITRE ATT&CK®, NIST CSF 2.0, and D3FEND.

| Rule ID | Title | ATT&CK | NIST CSF | D3FEND |
|---|---|---|---|---|
| account-creation | Local account creation | T1136.001 | DE.CM | D3-PSA |
| base64-execution | Base64-decoded command execution | T1027 | DE.CM | D3-PSA |
| c2-beacon-port | Outbound connection to a known C2 port | T1571 | DE.AE | D3-NTA |
| cron-persistence | Cron-based persistence | T1053.003 | DE.CM, PR.PS | D3-FA |
| interactive-shell-spawn | Interactive shell spawned with -i | T1059.004 | DE.CM | D3-PSA |
| kernel-module-load | Kernel module load | T1547.006 | DE.CM | D3-PSA |
| log-tampering | Log file deleted | T1070.002 | DE.CM, PR.PS | D3-FA |
| new-listening-service | New listening service on an unexpected port | T1571 | DE.CM | D3-NTA |
| new-suid-binary | New or newly-setuid binary | T1548.001 | DE.CM | D3-FA |
| passwd-file-modified | Account database (/etc/passwd) modified | T1098 | DE.CM | D3-FA |
| reverse-shell-process | Reverse-shell-style process invocation | T1059.004 | DE.CM, DE.AE | D3-PSA |
| shadow-file-modified | Shadow password file modified | T1003.008 | DE.CM | D3-FA |
| ssh-brute-force | SSH brute-force login attempts | T1110 | DE.CM, DE.AE | D3-UBA |
| ssh-root-login | Successful SSH login as root | T1078.003 | DE.CM | D3-UBA |
| sudoers-modified | Sudoers policy modified | T1548.003 | DE.CM | D3-FA |
| suspicious-tmp-exec | Process executing from a temporary directory | T1059 | DE.CM | D3-PSA |
| world-writable-sensitive | World-writable file in a system path | T1222.002 | DE.CM | D3-FA |
