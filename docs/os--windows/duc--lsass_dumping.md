# LSASS
## LSASS = Local Security Authority Subsystem Service
### Description

Key Functions of LSASS
- User Authentication: LSASS verifies users logging on to a Windows computer or server by validating their credentials (like username and password).
- Security Policy Enforcement: It enforces local security policies, such as password complexity and account lockout rules.
- Access Token Creation: After successful authentication, it creates access tokens that determine the user's privileges and what resources they can access.
- Credential Management: For the purpose of enabling single sign-on (SSO) and other services, LSASS handles and stores various forms of user credential material (like password hashes and Kerberos tickets) in its memory.


Because LSASS holds sensitive credential data in memory, it is a high-value target for attackers.
- Credential Dumping: Adversaries who gain elevated privileges (like administrative access) on a system often target the LSASS process memory to "dump" or extract stored credentials, which they can then use to move laterally across a network and escalate their privileges. Tools like Mimikatz are known for this.
- System Integrity: LSASS is a critical system file. If the lsass.exe process is forcibly terminated, the system will often lose access to accounts and may automatically restart as a security measure.

### References
- https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service
- https://strontic.github.io/xcyclopedia/library/lsass.exe-03C70933698C6E3E466076DD9C3FAA18.html
- https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/
- https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication

How it Works 
- https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication


## TTPs & Intel 
### Description
List of Intel Links & Emulations

### References
Lsass Dumping TTPs
- https://threathunterplaybook.com/hunts/windows/170105-LSASSMemoryReadAccess/notebook.html
- https://redcanary.com/threat-detection-report/techniques/lsass-memory/
- https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
- https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before
- https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2


Atomic Red Team Emulation
- https://www.atomicredteam.io/atomic-red-team/atomics/T1003.001


## Shtinkering 
### Description
The term LSASS Shtinkering refers to a specific, stealthy technique used by attackers to perform LSASS credential dumping on a Windows system.

It is a novel way to bypass security defenses by forcing a legitimate system process, the Windows Error Reporting (WER) service, to create a dump file of the Local Security Authority Subsystem Service (LSASS) process.

Method
- Exploiting WER: The core of the technique involves an attacker with elevated privileges manipulating registry keys or calling Windows API functions to instruct the Windows Error Reporting (WER) service to generate a crash dump.
- Targeting LSASS: The attacker points the WER mechanism to the lsass.exe process. Because WER is designed to create diagnostic crash dumps of any process that fails, it has the necessary permissions to access the protected LSASS memory.
- Creating a Dump File: The WER service, executing as a legitimate system component, writes a full memory snapshot of the LSASS process to a local file, often placing it in a default location like the CrashDumps folder.
- Credential Theft: The attacker then retrieves this dump file and analyzes it offline using a tool to extract the cached credentials.


### References
- https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2
- https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf

Sigma
- https://detection.fyi/sigmahq/sigma/windows/process_access/proc_access_win_lsass_werfault/

## Getting LSASS Process ID
### Description 
Before Dumping LSASS TA Needs To Get PID

Powershell
```
((get-process lsass).id)
```

Cmd
```
for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""')
```

## LSASS Runs as SYSTEM
### Description
LSASS typically runs with SYSTEM-level privileges, and therefore, security teams can detect malicious use by identifying instances of LSASS running under any non-privileged user context. 
In order to do this, you’ll need the ability to collect users’ security identifiers (SID) for newly launched processes. 
Most endpoint monitoring solutions provide this as a metadata attribute associated with a process start record. 
Look at instances of LSASS running without a User SID including S-1-5-18.


## Common Tools 
### Description
Tools Used To Dump LSASS
- Mimikatz
- Cobalt Strike
- Impacket 
- Metasploit 
- Powersploit: Invoke-Mimikatz 
- Empire
- Dumpert
- Nanodump
- Procdump: Sysinternals
- PypyKatz

## Procdump Via -ma or -mm
### Description 
Full Dump
```
procdump -accepteula -ma <outputfile>
```

Mini Dump
```
procdump -accepteula -mm <outputfile>
```

## Nandump
### Description
Tool to create minidumps of LSASS
### References 
- https://github.com/fortra/nanodump

## LOL LSASS Dumping Via Rundll32 & Comsvcs MiniDump
### Description 

c:\windows\system32\comsvcs.dll
Notable Function Name : MiniDumpW -- Ordinal : 24 

```
"C:\Windows\System32\rundll32.exe"  C:\Windows\System32\comsvcs.dll MiniDump <LSASS PID> \Windows\Temp\<filename>.dmp full
```

```
rundll32.exe  comsvcs.dll,#24 600 C:\Users\user\Desktop\lsass.dmp full
```

```
powershell.exe -ExecutionPolicy Bypass -C "C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID>Get-Process lsass).id $env:TEMP\lsass-<filename>.dmp full"
```

### References 
- https://strontic.github.io/xcyclopedia/library/comsvcs.dll-67B51761A4BC3BD1B5367A22BA1A5B65.html
LOLBAS
- https://lolbas-project.github.io/lolbas/Libraries/comsvcs/
TTP Examples
- https://gist.github.com/JohnLaTwC/3e7dd4cd8520467df179e93fb44a434e
- https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
- https://hawk-eye.io/2022/09/tools-used-for-dumping-of-rdpcreds-via-comsvcs-dll/

Lsassy
- https://github.com/Hackndo/lsassy/blob/14d8f8ae596ecf22b449bfe919829173b8a07635/lsassy/dumpmethod/comsvcs.py 


## Manual Taskmgr Dump LSASS
### Description 
FileName: lsass.dmp

Defualt location is 
```
C:\Users\<YourUserName>\AppData\Local\Temp
```

