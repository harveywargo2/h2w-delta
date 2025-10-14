# Registry

## Description
The Windows registry is a centralized, hierarchical database that manages resources and stores configuration settings for applications on the Windows operating system. Security account services, user interfaces, and device drivers can all use the Windows registry.

**Registry keys** containers that act like folders, with values or subkeys contained within them. 
**Registry values** are similar to files (not containers).

Registry Structure
- Hives: contain keys (directories) and values 
- Keys: might contain subkeys and/or values 
- Subkeys: no difference between key and subkey structure 
- Values: store data

The main branches of the registry are called **hives**.
All the folders in the registry are called _keys_ except for these five hives.

The difference between HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER is 
- whether the referenced executable launches at startup for any user logging in
- or a specific user 
- (current_user is copied to a stored “user hive” and loaded whenever that user ID logs in)

#### AutoRuns
The registry run keys perform the same action, but can be located in four different locations:
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

Then there is `Run` and `RunOnce`
- the only difference is that `RunOnce` will automatically delete the entry upon successful execution.


## References
- https://medium.com/@nikhil.aniill/windows-registry-for-cybersecurity-beginners-63eebffb4049
- https://www.avast.com/c-windows-registry
- https://academy.tcm-sec.com/p/practical-windows-forensics
- https://github.com/Defenders-Guide/TheDefendersGuide/blob/main/Windows/Windows%20Registry/The_Defenders_Guide_to_the_Windows_Registry.md

AutoRuns
- https://www.cyborgsecurity.com/cyborg-labs/hunting-for-persistence-registry-run-keys-startup-folder/#:~:text=Persistence%2C%20especially%20amongst%20threat%20hunters%2C%20doesn%E2%80%99t%20often%20get,top%20hunts%20that%20hunt%20teams%20should%20focus%20on
- https://medium.com/@domdalcerro/run-key-persistence-threat-package-part-1-introduction-56e63140013b
- https://www.linkedin.com/pulse/windows-persistence-registry-run-keysstartup-folder-mangipudi
- https://alican-kiraz1.medium.com/threat-hunting-for-windows-registry-27778993e21b
- https://resources.infosecinstitute.com/topics/malware-analysis/common-malware-persistence-mechanisms/

Tools
- https://kurtzimmermann.com/regcoolext_en.html


#### RDP Registry Keys 
To disable Network Level Authentication (NLA) for Remote Desktop Protocol (RDP) through the registry, 
you need to modify the SecurityLayer and UserAuthentication values within the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp registry key. 
Setting both values to 0 disables NLA. Disabling NLA can weaken security and make your system more vulnerable to attacks. 
It is generally recommended to keep NLA enabled unless there is a specific reason, like compatibility issues, to disable it. 

Find the SecurityLayer value and change its data to 0 
Find the UserAuthentication value and change its data to 0



Intel
- https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf
- https://www.cisa.gov/sites/default/files/2024-11/aa23-136a-joint-csa-stopransomware-bianlian-ransomware-group.pdf
- https://thedfirreport.com/2024/08/26/blacksuit-ransomware/
- https://fixingitpro.com/2011/07/06/disabling-rdp-network-level-authentication-nla-remotely-via-the-registry/
