# Process Creation (Sysmon EID 1)
Sysmon will log EventID 1 for the creation of any new process when it registers with the kernel.

Sysmon offers an advantage over the regular process logging in Windows since it not only pulls the same information 
as with EventID 4688 but it also pulls information from the PE header, hashes the images for correlation with IOC 
databases like Virus Total and it also provides unique fields when querying for events.

In Linux the advantage provided by Sysmon is that the data is structured in a wa that makes it easier to parse and 
leverage in a SIEM that leverages the logs. Bellow is an auditd example of the "ping -c 8.8.8.8" command.


| Delta           | Sysmon EID 1  | MDE DeviceProcessEvents |
|-----------------|---------------|-------------------------|
| process_cmdline | CommandLine   | ProcessCommandLine      |


## References
General Windows Process
- https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/process-events.md

Process Create Docs
- https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/process-creation.md
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001


MSFT Defender Endpoint - DeviceProcessEvents
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table