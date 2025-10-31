# Named Pipes

## General Overview Of Named Pipes on Windows

A named pipe is a named, one-way or duplex pipe for communication between the pipe server and one or more pipe clients. 
All instances of a named pipe share the same pipe name, but each instance has its own buffers and handles, and provides a separate conduit for client/server communication. 
The use of instances enables multiple pipe clients to use the same named pipe simultaneously.

Any process can access named pipes, subject to security checks, making named pipes an easy form of communication between related or unrelated processes.

Any process can act as both a server and a client, making peer-to-peer communication possible. 
As used here, the term pipe server refers to a process that creates a named pipe, and the term pipe client refers to a process that connects to an instance of a named pipe. 
The server-side function for instantiating a named pipe is CreateNamedPipe. 
The server-side function for accepting a connection is ConnectNamedPipe. 
A client process connects to a named pipe by using the CreateFile or CallNamedPipe function.

### References
MSFT Official
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea
- https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-instances


## Pipe Naming 
### Description 
Each named pipe has a unique name that distinguishes it from other named pipes in the system's list of named objects. 
A pipe server specifies a name for the pipe when it calls the CreateNamedPipe function to create one or more instances of a named pipe. 
Pipe clients specify the pipe name when they call the CreateFile or CallNamedPipe function to connect to an instance of the named pipe.

Use the following form when specifying the name of a pipe in the CreateFile, WaitNamedPipe, or CallNamedPipe function:

\\ServerName\pipe\PipeName
- ServerName is either the name of a remote computer or a period, to specify the local computer. 
- The pipe name string specified by PipeName can include any character other than a backslash, including numbers and special characters. 
- The entire pipe name string can be up to 256 characters long. Pipe names are not case-sensitive.

The pipe server cannot create a pipe on another computer, so CreateNamedPipe must use a period for the server name, as shown in the following example.
\\.\pipe\PipeName

Known Windows Pipes
- \pipe\atsvc:Used by the Task Scheduler service (specifically the legacy "AT" command) for remotely creating scheduled tasks.  
- \pipe\epmapper:The Endpoint Mapper service, used for dynamic RPC. It helps RPC clients find the dynamic port number of an RPC service.
- \pipe\InitShutdown: Used for system shutdown and restart procedures.
- \pipe\ntsvcs: Used by the Distributed Link Tracking: Workstation Protocol.
- \pipe\spoolss: Used by the Print System Remote Protocol to handle printing services.
- \pipe\trkwks: Used by the Distributed Link Tracking: Workstation Protocol.
- \pipe\winreg: Used for the Windows Remote Registry service. 
- \pipe\lsarpc: Manages access to the Local Security Authority (LSA) database. It is used to enumerate privileges, SIDs, trust relationships, and security policies.
- \pipe\samr: Provides access to the Security Account Manager (SAM) database, allowing for enumeration of local users and groups. On modern Windows versions, anonymous access is typically restricted.
- \pipe\netlogon: Used for domain-related operations, including user and machine authentication in an Active Directory environment.
- \pipe\svcctl: Used by the Service Control Manager (SCM) to remotely manage services, such as creating, starting, and stopping them.
- \pipe\wkssvc: Used by the Workstation Service Remote Protocol. 

### References
Pipe Naming
- https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names


## Named Pipe Inspection Tools
### Description 
References to tools to retrieve & do investigation on named pipes

Sysinternals
- PipeList
- PSFile 
```
grep named pipes with | findstr pipe
```

Powershell
```
[System.IO.Directory]::GetFiles("\\.\\pipe\\") or Get-ChildItem \\.\pipe\
```

### Reference
- https://github.com/cyberark/PipeViewer
- https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist

## Evidence & Intel 
### Description 
Collection of Articles & Intel

Threat Hunting Suspicious Named Pipes
- https://detect.fyi/threat-hunting-suspicious-named-pipes-a4206e8a4bc8
- https://www.elastic.co/security-labs/detecting-and-responding-to-dirty-pipe-with-elastic
- https://bherunda.medium.com/hunting-detecting-smb-named-pipe-pivoting-lateral-movement-b4382bd1df4
- https://bherunda.medium.com/hunting-named-pipe-token-impersonation-abuse-573dcca36ae0

C2 Pivoting With Named Pipes
- https://www.cobaltstrike.com/blog/named-pipe-pivoting
- https://havocframework.com/docs/pivoting
- https://sliver.sh/docs?name=Pivots
- https://github.com/nettitude/PoshC2/blob/master/resources/modules/Invoke-Pbind.ps1
- https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html
- https://sliver.sh/docs?name=Pivots

Monitoring Data
- https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/named-pipes.md

IOC Named Pipes
- https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_named_pipe_list.csv

Custom Cobalt Strike Named Pipes
- https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575
- https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/

Open Source Detection Repos
- https://research.splunk.com/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/

