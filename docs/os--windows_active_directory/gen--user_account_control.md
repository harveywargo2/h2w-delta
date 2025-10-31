# User Account Control
## User Account Control Flags 
### Description

Common Flags

ACCOUNTDISABLE
- Hex: 0x00000002
- Dec: 2
- Desc: The user account is disabled

PASSWD_NOTREQD
- Hex: 0x00000020
- Dec: 32
- Desc: No password required

NORMAL_ACCOUNT
- Hex: 0x00000200
- Dec: 512
- Desc: It's a default account type that represents a typical user

DONT_EXPIRE_PASSWORD
- Hex: 0x00010000
- Dec: 65536
- Desc: Represents the password, which should never expire on the account

### References 
- https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
- https://activedirectorypro.com/useraccountcontrol-check-and-manage-attribute-value/
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties