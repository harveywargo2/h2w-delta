# DSCL


## References
- https://www.real-world-systems.com/docs/dslocal.db.html
- https://www.loobins.io/binaries/dscl/
- https://ss64.com/mac/dscl.html

## Command Line

List users
```
dscl . list /Users UniqueID
```

Grep out users that start with _
```
dscl . list /Users UniqueID | grep -v ^_

```

List all local groups
```
dscl . list /Groups
```

Read Group
```
dscl . read /groups/admin
```

Check if a user is a member of a group
```
dseditgroup -o checkmember -m <username> <groupname>
```