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