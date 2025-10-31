# LDAP


## LDAP Search Query Examples 
### Description
Example LDAP Search Queries 

##### LDAP Search Contains (!(userAccountControl:1.2.840.113556.1.4.803:=2))
userAccountControl
- This is the attribute in Active Directory that holds a set of bit flags (a single numerical value where each bit represents a different account setting).

:1.2.840.113556.1.4.803
- This is the Object Identifier (OID) for the LDAP_MATCHING_RULE_BIT_AND. It instructs the LDAP server to perform a bitwise AND operation between the attribute's current value and the search value.

:=2
- The decimal value 2 corresponds to the ADS_UF_ACCOUNTDISABLE bit flag. In binary, 2 is ...0010

!
- LDAP NOT Operator

### References
- https://ldapwiki.com/wiki/Wiki.jsp?page=LDAP%20Query%20Examples
- https://theitbros.com/ldap-query-examples-active-directory/
- https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7
- https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
- https://ldap.com/ldap-filters/
- https://datatracker.ietf.org/doc/html/rfc4515