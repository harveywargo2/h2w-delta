
def powerview_g0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine contains 'Get-NetDomainTrust'
            or ProcessCommandLine contains 'Get-NetForestTrust'
            or ProcessCommandLine contains 'Get-DomainTrust'
            or ProcessCommandLine contains 'Get-Forest'
            or ProcessCommandLine contains 'Invoke-MapDomainTrust'
            or ProcessCommandLine contains 'Get-DomainTrustMapping'
        """
    query_json = {
        "delta": [""],
        "title": "PowerView Domain Trust CmdLet",
        "mitre_technique": ["t1482"],
        "mitre_sub_technique": [""],
        "query": query_text
        }

    return query_json


def powerview_g0002(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine contains 'Find-GPO'
            or ProcessCommandLine contains 'Get-NetGPO'
            or ProcessCommandLine contains 'Get-DomainGPO'
            or ProcessCommandLine contains 'Get-DomainPolicy'
        """
    query_json = {
        "delta": [""],
        "title": "PowerView GPO CmdLet",
        "mitre_technique": ["t1615"],
        "mitre_sub_technique": [""],
        "query": query_text
        }

    return query_json


def powerview_g0003(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine contains 'Invoke-ACLSScan'
            or ProcessCommandLine contains 'Find-InterestingDomain'
            or ProcessCommandLine contains 'Add-Object'
            or ProcessCommandLine contains 'Get-Object'
            or ProcessCommandLine contains 'Get-ADObject'
            or ProcessCommandLine contains 'Get-DomainObject'
            or ProcessCommandLine contains 'Set-DomainObject'
            or ProcessCommandLine contains 'Find-DomainObject'
            or ProcessCommandLine contains 'Get-Forest'
            or ProcessCommandLine contains 'Get-NetForest'
            or ProcessCommandLine contains 'Get-NetDomainController'
            or ProcessCommandLine contains 'Get-DomainController'
            or ProcessCommandLine contains 'Get-NetOU'
            or ProcessCommandLine contains 'Get-DomainOU'
            or ProcessCommandLine contains 'Get-Domain'
            or ProcessCommandLine contains 'Get-NetDomain'
        """
    query_json = {
        "delta": [""],
        "title": "PowerView Domain Object AD Enum CmdLet",
        "mitre_technique": ["t1018"],
        "mitre_sub_technique": [""],
        "query": query_text
        }

    return query_json

