def msftedr_p0001(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Process memory dump'
        """
    query_json = {
        "delta": ["comsvcs-p0001--process_create-windows_any"],
        "title": "Process memory dump",
        "mitre_technique": ["t1003", "t1555"],
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def msftedr_p0002(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Suspicious access to LSASS service'
        """
    query_json = {
        "delta": ["comsvcs-p0001--process_create-windows_any"],
        "title": "Suspicious access to LSASS service",
        "mitre_technique": ["T1003","T1055","T1550"],
        "mitre_sub_technique": ["T1003.001","T1055.001","T1055.002","T1055.012","T1550.002"],
        "query": query_text
        }

    return query_json


def msftedr_p0003(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Sensitive credential memory read'
        """
    query_json = {
        "delta": ["comsvcs-p0001--process_create-windows_any"],
        "title": "Sensitive credential memory read",
        "mitre_technique": ["T1003","T1550"],
        "mitre_sub_technique": ["T1003.001","T1550.002"],
        "query": query_text
        }

    return query_json


def msftedr_p0004(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Adfind tool collecting Active Directory information'
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Adfind tool collecting Active Directory information",
        "mitre_technique": ["T1016","T1018","T1069","T1087","T1482"],
        "mitre_sub_technique": ["T1069.002","T1087.002","T1087.003"],
        "query": query_text
        }

    return query_json


def msftedr_p0005(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Suspicious LDAP query'
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Suspicious LDAP query",
        "mitre_technique": ["T1018","T1033","T1069","T1082","T1087","T1135","T1558"],
        "mitre_sub_technique": ["T1069.002","T1087.002","T1558.003", "T1087.003"],
        "query": query_text
        }

    return query_json


def msftedr_p0006(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Uncommon Adfind tool launch'
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Uncommon Adfind tool launch",
        "mitre_technique": ["T1016","T1018","T1069","T1087","T1482"],
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def msftedr_p0007(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Sensitive information theft activity via Security Account Manager'
        """
    query_json = {
        "delta": ["certutil-p0001--process_create-windows_any"],
        "title": "Sensitive information theft activity via Security Account Manager",
        "mitre_technique": ["T1003","T1012"],
        "mitre_sub_technique": ["T1003.002","T1003.004","T1003.005"],
        "query": query_text
        }

    return query_json