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