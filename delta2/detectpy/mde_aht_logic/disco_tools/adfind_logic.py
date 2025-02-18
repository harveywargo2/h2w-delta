

def adfind_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('objectcategory=organizationalUnit', '-f')
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Adfind Enumeration By ObjectCategory Filter by OU Command",
        "mitre_technique": "t1003",
        "mitre_sub_technique": "t1003.001",
        "query": query_text
        }

    return query_json


def adfind_p0002(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'trustdmp'
            and ProcessCommandLine has_any ('-gcb', '-sc', '-gc')
        """
    query_json = {
        "delta": ["adfind-p0002--process_create-windows_any"],
        "title": "Adfind Enumeration By Trustdmp Command",
        "mitre_technique": "t1482",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0003(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'dclist'
            and ProcessCommandLine has_any ('-gcb', '-sc', '-gc')
        """
    query_json = {
        "delta": ["adfind-p0003--process_create-windows_any"],
        "title": "Adfind Enumeration By Dclist Command",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0004(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'domainlist'
            and ProcessCommandLine has_any ('-gcb', '-sc')
        """
    query_json = {
        "delta": ["adfind-p0004--process_create-windows_any"],
        "title": "Adfind Enumeration By Domainlist Command",
        "mitre_technique": "",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0005(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_any ('pwdnotreqd', 'users', 'computers')
            and ProcessCommandLine has_any ('-gcb', '-sc')
        | where ProcessCommandLine contains 'users_pwdnotreqd'
            or ProcessCommandLine contains 'computers_pwdnotreqd'
        """
    query_json = {
        "delta": ["adfind-p0005--process_create-windows_any"],
        "title": "Adfind Enumeration By PwdNotReqD Command",
        "mitre_technique": "",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0006(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('objectcategory=computer', '-f')
        """
    query_json = {
        "delta": ["adfind-p0006--process_create-windows_any"],
        "title": "Adfind Enumeration By ObjectCategory Filter by Computer Command",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0007(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('objectcategory=person', '-f')
        """
    query_json = {
        "delta": ["adfind-p0007--process_create-windows_any"],
        "title": "Adfind Enumeration By ObjectCategory Filter by Person Command",
        "mitre_technique": "t1087.002",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json

