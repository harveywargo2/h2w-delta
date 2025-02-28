

def adfind_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('objectcategory=organizationalUnit', '-f')
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Adfind ObjectCategory Filter by OU Command",
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
        "title": "Adfind Trustdmp Command",
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
        "title": "Adfind Dclist Command",
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
        "title": "Adfind Domainlist Command",
        "mitre_technique": "",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0005(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'users_pwdnotreqd'
            and ProcessCommandLine has_any ('-gcb', '-sc')
        """
    query_json = {
        "delta": ["adfind-p0005--process_create-windows_any"],
        "title": "Adfind Users_PwdNotReqD Command",
        "mitre_technique": "",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0006(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has 'computers_pwdnotreqd'
            and ProcessCommandLine has_any ('-gcb', '-sc')
        """
    query_json = {
        "delta": ["adfind-p0006--process_create-windows_any"],
        "title": "Adfind Computers_PwdNotReqD",
        "mitre_technique": "",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0007(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('objectcategory=computer', '-f')
        """
    query_json = {
        "delta": ["adfind-p0007--process_create-windows_any"],
        "title": "Adfind ObjectCategory Filter By Computers Command",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0008(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('objectcategory=person', '-f')
        """
    query_json = {
        "delta": ["adfind-p0008--process_create-windows_any"],
        "title": "Adfind ObjectCategory Filter By Person Command",
        "mitre_technique": "t1087.002",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def adfind_p0009(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_any ('objectcategory=person', 'objectcategory=computer', 'objectcategory=subnet', 
                                            'objectcategory=organizationalUnit', 'domainlist', 'trustdmp', 'adinfo', 
                                            'dclist')
        | where ProcessCommandLine contains ' > '
            or ProcessCommandLine contains ' >> '
        """
    query_json = {
        "delta": ["adfind-p0009--process_create-windows_any"],
        "title": "Adfind Command Output Redirected to File",
        "mitre_technique": "",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json

