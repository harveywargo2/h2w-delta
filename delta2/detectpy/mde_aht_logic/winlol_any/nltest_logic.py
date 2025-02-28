

def nltest_p0001(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('nltest', '/dclist')
        """
    query_json = {
        "delta": ["nltest-p0001--process_create-windows_any"],
        "title": "Nltest DCLIST Command Run",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def nltest_p0002(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('nltest', '/domain_trusts')
        """
    query_json = {
        "delta": ["nltest-p0002--process_create-windows_any"],
        "title": "Nltest Domain Trust Command Run",
        "mitre_technique": "t1482",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def nltest_p0003(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('nltest', '/trusted_domains')
        """
    query_json = {
        "delta": ["nltest-p0003--process_create-windows_any"],
        "title": "Nltest Trusted Domains Command Run",
        "mitre_technique": "t1482",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def nltest_p0004(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('nltest', '/dsgetdc')
        """
    query_json = {
        "delta": ["nltest-p0004--process_create-windows_any"],
        "title": "Nltest /dsgetdc Command Run",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def nltest_p0005(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where ProcessCommandLine has_all ('nltest', '/dnsgetdc')
        """
    query_json = {
        "delta": ["nltest-p0005--process_create-windows_any"],
        "title": "Nltest /dnsgetdc Command Run",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def nltest_p0006(kql_ago='1d'):

    query_text = f"""DeviceProcessEvents
        | where Timestamp >= ago({str(kql_ago)})
        | where FileName !~ 'nltest.exe'
            and ProcessCommandLine !contains 'nltest'
            and ProcessCommandLine has_any ('/dclist', '/domain_trusts', '/trusted_domains', '/dsgetdc', '/dnsgetdc')
        """
    query_json = {
        "delta": ["nltest-p0005--process_create-windows_any"],
        "title": "Renamed Nltest File Ad Enum Command Run",
        "mitre_technique": ["t1018", "t1481"],
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json

