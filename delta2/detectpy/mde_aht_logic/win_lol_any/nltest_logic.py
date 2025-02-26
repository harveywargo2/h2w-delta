
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
        | where ProcessCommandLine has 'nltest'
            and ProcessCommandLine has_any ('/domain_trusts', '/trusted_domains')
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
        | where ProcessCommandLine has_all ('nltest', '/dsgetdc')
        """
    query_json = {
        "delta": ["nltest-p0003--process_create-windows_any"],
        "title": "Nltest /dsgetdc Command Run",
        "mitre_technique": "t1018",
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


