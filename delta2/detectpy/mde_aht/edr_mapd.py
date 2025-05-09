def mdeedr_process_memory_dump(kql_ago='1d'):

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


def mdeedr(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Suspicious access to LSASS service'
        """
    query_json = {
        "delta": ["comsvcs-p0001--process_create-windows_any"],
        "title": "Suspicious access to LSASS service",
        "mitre_technique": ["T1003", "T1055", "T1550"],
        "mitre_sub_technique": ["T1003.001", "T1055.001", "T1055.002", "T1055.012", "T1550.002"],
        "query": query_text
        }

    return query_json


def mdeedr_sensitive_credential_memory_read(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Sensitive credential memory read'
        """
    query_json = {
        "delta": ["comsvcs-p0001--process_create-windows_any"],
        "title": "Sensitive credential memory read",
        "mitre_technique": ["T1003", "T1550"],
        "mitre_sub_technique": ["T1003.001", "T1550.002"],
        "query": query_text
        }

    return query_json


def mdeedr_adfind_tool_collecting_ad_info(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Adfind tool collecting Active Directory information'
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Adfind tool collecting Active Directory information",
        "mitre_technique": ["T1016", "T1018", "T1069", "T1087", "T1482"],
        "mitre_sub_technique": ["T1069.002", "T1087.002", "T1087.003"],
        "query": query_text
        }

    return query_json


def mdeedr_sus_ldap_query(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Suspicious LDAP query'
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Suspicious LDAP query",
        "mitre_technique": ["T1018", "T1033", "T1069", "T1082", "T1087", "T1135", "T1558"],
        "mitre_sub_technique": ["T1069.002", "T1087.002", "T1558.003", "T1087.003"],
        "query": query_text
        }

    return query_json


def mdeedr_uncommon_adfind_tool_launch(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Uncommon Adfind tool launch'
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Uncommon Adfind tool launch",
        "mitre_technique": ["T1016", "T1018", "T1069", "T1087", "T1482"],
        "mitre_sub_technique": "",
        "query": query_text
        }

    return query_json


def mdeedr_sensitive_info_theft_via_sam(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Sensitive information theft activity via Security Account Manager'
        """
    query_json = {
        "delta": ["certutil-p0001--process_create-windows_any"],
        "title": "Sensitive information theft activity via Security Account Manager",
        "mitre_technique": ["T1003", "T1012"],
        "mitre_sub_technique": ["T1003.002", "T1003.004", "T1003.005"],
        "query": query_text
        }

    return query_json


def mdeedr_attempt_to_steal_creds(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Possible attempt to steal credentials'
        """
    query_json = {
        "delta": [""],
        "title": "Possible attempt to steal credentials",
        "mitre_technique": ["T1003"],
        "mitre_sub_technique": [""],
        "query": query_text
        }

    return query_json


def mdeedr_suspicious_registry_export(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Suspicious registry export'
        """
    query_json = {
        "delta": [""],
        "title": "Suspicious registry export",
        "mitre_technique": ["T1003", "T1012", "T1074"],
        "mitre_sub_technique": ["T1074.001"],
        "query": query_text
        }

    return query_json


def mdeedr_malicious_pshell_cmdlet_invoked(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'A malicious PowerShell Cmdlet was invoked on the machine'
        """
    query_json = {
        "delta": [""],
        "title": "A malicious PowerShell Cmdlet was invoked on the machine",
        "mitre_technique": ["T1021", "T1059", "T1069", "T1087", "T1003", "T1555", "T1012", "T1135", "T1007"],
        "mitre_sub_technique": ["T1021.001", "T1059.001", "T1087.001", "T1055.003"],
        "query": query_text
        }

    return query_json


def mdeedr_sensitive_info_lookup(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Sensitive information lookup'
        """
    query_json = {
        "delta": [""],
        "title": "Sensitive information lookup",
        "mitre_technique": ["T1003", "T1012", "T1083", "T1552"],
        "mitre_sub_technique": ["T1552.001", "T1552.002"],
        "query": query_text
        }

    return query_json


def mdeedr_sensitive_info_extract_from_registry(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Sensitive data was extracted from registry'
        """
    query_json = {
        "delta": [""],
        "title": "Sensitive data was extracted from registry",
        "mitre_technique": ["T1003"],
        "mitre_sub_technique": ["T1003.002"],
        "query": query_text
        }

    return query_json


def mdeedr_reading_files_from_shadow_copies(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Reading files from volume shadown copies'
        """
    query_json = {
        "delta": [""],
        "title": "Reading files from volume shadow copies",
        "mitre_technique": ["T1003"],
        "mitre_sub_technique": ["T1003.002"],
        "query": query_text
        }

    return query_json


def mdeedr_powerview_script_detected(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'PowerView script detected'
        """
    query_json = {
        "delta": [""],
        "title": "PowerView script detected",
        "mitre_technique": ["T1482"],
        "mitre_sub_technique": [""],
        "query": query_text
        }

    return query_json


def mdeedr_suspicious_domain_trust_discovery(kql_ago='1d'):

    query_text = f"""AlertEvidence
        | where Timestamp >= ago({str(kql_ago)})
        | where Title =~ 'Suspicious Domain Trust Discovery'
        """
    query_json = {
        "delta": [""],
        "title": "Suspicious Domain Trust Discovery",
        "mitre_technique": ["T1482"],
        "mitre_sub_technique": [""],
        "query": query_text
        }

    return query_json