

def mdeav_rundlllolbin(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'rundlllolbin'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'rundlllolbin'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": ["comsvcs-p0001--process_create-windows_any"],
        "title": "RundllLolBin MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": "t10003.001",
        "query": query_text
        }

    return query_json


def mdeav_adfind(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'adfind'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'adfind'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": ["adfind-p0001--process_create-windows_any"],
        "title": "Adfind MDE Av Detection",
        "mitre_technique": ["t1482"],
        "mitre_sub_technique": "t10003.001",
        "query": query_text
        }

    return query_json


def mdeav_gsecdump(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'gsecdump'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'gsecdump'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Gsecdump MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001", "t1003.002"],
        "query": query_text
        }

    return query_json


def mdeav_presenoker(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'presenoker'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'presenoker'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "presenoker MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001", "t1003.002"],
        "query": query_text
        }

    return query_json


def mdeav_atpminidump(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'ATPMiniDump'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'ATPMiniDump'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "ATPMiniDump MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001"],
        "query": query_text
        }

    return query_json


def mdeav_dumplass(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'DumpLsass'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'DumpLsass'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "DumpLsass MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001"],
        "query": query_text
        }

    return query_json


def mdeav_poderscan(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'Posdercan'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'Posdercan'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Posdercan MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.002"],
        "query": query_text
        }

    return query_json


def mdeav_registryexfil(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'RegistryExfil'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'RegistryExfil'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "RegistryExfil MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.002"],
        "query": query_text
        }

    return query_json


def mdeav_mimikatz(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'Mimikatz'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'Mimikatz'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Mimikatz MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.002"],
        "query": query_text
        }

    return query_json


def mdeav_powersploit(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'Powersploit'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'Powersploit'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Powersploit MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001"],
        "query": query_text
        }

    return query_json


def mdeav_nanodump(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'nanodump'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'nanodump'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "Nanodump MDE Av Detection",
        "mitre_technique": ["t1003"],
        "mitre_sub_technique": ["t10003.001"],
        "query": query_text
        }

    return query_json


def mdeav_maleficams(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'MaleficAms'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'MaleficAms'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "MaleficAms MDE Av Detection",
        "mitre_technique": [""],
        "mitre_sub_technique": [""],
        "query": query_text
        }

    return query_json


def mdeav_lsassdump(kql_ago='1d'):

    query_text = f"""
        let AvAlertEvidence = materialize(
            AlertEvidence
            | where Timestamp >= ago({str(kql_ago)})
                and DetectionSource =~ 'Antivirus'
                and Title contains 'LsassDump'
        );
        let AvDeviceEvents = materialize(
            DeviceEvents
            | where Timestamp >= ago({str(kql_ago)})
                and ActionType in~ ('OtherAlertRelatedActivity', 'AntivirusDetection')
                and AdditionalFields contains 'LsassDump'
        );
        union AvAlertEvidence, AvDeviceEvents
        """
    query_json = {
        "delta": [""],
        "title": "LsassDump MDE Av Detection",
        "mitre_technique": [""],
        "mitre_sub_technique": [""],
        "query": query_text
        }

    return query_json