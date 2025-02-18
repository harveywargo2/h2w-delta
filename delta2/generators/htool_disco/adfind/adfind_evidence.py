

_adfind_p0001_e01 = {
    "evidence_type": "emulation",
    "evidence_source": "atomic_red_team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md#atomic-test-4---adfind---enumerate-active-directory-ous",
    "ns_meta": {
        "guid": "d1c73b96-ab87-4031-bad8-0e1b3b8bf3ec",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''"path\AdFind.exe -f (objectcategory=organizationalUnit)"'''}
}


_adfind_p0002_e01 = {
    "type": "report",
    "source": "DFIR",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "date": "2020-05-08",
    "pattern_count": 1,
    "patterns": [{"process_command_line": r'''adFind.exe -sc trustdmp > trustdmp.txt'''}]
}


_adfind_p0001_e03 = {
    "type": "report",
    "source": "DFIR",
    "url": "https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/",
    "date": "2022-08-08",
    "pattern_count": 1,
    "patterns": [{"process_command_line": r'''adFind.exe -sc trustdmp > trustdmp.txt'''}]
}


_adfind_p0002_e01 = {
    "type": "emulation",
    "source": "Atomic Red Team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md#atomic-test-5---adfind---enumerate-active-directory-trusts",
    "date": "",
    "guid": "5fe436d-e771-4ff3-b655-2dca9ba52834",
    "pattern_count": 1,
    "patterns": [{"process_command_line": r'''"path\AdFind.exe -gcb -sc trustdmp"'''}]
}


_adfind_p0002_e02 = {
    "type": "report",
    "source": "DFIR",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "date": "2020-05-08",
    "pattern_count": 1,
    "patterns": [{"process_command_line": r'''adFind.exe -sc trustdmp > trustdmp.txt'''}]
}

_adfind_e03 = {
    "type": "report",
    "source": "DFIR",
    "url": "https://thedfirreport.com/2020/05/08/adfind-recon/",
    "date": "2020-05-08",
    "pattern_count": 8,
    "patterns": [
        {
            "process_command_line": r'''adFind.exe -f "(objectcategory=person)" > ad_users.txt'''
        },
        {
            "process_command_line": r'''adFind.exe -f "objectcategory=computer" > ad_computers.txt'''
        },
        {

        },
        {
            "process_command_line": r'''adFind.exe -sc domainlist > domainlist.txt'''
        },
        {
            "process_command_line": r'''adFind.exe -sc dcmodes > dcmodes.txt'''
        },
        {
            "process_command_line": r'''adFind.exe -sc adinfo > adinfo.txt'''
        },
        {
            "process_command_line": r'''adFind.exe -sc dclist > dclist.txt'''
        },
        {
            "process_command_line": r'''adFind.exe -sc computers_pwdnotreqd > computers_pwdnotreqd.txt'''
        }

    ]
}


