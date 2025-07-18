# caffeinate

## References
- https://www.loobins.io/binaries/caffeinate/
- https://ss64.com/mac/caffeinate.html

Blog
- https://james.brooks.page/blog/macos-caffeinate-command
- https://www.theapplegeek.co.uk/blog/caffeinate

Example
- https://stackoverflow.com/questions/48041791/using-caffeinate-command-in-macos
- https://superuser.com/questions/770151/how-do-i-use-caffeinate-to-prevent-my-computer-from-sleeping-while-a-script-runs
- https://osxdaily.com/2014/06/16/caffeinate-prevent-sleep-while-command-active-mac-os-x/
- https://macperformanceguide.com/blog/2021/20210927_1306-macOS-caffeinate-git-push.html

Mitre Attack
- https://attack.mitre.org/techniques/T1653/

## Notable

To prevent a Mac from sleeping while running a script, use the caffeinate command with the -i flag to inhibit idle sleep and the -w flag to wait for the script to finish. 
For example: 
```
caffeinate -i -w $$ your_script.sh. 
```
The $$ represents the current process ID, ensuring caffeinate stays active until the script completes. 


You can also use caffeinate in utility mode, where you don't need to provide a pid, but a utility that should be executed. 
E.g. wrap your work in a shell script mywork.sh and:
```
caffeinate -disu mywork.sh
```

Fork/Pin to Process
```
caffeinate -i [command / process]
caffeinate -i ssh coffeebeans &
caffeinate -i make
caffeinate -i /private/tmp/./whatisthis.sh
caffeinate -i /Applications/Safari.app/Resources/MacOS/Safari
caffeinate -d telnet towel.blinkenlights.nl
```

AI Generated Examples
```
caffeinate -i python3 my_long_script.py
nohup caffeinate -i &
caffeinate -i &
caffeinate -i <your_command_here>
```

Command Flags
Flag -d 
- Prevents the display from sleeping, even if the system is idle. The display will remain on, but the system may still go to sleep.  

Flag -i
- Prevents the system from going into idle sleep. The system will stay awake, but the display might still sleep if idle.  

Flag -m
- Prevents the hard drive from going to sleep. This is useful for tasks that involve disk access.

Flag -s 
- Prevents the system from sleeping when it is connected to AC power. This is a more forceful sleep prevention than -i.   

Flag -t
- <timeout> Sets a timeout in seconds for the caffeinate command. After the timeout expires, caffeinate will exit, and the system will revert to its normal sleep behavior. For example, caffeinate -t 3600 will prevent sleep for one hour. 

Flag -u
- Declares user activity, which also prevents sleep. If the display is off, this option will turn it on and prevent it from sleeping for the specified timeout (defaulting to 5 seconds if not used with -t). 

Flag -w
- <pid> Prevents the system from sleeping until the process with the specified process ID (PID) exits. This is useful for preventing sleep while a specific long-running process is active. 


From the Mac developer library, the differences between idle sleep and (forced) sleep are:
- Forced sleep occurs when the user takes some sort of direct action to cause the machine to sleep. Closing the lid on a laptop or selecting sleep from the Apple menu both cause forced sleep. The system will also induce forced sleep under certain conditions, for example, a thermal emergency or a low battery.
- Idle sleep occurs when the machine is unused for a specific period of time configured in the Energy Saver System Preferences