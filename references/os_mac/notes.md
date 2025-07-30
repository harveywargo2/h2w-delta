/Library
Significance/Usage:
- This folder contains resources and support files that are shared by all users on the Mac. These are not user-specific files but rather system-wide resources.

Application Support: Many applications store their shared support files, plugins, and preferences here (e.g., /Library/Application Support).

System-Wide Preferences: Contains preference files that apply to all users (e.g., /Library/Preferences).

Fonts: System-wide fonts are stored here (/Library/Fonts).

Audio: System-wide audio components and sounds (/Library/Audio).

LaunchDaemons and LaunchAgents: Background processes and agents that run at system startup or login for all users (/Library/LaunchDaemons, /Library/LaunchAgents).

Internet Plug-Ins: Browser plug-ins that are available to all users (/Library/Internet Plug-Ins).

Printers: Printer drivers and related files (/Library/Printers).

Distinction from ~/Library: It's important to distinguish /Library (system-wide) from ~/Library (user-specific, located within your home directory, often hidden by default). ~/Library contains preferences, caches, and application support files specific to your user account.

/System
Significance/Usage:
This is arguably the most critical folder as it contains the core macOS operating system files. These files are essential for the Mac to boot up and function correctly.

Core Operating System Files: Contains frameworks, libraries, kernel extensions (KEXTs), and executables that make up macOS.

System Integrity Protection (SIP): Since macOS El Capitan, this folder is heavily protected by System Integrity Protection (SIP). This means even with administrator privileges, users and most software cannot modify or delete files within this folder directly. This is a crucial security feature to prevent malware from compromising the core OS and to ensure system stability.

Updates: macOS updates primarily modify files within this folder.

Read-Only Access: For security and stability, the /System folder is typically mounted as read-only.

Examples of Contents:

/System/Library: Contains most of the critical frameworks, kernel extensions, and other system-level components. This is the most significant subfolder within /System.

/System/Applications: Contains core macOS applications that are essential for the system's basic functionality (e.g., Finder, Terminal). These are distinct from user-installed applications in /Applications.

In summary:

/Applications: Where most user-installed applications reside.

/Library: Contains resources and support files shared by all users.

/System: Contains the core operating system files, protected by SIP, and essential for macOS functionality.