# Hierarchy


## References
- https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW14

Library
- https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW1

## MacOS Top Level Directories
/Library
- Purpose: Stores system-wide resources and supporting files that are shared by all users and applications.
- Content: Includes fonts, application support files, preferences (global settings), screen savers, system frameworks, plug-ins, etc.
- Note: This /Library is distinct from the ~/Library (your user's Library) and /System/Library. It contains resources available to all users on the machine.

/Applications
- Purpose: This is where applications (apps) designed for all users on the Mac are typically installed.
- Content: Contains applications like Safari, Mail, Pages, etc., as well as third-party applications you install.
- Note: You can also have an Applications folder inside your Home Directory (~/Applications) for apps specific to your user account.


/System
- Purpose: Contains the core macOS operating system files, frameworks, and essential resources.
- Content: This directory is crucial for the operation of macOS. It includes system applications, kernel extensions, core frameworks, and other fundamental components.
- Security: Since macOS Catalina (10.15) and later, the /System volume is sealed and read-only due to System Integrity Protection (SIP). This prevents unauthorized modification of critical system files, enhancing security and stability. You generally cannot (and should not) modify anything directly within this folder.

/Users
- Purpose: Contains the home directories for all user accounts on the Mac.
- Content: Each user on the system has a dedicated folder here, named after their short username (e.g., /Users/yourusername).
- Home Directory (~ or /Users/yourusername): This is your personal workspace. 
  - Inside your home directory, you'll find:
    - Desktop
    - Documents
    - Downloads
    - Library(hidden)
    - Public
    - Movies/Music/Pictures

## Unix Standard Top-Level Directories
/bin
/sbin
/etc
/tmp
/user
/var
/dev
/Volumes
/private