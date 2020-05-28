![xCyclopedia Logo](/assets/strontic-xcyclopedia-logo_full.png)

# xCyclopedia
Encyclopedia for Executables

## What is xCyclopedia?
The xCyclopedia project attempts to document all executables binaries (and eventually scripts) that reside on a typical operating system. It provides a machine-readable format of this data (e.g. JSON and CSV) so that it can be immediately usable in other systems such as SIEMs to enrich observed executions with contextual data.

## How is this done?
For Windows, this is done with a powershell script that iterates recursively through all directories and starts any executables found (note: the script is not released yet). It grabs the output from these, in search of helpful syntax messages. It also grabs a screenshot if a window is visible. The current version of this script only targets .exe's in C:\Windows, C:\Windows\System32\*, C:\Windows\SysWOW64\*, and C:\ProgramData\*.

### TODO
- Add more hashing algorithms
- Run on more versions of Windows (e.g. server)
- Convince a linux/macos guru to script this for other OS's :)
