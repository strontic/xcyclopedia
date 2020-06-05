![xCyclopedia Logo](/assets/strontic-xcyclopedia-logo_full.png)

# xCyclopedia
Encyclopedia for Executables

## What is xCyclopedia?
The xCyclopedia project attempts to document all executables binaries (and eventually scripts) that reside on a typical operating system. It provides a machine-readable format of this data (e.g. JSON and CSV) so that it can be immediately usable in other systems such as SIEMs to enrich observed executions with contextual data.

## What Datapoints are Available?

* File name
* File path
* Runtime data (Standard Out, Standard Error, Children Processes, Screenshots -- if window is visible)
* File hashes (MD5, SHA1, SHA256, SHA384, SHA512)
* Fuzzy file hash (ssdeep)
* Digital signature validity and associated metadata (Serial, Thumbprint, Issuer, Subject)
* File metadata (File Description, Original File Name, Product Name, Comments, Company Name, File Version, Product Version, Copyright)

## How is this done?
For Windows, this is done with a powershell script that iterates recursively through all directories and starts any executables found (*note: the script is now released!*). It grabs the output from these, in search of helpful syntax messages. It also grabs a screenshot if a window is visible.

## Where is this data stored?

See [strontic-xcyclopedia.json](strontic-xcyclopedia.json). (Note: a CSV file will be made available soon. I'm currently having problems with formatting.)

## Script Usage

### Example
```powershell
Get-Xcyclopedia -save_path "c:\temp\strontic-xcyclopedia" -target_path "$env:windir\system32" -target_file_extension ".exe"
````

### TODO
- ~~Add more hashing algorithms~~
- ~~Run on more versions of Windows (e.g. server)~~
- ~~Upload script~~
- Convince a linux/macos guru to script this for other OS's :)
