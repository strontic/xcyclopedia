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

### Syntax

 ```powershell
  Get-Xcyclopedia
  #Synopsis: Iterate through all executable files in a specified directory (default target is .EXE). Gather CLI usage/syntax, screenshots, file hashes, file metadata, signature validity, and child processes.
    -save_path                        #path to save output
    -target_path                      #target path for enumerating files (non-recursive). Comma-delimited for multiple paths.
    -target_path_recursive            #target path for enumerating files (recursive). Comma-delimited for multiple paths.
    -target_file_extension            #File extension to target (default = ".exe")
    -execute_files    [$true|$false]  #Execute each for gathering syntax/usage info (stdout/stderr)
    -take_screenshots [$true|$false]  #Take a screenshot if a given process has a window visible. This requires execute_files to be enabled.
    -minimize_windows [$true|$false]  #Minimizing windows helps with screenshots, so that other windows do not get in the way. This only takes effect if execute_files and $take_screenshots are both enabled.
    -xcyclopedia_verbose [$true|$false] #Verbose Output
    -transcript_file  [$true|$false]  #Write console output to a file (job.txt)

  Coalesce-Json
    #Synopsis: Combine JSON files into a single file. Only works with PowerShell-compatible JSON files.
    -target_files                   #List of JSON files (comma-delimited) to combine.
    -save_path                      #Path to save the combined JSON file.
    -verbose_output [$true|$false]
    -save_json      [$true|$false]  #Save file as JSON (recommended)
    -save_csv       [$true|$false]  #Save file as CSV
````

### Example
```powershell
Get-Xcyclopedia -save_path "c:\temp\strontic-xcyclopedia" -target_path "$env:windir\system32" -target_file_extension ".exe"
````

### **Optional** Dependencies:
*ssdeep*: For obtaining ssdeep fuzzy hashes (useful for finding similar files) then you must extract the ssdeep ZIP file (available [here](https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1-win32-binary.zip)) into a subfolder called "ssdeep-2.14.1".

### TODO
- ~~Add more hashing algorithms~~
- ~~Run on more versions of Windows (e.g. server)~~
- ~~Upload script~~
- Convince a linux/macos guru to script this for other OS's :)
