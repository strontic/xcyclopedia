![xCyclopedia Logo](/assets/strontic-xcyclopedia-logo.png "xCyclopedia")

# xCyclopedia
Encyclopedia for Executables

## What is xCyclopedia?
The xCyclopedia project attempts to document all executable binaries (and eventually scripts) that reside on a typical operating system. Currently, this includes all observed EXE and DLL files, as well as COM Objects *(new!)*. It provides a [web page](https://strontic.github.io/xcyclopedia) to view the data as well as a [machine-readable format](/output) (JSON and CSV) that can be immediately usable in other systems such as SIEMs to enrich observed executions with contextual data.

## What data points are available?

* Runtime data (Standard Out, Standard Error, Children Processes, Screenshots, Open Handles, Loaded Modules, Window Title)
* File metadata (File Description, Original File Name, Product Name, Comments, Company Name, File Version, Product Version, Copyright, PE Machine Type)
* Digital signature validity and associated metadata (Serial, Thumbprint, Issuer, Subject)
* File hashes (MD5, SHA1, SHA256, SHA384, SHA512, IMP, PESHA1, PE256)
* Fuzzy file hash (ssdeep)
* Similar files* (available on [xCyclopedia web page](https://strontic.github.io/xcyclopedia) only)
* External References* (available on [xCyclopedia web page](https://strontic.github.io/xcyclopedia) only)
  * Examples of misuse (e.g. malicious use of legitimate executable)
  * Microsoft Documentation
* File scan results (VirusTotal)
* DLL Exported Functions (DLL files only)
* (NEW!) COM Objects (CLSID, Friendly Names, Mappings to EXE/DLLs, Exposed methods/properties, other metadata) - Gathered via [Get-ComObjects.ps1](script/Get-ComObjects)

## How is this done?

The results provided in the [output](/output) directory were gathered in virtual machines of various Windows OS versions and patch levels (currently a very manual process). For your own usage, it is always recommended these scripts be first executed in test environments.

### Get-Xcyclopedia
The [Get-Xcyclopedia](script/Get-Xcyclopedia.ps1) script iterates recursively through all directories and starts any executables found. It then gathers a multitude of artifacts (which is slowly being improved). For example, it grabs the command line output, in search of helpful syntax messages. And if a window is visible, it will take a screenshot.

### Get-ComObjects
The [Get-ComObjects](script/Get-ComObjects.ps1) script iterates through each CLSID and enumerates its associated registry keys and exposed methods/properties. 

## Where is this data stored?

#### JSON/CSV
For the machine-readable data (JSON & CSV):
* EXE Data
  * [strontic-xcyclopedia.json.zip](output/strontic-xcyclopedia.json.zip)
  * [strontic-xcyclopedia.csv.zip](output/strontic-xcyclopedia.csv.zip)
* DLL Data
  * [strontic-xcyclopedia_DLL.json.zip](output/strontic-xcyclopedia_DLL.json.zip)
  * [strontic-xcyclopedia_DLL.csv.zip](output/strontic-xcyclopedia_DLL.csv.zip)
* COM-Object Data
  * [strontic-xcyclopedia_COM.json.zip](output/strontic-xcyclopedia_COM.json.zip)

#### Web Page (Markdown)
For a web-based view of the data click here: [strontic.github.io/xcyclopedia](https://strontic.github.io/xcyclopedia). *Note: the web view includes a few bonus features that the JSON/CSV files do not currently include; namely the following:*
* Examples of known malicious use of a given executable (current sources: [atomic-red-team](https://github.com/redcanaryco/atomic-red-team), [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS), [malware-ioc](https://github.com/eset/malware-ioc), [Sigma](https://github.com/Neo23x0/sigma), and [Signature-Base](https://github.com/Neo23x0/signature-base))
* File comparisons/similarities (using [ssdeep](https://github.com/ssdeep-project/ssdeep/releases/tag/release-2.14.1))
* Relevant [Microsoft documentation](https://github.com/MicrosoftDocs/windowsserverdocs).

## Can I collect this data myself?

Sure! The powershell scripts are [here](/script)! See syntax/usage section below.

## Collector Script Usage

### Syntax

 ```powershell
  Get-Xcyclopedia
  #Synopsis: Iterate through all executable files in a specified directory (default target is .EXE). Gather CLI usage/syntax, screenshots, file hashes, file metadata, signature validity, and child processes.
    -save_path                  #path to save output
    -target_path                #target path for enumerating files (non-recursive). Comma-delimited for multiple paths.
    -target_path_recursive      #target path for enumerating files (recursive). Comma-delimited for multiple paths.
    -target_file_extension      #File extension to target (default = ".exe")
    -execute_files    [bool]    #Execute each for gathering syntax/usage info (stdout/stderr)
    -take_screenshots [bool]    #Take a screenshot if a given process has a window visible. This requires execute_files to be enabled.
    -minimize_windows [bool]    #Minimizing windows helps with screenshots, so that other windows do not get in the way. This only takes effect if execute_files and $take_screenshots are both enabled.
    -xcyclopedia_verbose   [bool] #Verbose Output
    -transcript_file       [bool] #Write console output to a file (job.txt)
    -export_ssdeep_list    [bool] #Export ssdeep results to a ssdeep-compatible csv file
    -export_ssdeep_list_with_md5 [bool] #Include MD5 with ssdeep file export. Useful for determining similarity of unique files.
    -get_sigcheck          [bool] #Use Sigcheck (Sysinternals) to obtain additional file signatures and PE metadata.
    -get_virustotal        [bool] #Use Sigcheck (Sysinternals) to obtain VirusTotal detection ratio. It does NOT submit file by default.
    -accept_virustotal_tos [bool] #Accept VirusTotal's Terms of Service (https://www.virustotal.com/en/about/terms-of-service/)
    -path_to_file_arg1            #This filepath will be provided as an argument to each binary (to test their response to a file being provided as input)
    -path_to_file_arg2            #This filepath will be provided as an argument to each binary (to test their response to a file being provided as input)
    -convert_to_csv        [bool] #CSV export is enabled by default but can be disabled if desired -- JSON will always be exported.

  Coalesce-Json
    #Synopsis: Combine JSON files into a single file. Only works with PowerShell-compatible JSON files.
    -target_files          #List of JSON files (comma-delimited) to combine. NOTE: The first file listed takes precedence in case of duplicates.
    -save_path             #Path to save the combined JSON file.
    -verbose_output [bool]
    -save_json      [bool] #Save file as JSON
    -save_csv       [bool] #Save file as CSV
    
  Get-ComObjects
    #Iterate through all COM Objects by CLSID. Gather ProgIDs, File Paths, Descriptions, and any other data present in the Classes Root. COM Methods can also be collected. Saves as JSON and CSV.
    -save_path              #path to save output
    -transcript_file [bool] #Write console output to a file (job.txt)
    -create_instance [bool] #UNSAFE! System crash may occur. When enabled, a COM instance is created for CLSID. This is required for determining COM methods.
    -verbose         [bool]
````

### Example
```powershell
Get-Xcyclopedia -save_path "c:\xCyclopedia\out\" -target_path "$env:windir\system32" -target_file_extension ".exe"
Coalesce-Json -save_path "c:\xCyclopedia\out\" -target_files "c:\temp\A.json","c:\temp\B.json"
Get-ComObjects -save_path "c:\xCyclopedia\out\" -create_instance $true
````

### **Optional** Dependencies:
* *ssdeep*: For obtaining ssdeep fuzzy hashes (useful for finding similar files). You must extract the ssdeep ZIP file (available [here](https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1-win32-binary.zip)) into a subfolder called "bin/ssdeep-2.14.1".
* *Sysinternals Handle*: For obtaining the open handles of a given process. You must place `handle64.exe` (available [here](https://docs.microsoft.com/en-us/sysinternals/downloads/handle)) in a subfolder called "bin/sysinternals/handle".
* *Sysinternals Sigcheck*: For obtaining additional file hashes, VirusTotal detections, and PE machine-type. You must place `sigcheck64.exe` (available [here](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck)) in a subfolder called "bin/sysinternals/sigcheck".
* *DLL Export Viewer*: For obtaining Exported Functions from DLLs. You must place `dllexp.exe` (available [here](https://www.nirsoft.net/utils/dll_export_viewer.html)) in a subfolder called "bin/dllexp-x64".

## How can I contribute?
* Share it with friends
* Provide feedback

## TODO
- Convince a linux/macos guru to script this for other OS's :)
- Use a more reliable method for determining children processes (and for stopping them)
- Use Logman.exe (or equivalent) to determine which ETW providers are being populated by a given process.
- Use SilkETW (or equivalent) for vastly improved runtime metadata gathering. 
- Identify runtime deltas in different executable versions. (e.g. when a new command-line switch is added to the standard output)
