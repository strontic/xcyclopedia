<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Synopsis: Iterate through all executable files in a specified directory (default target is .EXE). Gather CLI usage/syntax, screenshots, file hashes, file metadata, signature validity, and child processes.
    Warning: Please be advised, if execute_files is enabled, this script may cause system instability, crash, or unwanted reboot/shutdown. Use this option at your own risk.
    License: MIT License; Copyright (c) 2020 strontic
#>

function Get-Xcyclopedia {

    # set-executionpolicy unrestricted -force

    param (
        [string]$save_path = "c:\temp\strontic-xcyclopedia", #path to save output
        [string[]]$target_path_recursive = @("$env:windir\system32","$env:windir\SysWOW64","$env:ProgramData"), #target path for recursive dir
        [string[]]$target_path = @("$env:windir"), #target path for NON-recursive dir
        [string]$target_file_extension = ".exe", #File extension to target
        [bool]$execute_files = $true,    # In order for syntax/usage info to be gathered (stdout/stderr), the files must be executed.
        [bool]$take_screenshots = $false, # Take a screenshot if a given process has a window visible. This requires execute_files to be enabled.
        [bool]$minimize_windows = $false, # Minimizing windows helps with screenshots, so that other windows do not get in the way. This only takes effect if execute_files and $take_screenshots are both enabled.
        [bool]$xcyclopedia_verbose = $true,
        [bool]$transcript_file = $true # Write console output to a file (job.txt)
    )

    $comment = [PSCustomObject]@{
        author = '@strontic20'
        website = 'strontic.com'
        github = 'github.com/strontic/xcyclopedia'
        synopsis = 'Gather metadata of executables'
        license = 'MIT License; Copyright (c) 2020 strontic'
        rundate = Get-Date -Format "yyyy-MM-dd"
    }

    # Define the header names. This is only used for export to CSV file -- not JSON. 
    #  If the header name is not defined here, or it does not match the name defined in the file_object, then it will no be included.
    $header = [PSCustomObject]@{
        file_name = $null
        file_path = $null
        hash_md5 = $null
        hash_sha1 = $null
        hash_sha256 = $null
        hash_sha384 = $null
        hash_sha512 = $null
        hash_ssdeep = $null
        signature_status = $null
        signature_status_message = $null
        signature_serial = $null
        signature_thumbprint = $null
        signature_issuer = $null
        signature_subject = $null
        meta_description = $null
        meta_original_filename = $null
        meta_product_name = $null
        meta_comments = $null
        meta_company_name = $null
        #meta_file_name = $null
        meta_file_version = $null
        meta_product_version = $null
        #meta_isdebug = $null
        #meta_ispatched = $null
        #meta_isprerelease = $null
        #meta_isprivatebuild = $null
        #meta_isspecialbuild = $null
        meta_language = $null
        meta_legal_copyright = $null
        meta_legal_trademarks = $null
        #meta_private_build = $null
        #meta_special_build = $null
        #meta_file_version_raw = $null
        #meta_product_version_raw = $null
		output = $null
		error = $null
		children = $null
    }

    # Create directory where files will be saved
    New-Item -ItemType Directory -Force -Path "$save_path" | Out-Null

    # Get Date
    $time = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"

    # Start transcript
    if($transcript_file) {
        try { Stop-Transcript } catch{}
        Start-Transcript "$save_path\$time-job.txt"
    }
    
    if($take_screenshots) { 
        $screenshot_dir = "$save_path\$time-screenshots" 
        
        #Create directory for screenshots
        New-Item -ItemType Directory -Force -Path "$screenshot_dir" | Out-Null
    }

    # If window minimization is enabled,check if user wants to continue, 
    if($minimize_windows -AND $execute_files) { $minimize_windows = PromptUser-Minimization }
    
    # Specify list of arguments to be executed
    $args_list = @("/?","/h","-help","help")

    #Import Modules
    Import-LocalModule Get-Ssdeep
    Import-LocalModule Get-Screenshot
    Import-LocalModule Start-ProcessGetOutput

    # Get directory listing of specified directories (comma delimited) and file extension
    $files = $null
    $files = Get-FileList -path_recursive $target_path_recursive  -path_normal $target_path -file_extension "$target_file_extension"

    # Blacklisted Args - Arguments to skip (NOTE: $true = skip ALL arguments, i.e. do not execute that file)
    $arg_filters = [PSCustomObject]@{}
    $arg_filters | Add-Member -NotePropertyName "makecab.exe" -NotePropertyValue "help" # Avoids large erroneous output
    $arg_filters | Add-Member -NotePropertyName "shutdown.exe" -NotePropertyValue "/h" # Avoids hibernation
    $arg_filters | Add-Member -NotePropertyName "csrss.exe" -NotePropertyValue "$true" # Avoids freezing the script.
    $arg_filters | Add-Member -NotePropertyName "LsaIso.exe" -NotePropertyValue "$true" # Avoids BSOD
    $arg_filters | Add-Member -NotePropertyName "lsass.exe" -NotePropertyValue "$true" # Avoids BSOD
    $arg_filters | Add-Member -NotePropertyName "rdpinit.exe" -NotePropertyValue "$true" # Avoids BSOD
    $arg_filters | Add-Member -NotePropertyName "rdpinput.exe" -NotePropertyValue "$true" # Avoids BSOD
    $arg_filters | Add-Member -NotePropertyName "SlideToShutDown.exe" -NotePropertyValue "$true" # Avoids explorer crash
    $arg_filters | Add-Member -NotePropertyName "FirstLogonAnim.exe" -NotePropertyValue "$true" # Avoids possible reboots
    $arg_filters | Add-Member -NotePropertyName "smss.exe" -NotePropertyValue "$true" # Avoids freezing the script.
    $arg_filters | Add-Member -NotePropertyName "WindowsActionDialog.exe" -NotePropertyValue "$true" # Avoids possible reboot
    $arg_filters | Add-Member -NotePropertyName "WindowsUpdateElevatedInstaller.exe" -NotePropertyValue "$true" # Avoids possible reboot
    $arg_filters | Add-Member -NotePropertyName "wininit.exe" -NotePropertyValue "$true" # Avoids possible reboot

    $file_objects = [PSCustomObject]@{}
    $file_objects | Add-Member  -NotePropertyName header -NotePropertyValue $header
    $file_objects | Add-Member  -NotePropertyName comment -NotePropertyValue $comment

    #for minimizing stray windows
    $shell = New-Object -ComObject "Shell.Application"

    # Iterate through all EXE files.
    $i = 0
    foreach ($file in $files) {

        ## TESTING ##
        #Test for screenshot:
        #$filename = "notepad.exe"; $filepath = "c:\windows\system32\notepad.exe"
        #Test for stdout:
        #$filename = "ping.exe"; $filepath = "c:\windows\system32\ping.exe"
        #Test for unicode characters (1):
        #$filename = "sfc.exe"; $filepath = "C:\WINDOWS\system32\sfc.exe"
        #Test for unicode characters (2):
        #$filename = "arp.exe"; $filepath = "C:\WINDOWS\system32\arp.exe"
        #Test for child processes:
        #$filename = "write.exe"; $filepath = "C:\WINDOWS\system32\write.exe"
        #Test for stdout size comparison (/? vs /h):
        #$filename = "certutil.exe"; $filepath = "C:\WINDOWS\system32\certutil.exe"
        #Test for argument filter (certain makecab args will cause very large output)
        #$filename = "makecab.exe"; $filepath = "C:\WINDOWS\system32\makecab.exe"
        #Test for sihost spawning explorer, which can be inadvertently killed, causing unexpected behavior.
        #$filename = "sihost.exe"; $filepath = "C:\WINDOWS\system32\sihost.exe"
        #Test for script freeze
        #$filename = "DiskSnapshot.exe"; $filepath = "C:\WINDOWS\system32\DiskSnapshot.exe"
        #Test for handling of null file metadata
        #$filename = "AgentService.exe"; $filepath = "C:\WINDOWS\system32\AgentService.exe"
        #Test for handling of stray windows (i.e. minimizing them)
        #$filename = "calc.exe"; $filepath = "C:\WINDOWS\system32\calc.exe"

        $filename = $file.name
        $filepath = $file.fullname
        $filehash_md5 = $file_description = $file_metadata = $null

        # Get file metadata
        $file_metadata = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filepath)
    
        #Get file hashes
        try {
            $filehash_md5 = (Get-FileHash $filepath -Algorithm MD5).Hash
            $filehash_sha1 = (Get-FileHash $filepath -Algorithm SHA1).Hash
            $filehash_sha256 = (Get-FileHash $filepath -Algorithm SHA256).Hash
            $filehash_sha384 = (Get-FileHash $filepath -Algorithm SHA384).Hash
            $filehash_sha512 = (Get-FileHash $filepath -Algorithm SHA512).Hash
        }
        catch { 
            Write-Host "File Hash: FAILED"
            $filehash_md5 = "00000000000000000000000000000000"
            if($xcyclopedia_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
        }

        #Get file signature data (e.g. validity)
        $file_signature = Get-AuthenticodeSignature -FilePath "$filepath"

        #Get ssdeep fuzzy hashes
        try {
            $filehash_ssdeep = Get-Ssdeep -filepath $filepath -ssdeep_verbose $xcyclopedia_verbose
        }
        catch {
            $filehash_ssdeep = "$null"
            if($xcyclopedia_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
        }

        ### Assign all gathered values to pscustomobject, file_object
        $file_object = $null
        $file_object = [PSCustomObject]@{}

        #Add file names
        $file_object | Add-Member  -NotePropertyName file_name -NotePropertyValue $filename
        $file_object | Add-Member  -NotePropertyName file_path -NotePropertyValue $filepath
        
        #Add file hashes (from Get-FileHash and Get-Ssdeep)
        $file_object | Add-Member  -NotePropertyName hash_md5 -NotePropertyValue $filehash_md5
        $file_object | Add-Member  -NotePropertyName hash_sha1 -NotePropertyValue $filehash_sha1
        $file_object | Add-Member  -NotePropertyName hash_sha256 -NotePropertyValue $filehash_sha256
        $file_object | Add-Member  -NotePropertyName hash_sha384 -NotePropertyValue $filehash_sha384
        $file_object | Add-Member  -NotePropertyName hash_sha512 -NotePropertyValue $filehash_sha512
        $file_object | Add-Member  -NotePropertyName hash_ssdeep -NotePropertyValue $filehash_ssdeep

        #Add file signature data (from Get-AuthenticodeSignature)
        $file_object | Add-Member  -NotePropertyName signature_status -NotePropertyValue $file_signature.Status
        $file_object | Add-Member  -NotePropertyName signature_status_message -NotePropertyValue $file_signature.StatusMessage
        $file_object | Add-Member  -NotePropertyName signature_serial -NotePropertyValue $file_signature.SignerCertificate.SerialNumber
        $file_object | Add-Member  -NotePropertyName signature_thumbprint -NotePropertyValue $file_signature.SignerCertificate.Thumbprint
        $file_object | Add-Member  -NotePropertyName signature_issuer -NotePropertyValue $file_signature.SignerCertificate.Issuer
        $file_object | Add-Member  -NotePropertyName signature_subject -NotePropertyValue $file_signature.SignerCertificate.Subject

        #Add file metadata (from GetVersionInfo)
        if($file_metadata.FileDescription)  { $file_object | Add-Member  -NotePropertyName meta_description -NotePropertyValue $file_metadata.FileDescription }
        if($file_metadata.OriginalFilename) { $file_object | Add-Member  -NotePropertyName meta_original_filename -NotePropertyValue $file_metadata.OriginalFilename }
        if($file_metadata.ProductName)      { $file_object | Add-Member  -NotePropertyName meta_product_name -NotePropertyValue $file_metadata.ProductName }
        if($file_metadata.Comments)         { $file_object | Add-Member  -NotePropertyName meta_comments -NotePropertyValue $file_metadata.Comments }
        if($file_metadata.CompanyName)      { $file_object | Add-Member  -NotePropertyName meta_company_name -NotePropertyValue $file_metadata.CompanyName }
        #if($file_metadata.FileName)        { $file_object | Add-Member  -NotePropertyName meta_file_name -NotePropertyValue $file_metadata.FileName }
        if($file_metadata.FileVersion)      { $file_object | Add-Member  -NotePropertyName meta_file_version -NotePropertyValue $file_metadata.FileVersion }
        if($file_metadata.ProductVersion)   { $file_object | Add-Member  -NotePropertyName meta_product_version -NotePropertyValue $file_metadata.ProductVersion }
        #if($file_metadata.IsDebug)         { $file_object | Add-Member  -NotePropertyName meta_isdebug -NotePropertyValue $file_metadata.IsDebug }
        #if($file_metadata.IsPatched)       { $file_object | Add-Member  -NotePropertyName meta_ispatched -NotePropertyValue $file_metadata.IsPatched }
        #if($file_metadata.IsPreRelease)    { $file_object | Add-Member  -NotePropertyName meta_isprerelease -NotePropertyValue $file_metadata.IsPreRelease }
        #if($file_metadata.IsPrivateBuild)  { $file_object | Add-Member  -NotePropertyName meta_isprivatebuild -NotePropertyValue $file_metadata.IsPrivateBuild }
        #if($file_metadata.IsSpecialBuild)  { $file_object | Add-Member  -NotePropertyName meta_isspecialbuild -NotePropertyValue $file_metadata.IsSpecialBuild }
        if($file_metadata.Language)         { $file_object | Add-Member  -NotePropertyName meta_language -NotePropertyValue $file_metadata.Language }
        if($file_metadata.LegalCopyright)   { $file_object | Add-Member  -NotePropertyName meta_legal_copyright -NotePropertyValue $file_metadata.LegalCopyright }
        if($file_metadata.LegalTrademarks)  { $file_object | Add-Member  -NotePropertyName meta_legal_trademarks -NotePropertyValue $file_metadata.LegalTrademarks }
        #if($file_metadata.PrivateBuild)    { $file_object | Add-Member  -NotePropertyName meta_private_build -NotePropertyValue $file_metadata.PrivateBuild }
        #if($file_metadata.SpecialBuild)    { $file_object | Add-Member  -NotePropertyName meta_special_build -NotePropertyValue $file_metadata.SpecialBuild }
        #if($file_metadata.FileVersionRaw)  { $file_object | Add-Member  -NotePropertyName meta_file_version_raw -NotePropertyValue $file_metadata.FileVersionRaw }
        #if($file_metadata.ProductVersionRaw) { $file_object | Add-Member  -NotePropertyName meta_product_version_raw -NotePropertyValue $file_metadata.ProductVersionRaw }
        

        $filename_unique = "$filename-$filehash_md5"

        if($execute_files) {

            Write-Host "Starting execution of $filepath..."

            # counter for screenshot filenames
            $i2 = 0

            #iterate through specified command line arguments and execute them
            foreach ($arg in $args_list) {
            
                $i2++ # counter for screenshot filenames
                $process_out = $null

                #Skip blacklisted arguments
                foreach ($arg_filter in $arg_filters.PSObject.Properties) {
                    if(($filename -eq $arg_filter.Name) -AND (($arg -eq $arg_filter.Value) -OR ($arg_filter.Value -eq $true))) {
                        Write-Host "--> Skipped blacklisted argument ($filepath $arg)"
                        $break = $true
                        Break
                    }
                }
                if($break) {
                    $break = $null
                    Continue
                }

                #Execute EXE file
                try {
            
                    $process_out = Start-ProcessGetOutput -filepath "$filepath" -commandline "$arg" -takescreenshot $take_screenshots -screenshotpath "$screenshot_dir\$filename_unique-$i2" -start_process_verbose $xcyclopedia_verbose
    
                }
                catch { 
                    write-host "--> Start: FAILED ($filename)"
                    if($xcyclopedia_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
                    Continue
                }

                # Minimize any stray windows for the purposes of screenshots
                if($minimize_windows -AND $take_screenshots) { $shell.minimizeall() }

                # Add final output values for each file to pscustomobject. Only keep the largest ones.
                # Check if stdout length is longer. If longer, then overwrite existing stdout value using -force
                if ($process_out.stdout.Length -gt $file_object.output.Length) {
                    $file_object | Add-Member  -NotePropertyName output -NotePropertyValue $process_out.stdout -Force
                }

                # Check if stderr length is longer. If longer, then overwrite existing stderr using -force
                if ($process_out.stderr.Length -gt $file_object.error.Length) {
                    $file_object | Add-Member  -NotePropertyName error -NotePropertyValue $process_out.stderr -Force
                }

                # Check if children length is longer. If longer, then overwrite existing children using -force
                if ($process_out.children.Length -gt $file_object.children.Length) {
                    $file_object | Add-Member  -NotePropertyName children -NotePropertyValue $process_out.children -Force
                }

            }

        }

        # Aggregate file group into parent
        try { $file_objects | Add-Member  -NotePropertyName $filename_unique -NotePropertyValue $file_object } catch { write-host "failed: adding file_object to file_objects " }

        # Update status bar
        $i++
        Write-Progress -activity "Files Progress . . ." -status "Completed: $i of $($files.Count)" -percentComplete (($i / $files.Count)  * 100)

        ### TESTING ###
        #$file_object
        #$file_objects | fl
        #Break

    }

    # Convert output to CSV
    # Note: The first object in $file_objects defines the column header names.
    # Note2: This part ".PSObject.Properties | ForEach-Object { $_.value }" is needed for transposing the columns/rows.
    $csv_output = $file_objects.PSObject.Properties | ForEach-Object { $_.value } | ConvertTo-Csv -NoTypeInformation

    # Convert output to JSON
    $file_objects.PSObject.Properties.Remove('header') #removes column headers which is only needed for the CSV file
    $json_output = $file_objects | ConvertTo-Json | Convert-UnicodeToUTF8 | Remove-NonAsciiCharacters

    # Save output to files
    try {
        Set-Content -Path "$save_path\$time-Strontic-xCyclopedia.json" -Value $json_output -Encoding UTF8
        Set-Content -Path "$save_path\$time-Strontic-xCyclopedia.csv" -Value $csv_output -Encoding UTF8
    } catch {
        Write-Host "failed: unable to write output files"
        if($xcyclopedia_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
    }

    Remove-Module Get-Screenshot
    Remove-Module Get-Ssdeep
    Remove-Module Start-ProcessGetOutput
    
    if($transcript_file) { Stop-Transcript }

    # set-executionpolicy restricted -force

}

function PromptUser-Minimization {
    
    $title = 'Info'
    $prompt = 'This script will repeatedly minimize all windows until it has finished (which could take a long time). Are you sure you want to continue? [Y]es, [N]o, or [D]isable Minimization?'
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes','Continue with the script.'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No','Exit the script.'
    $disable = New-Object System.Management.Automation.Host.ChoiceDescription '&Disable Minimization','Disable window minimization.'
    $options = [System.Management.Automation.Host.ChoiceDescription[]] ($yes,$no,$disable)
    $choice = $host.ui.PromptForChoice($title,$prompt,$options,0)


    if($choice -eq 0) { 
        Write-Host "Minimizing Windows: User chose to continue with window minimization enabled."
        return $true
    }
    if($choice -eq 1) { 
        Write-Host "Minimizing Windows: User chose to abort."
        exit 
    }
    if($choice -eq 2) { 
        Write-Host "Minimizing Windows: User chose to disable automated window minimization."
        return $false
    }
}

function Import-LocalModule ([string]$module_name) {

    #Import Screenshot Module

    $script_dir = $null
    $script_dir = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent

    try { Remove-Module $module_name -ErrorAction SilentlyContinue } catch {}

    try { 
        Import-Module "$script_dir\$module_name" -Global
    } 
    catch {
        write-host "Failed to load $module_name module"
        if($xcyclopedia_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
    }

}

function Convert-UnicodeToUTF8 {

    [regex]::replace($input, '(?:\\u[0-9a-f]{4})+', 
    { 
        param($m) 
        $utf8Bytes = (-split ($m.Value -replace '\\u([0-9a-f]{4})', '0x$1 ')).ForEach([byte])
        [text.encoding]::utf8.GetString($utf8Bytes)
    })

    $files_stdout_content = $files_stdout_content -replace '[^\u0001-\u007F]+', ''

}

function Remove-NonAsciiCharacters {
    
    #$input -replace '(\\u0000)', ''
    
    #remove non-ascii:
    $input -replace '[^\u0009-\u007F]+', ''

}

function Get-FileList {

    param (
        #Specifies directories for *recursive* directory walk 
        [string[]]$path_recursive = @("$env:windir\system32","$env:windir\SysWOW64","$env:ProgramData"),

        #Specifies directories for normal dir listing (non-recursive)
        [string[]]$path_normal = @("$env:windir"),

        #Set file extension to 
        [string[]]$file_extension = ".exe"
    )

    $dir = $files_output = $null

    Write-Host "Starting directory listing..."

    $dir = $path_recursive | ForEach-Object {
        Write-Host "--> Starting directory listing... $_ (recursive)"
        Get-ChildItem "$_" -file -recurse -ea SilentlyContinue
    }
    $dir += $path_normal | ForEach-Object {
        Write-Host "--> Starting directory listing... $_"
        Get-ChildItem "$_" -file -ea SilentlyContinue
    }

    # Filter down to just the specified file extension
    $files_output = $dir | Where {$_.extension -eq "$file_extension"}

    $file_count = $files_output.Count

    Write-Host "Directory listing complete ($file_count `"$file_extension`" files found)"

    return $files_output
}

#start main function with defaults
Get-Xcyclopedia
