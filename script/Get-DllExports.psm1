<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Synopsis: PowerShell wrapper for DLL Export Viewer (https://www.nirsoft.net/utils/dll_export_viewer.html).
    License: MIT License; Copyright (c) 2020 strontic
#>

function Get-DllExports {
    
    param (
        [Parameter(Position=0,mandatory=$true)]
        [string]$filepath,    #path to dll
        
        [bool]$dllexports_verbose      = $false,

        [string]$script_dir_dllexports = $null
    )

    if (-NOT ($script_dir_dllexports)) { $script_dir_dllexports = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent }

    # Load Module -- If the necessary module is NOT already loaded, then load it.
    if (-NOT (Get-Module Start-ProcessGetOutput)) {
        try { 
          Import-Module "$script_dir_dllexports\Start-ProcessGetOutput"
        } 
        catch {
            write-host "DllExports: Failed to load Start-ProcessGetOutput module"
            if($dllexports_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
            Break
        }
    } 
    
    try { 
        $dllexp_stdout = $null
        $dllexp_stdout = Start-DllExports -filepath $filepath
    }
    catch {
        write-host "----> DllExports: FAILED ($filepath)"
        if($dllexports_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
        Break
    }

    $dllexp_matched_results = [PSCustomObject]@{}

    #Parse each line of the dllexp.exe output using regex extraction
    foreach ($dllexp_stdout_line in $dllexp_stdout) {

        $dllexp_extract = $Matches = $null

        $dllexp_extract =  $dllexp_stdout_line -match '^([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)'

        # Write match data to object (if the line has a match)
        if($dllexp_extract) {

            $dllexp_matched_line = [PSCustomObject]@{}

            $dllexp_function_name    = $Matches[1]
            $dllexp_address          = $Matches[2]
            $dllexp_relative_address = $Matches[3]
            $dllexp_ordinal          = $Matches[4]
            #$dllexp_filename         = $Matches[5]
            #$dllexp_filepath         = $Matches[6]
            $dllexp_type             = $Matches[7]

            if($dllexp_function_name)    { $dllexp_matched_line | Add-Member -NotePropertyName "dll_export_functionname"    -NotePropertyValue "$dllexp_function_name"    -ErrorAction SilentlyContinue }
            if($dllexp_address)          { $dllexp_matched_line | Add-Member -NotePropertyName "dll_export_address"         -NotePropertyValue "$dllexp_address"          -ErrorAction SilentlyContinue }
            if($dllexp_relative_address) { $dllexp_matched_line | Add-Member -NotePropertyName "dll_export_relativeaddress" -NotePropertyValue "$dllexp_relative_address" -ErrorAction SilentlyContinue }
            if($dllexp_ordinal)          { $dllexp_matched_line | Add-Member -NotePropertyName "dll_export_ordinal"         -NotePropertyValue "$dllexp_ordinal"          -ErrorAction SilentlyContinue }
            if($dllexp_type)             { $dllexp_matched_line | Add-Member -NotePropertyName "dll_export_type"            -NotePropertyValue "$dllexp_type"             -ErrorAction SilentlyContinue }

            $dllexp_ordinal = ($dllexp_ordinal -replace ' \(.*','')

            #Add to group
            try { if($dllexp_matched_line)     { $dllexp_matched_results | Add-Member -NotePropertyName "[$dllexp_ordinal]" -NotePropertyValue $dllexp_matched_line -ErrorAction SilentlyContinue } }
            catch { 
                Write-Host "DllExports: FAILED to add-member $dllexp_ordinal (value: $dllexp_matched_line)" 
                if($dllexports_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black }
            }

        }

    }

    return $dllexp_matched_results
}

function Start-DllExports {
    
    param (
        [string]$filepath
    )

    $dllexp_process = $null
    #$filepath = Fix-FilePathRedirection -original_file_path $filepath
    $dllexp_process = Start-ProcessGetOutput -filepath "$script_dir_dllexports\bin\dllexp-x64\dllexp.exe" -commandline "/stab `"`" /from_files `"$filepath`"" -takescreenshot $false -get_handles $false
    return ($dllexp_process.stdout).Split([Environment]::NewLine)

}

<#
function Fix-FilePathRedirection ([string]$original_file_path) {
    
    #Description: Fixes system redirection problem. Replaces "system32" with "sysnative" in the filepath. Otherwise, DllExports might be redirected to SYSWOW64 directory.
    #More Info: https://docs.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector

    $fixed_file_path = $null
    $fixed_file_path = $original_file_path -replace '\\system32\\', '\sysnative\'

    return $fixed_file_path

}
#>

Export-ModuleMember -function Get-DllExports
