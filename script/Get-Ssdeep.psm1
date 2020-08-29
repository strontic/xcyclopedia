<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Synopsis: Get the ssdeep file hash using the binary downloaded from: https://github.com/ssdeep-project/ssdeep/releases
    License: MIT License; Copyright (c) 2020 strontic
#>

function Get-Ssdeep ([string]$filepath,[bool]$ssdeep_verbose = $false) {
    
    $script_dir_ssdeep = $null
    $script_dir_ssdeep = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent

    # Load Module -- If the necessary module is NOT already loaded, then load it.
    if (-NOT (Get-Module Start-ProcessGetOutput)) {
        try { 
          Import-Module "$script_dir_ssdeep\Start-ProcessGetOutput"
        } 
        catch {
            write-host "ssdeep: Failed to load Start-ProcessGetOutput module"
            if($ssdeep_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
            Break
        }
    } 
    
    try { 
        $Hash = Start-Ssdeep
    }
    catch {
        write-host "----> ssdeep: FAILED ($filepath)"
        if($ssdeep_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
    }

    return $Hash
}

function Start-Ssdeep {
    
    $filepath = Fix-FilePathRedirection -original_file_path $filepath
    $ssdeep_process = Start-ProcessGetOutput -filepath "$script_dir_ssdeep\bin\ssdeep-2.14.1\ssdeep.exe" -commandline "-s -b `"$filepath`"" -takescreenshot $false
    $Hash = ($ssdeep_process.stdout | ConvertFrom-Csv).ssdeep
    return $Hash

}

function Fix-FilePathRedirection ([string]$original_file_path) {
    
    <#
    Description: Fixes system redirection problem. Replaces "system32" with "sysnative" in the filepath. Otherwise, SSDEEP will be redirected to SYSWOW64 directory.
    More Info: https://docs.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
    #>

    $fixed_file_path = $null
    $fixed_file_path = $original_file_path -replace '\\system32\\', '\sysnative\'

    return $fixed_file_path

}


Export-ModuleMember -function Get-Ssdeep