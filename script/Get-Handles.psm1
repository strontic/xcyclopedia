<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Synopsis: Wrapper script for Sysinternals Handle.exe. Parses the handles output for a given process (url: https://docs.microsoft.com/en-us/sysinternals/downloads/handle)
    License: MIT License; Copyright (c) 2020 strontic
#>

function Get-Handles  {
    
    param (
        [Parameter(Position=0,mandatory=$true)]
        [int]$handles_process_id,                                             #process id from which handles should be obtained
        [string]$handle_exe_path = ".\bin\sysinternals\handle\handle64.exe",  #path to Sysinternals Handles executable
        [bool]$handles_verbose = $false
    )

    #Check if handle executable exists at the path specified
    if (-NOT (Test-Path $handle_exe_path -PathType Leaf)) {
        Write-Host "--> Get Handle: FAILED. The Handle executable was not found. Expected path: $handle_exe_path"
        return
    }

    try {
        $handle_process_stdout = Invoke-Expression "$handle_exe_path -pid $handles_process_id -nobanner -accepteula"}
    catch {
        write-host "----> handles: FAILED for pid $handles_process_id ($handle_exe_path)"
        if($handles_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
        return
    }

    $handles_matched_results = [PSCustomObject]@{}

    #Parse each line of the handle.exe output using regex extraction
    foreach ($handle_stdout_line in $handle_process_stdout) {

        $handles_extract = $null

        $handles_extract =  $handle_stdout_line -match '^[\s\w]+:[\s]+(\w+)[\s]+(.*)$'

        # Write match data to object (if the line has a match)
        if($handles_extract) {

            $handle_type = $Matches[1]
            $handle_path = $Matches[2]

            if($handle_type -AND $handle_path){ $handles_matched_results | Add-Member  -NotePropertyName "$handle_path" -NotePropertyValue $handle_type -ErrorAction SilentlyContinue }

        }

    }

    #Return results
    return $handles_matched_results

}

Export-ModuleMember -function Get-Handles