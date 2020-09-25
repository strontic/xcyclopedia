<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Synopsis: Wrapper script for Sysinternals Sigcheck.exe. Parses the sigcheck output and return PowerShell object (Sigcheck url: https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck)
    License: MIT License; Copyright (c) 2020 strontic
#>

function Get-Sigcheck  {
    
    param (
        [Parameter(Position=0,mandatory=$true)]
        [string]$file_to_sigcheck,                                                    #process id from which handles should be obtained
        [string]$sigcheck_exe_path   = ".\bin\sysinternals\sigcheck\sigcheck64.exe",  #path to Sysinternals Sigcheck executable
        [bool]$sigcheck_verbose      = $false,
        [bool]$get_virustotal        = $false,  # Get VirusTotal detection ratio. It does NOT submit file by default.
        [bool]$accept_virustotal_tos = $false   # Accept VirusTotal's Terms of Service (https://www.virustotal.com/en/about/terms-of-service/)
    )

    # If user chose to enable VirusTotal checks, prompt the user to accept VirusTotal ToS, if not already accepted.
    if($get_virustotal -AND (-NOT $accept_virustotal_tos)) { $get_virustotal = PromptUser-VirusTotal }

    #Check if Sigcheck executable exists at the path specified
    if (-NOT (Test-Path "$sigcheck_exe_path" -PathType Leaf)) {
        Write-Host "--> Get Sigcheck: FAILED. The Sigcheck executable was not found. Expected path: $sigcheck_exe_path"
        return
    }

    #Execute the sigcheck binary and grab output
    try {
        
        # Get Sigcheck results WITH VirusTotal data
        if ($get_virustotal) {
            $sigcheck_stdout = Invoke-Expression "$sigcheck_exe_path -vt -h -accepteula `"$file_to_sigcheck`""
        }

        # Get Sigcheck results WITHOUT VirusTotal data
        else {
            $sigcheck_stdout = Invoke-Expression "$sigcheck_exe_path -h -accepteula `"$file_to_sigcheck`""
        }        
    }
    catch {
        write-host "----> sigcheck: FAILED for file $file_to_sigcheck ($sigcheck_exe_path)"
        if($sigcheck_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
        return
    }

    $sigcheck_matched_results = [PSCustomObject]@{}

    #Parse each line of the sigcheck.exe output using regex extraction
    foreach ($sigcheck_stdout_line in $sigcheck_stdout) {

        $sigcheck_extract = $Matches = $null

        $sigcheck_extract =  $sigcheck_stdout_line -match '^\s+([^:]+):\s+(.*)$'

        # Write match data to object (if the line has a match)
        if($sigcheck_extract) {

            $sigcheck_key   = $Matches[1]
            $sigcheck_value = $Matches[2]

            if($sigcheck_key -AND $sigcheck_value){ $sigcheck_matched_results | Add-Member  -NotePropertyName "$sigcheck_key" -NotePropertyValue $sigcheck_value -ErrorAction SilentlyContinue }

        }

    }

    #Return results
    return $sigcheck_matched_results

}

function PromptUser-VirusTotal {
    
    $title = 'Info'
    $prompt = 'You have enabled VirusTotal checks. You must accept VirusTotal terms of service before continuing (https://www.virustotal.com/en/about/terms-of-service/). Do you accept [Y]es, [N]o, [A]bort?'
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes','Accept and continue.'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No','Disable VirusTotal checks.'
    $abort = New-Object System.Management.Automation.Host.ChoiceDescription '&Abort','Exit script.'
    $options = [System.Management.Automation.Host.ChoiceDescription[]] ($yes,$no,$abort)
    $choice = $host.ui.PromptForChoice($title,$prompt,$options,0)

    if($choice -eq 0) { 
        Write-Host "VirusTotal Prompt: User chose to accept VirusTotal ToS and continue. Note: in the future please add `"-accept_virustotal_tos $true`"."
        return $true
    }
    if($choice -eq 1) { 
        Write-Host "VirusTotal Prompt: User chose to disable VirusTotal checks and continue."
        return $false
    }
    if($choice -eq 2) { 
        Write-Host "VirusTotal Prompt: User chose to abort."
        exit
    }
}

Export-ModuleMember -function Get-Sigcheck