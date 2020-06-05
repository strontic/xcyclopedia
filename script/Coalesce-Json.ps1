<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Synopsis: Combined specified JSON files into a single files. Only works with PowerShell-compatible JSON files.
    License: MIT License; Copyright (c) 2020 strontic
#>

function Coalesce-Json {

    param (
        [string[]]$target_files,
        [string]$save_path = "c:\temp\strontic-xcyclopedia", #path to save output
        [bool]$verbose_output = $true
    )

    #Check for existence of parameters
    if((-NOT ($target_files)) -OR ($target_files.Count -lt 2)) {
        Write-Host "There must be two or more values specified with target_files. Enter each path in comma-delimited format."
        Exit
    }

    #Check path exists
    foreach ($target_file in $target_files) {
        if (-NOT (Test-Path $target_file)) {
            Write-Host "No file found at $target_file"
            Exit
        }
    }

    # Get Date
    $time = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"
    $json_obj_group = [PSCustomObject]@{}
    $json_obj_group

    Write-Host "Reading JSON files..."

    #Load each file
    foreach ($target_file in $target_files) {
        
        Write-Host "--> Reading: $target_file"

        $json_obj = $null
        $json_obj = Get-Content $target_file | Out-String | ConvertFrom-Json

        foreach ($json_item in $json_obj.PSObject.Properties) {

            $json_item_name = $json_item_value = $null
            $json_item_name = $json_item.Name
            $json_item_value = $json_item.Value

            try { $json_obj_group | Add-Member -NotePropertyName $json_item_name -NotePropertyValue $json_item_value -ErrorAction SilentlyContinue } catch { write-host "Failed adding $json_item_name." }
        }
    }

    # Convert output to JSON and CSV
    $json_output = $json_obj_group | ConvertTo-Json | Convert-UnicodeToUTF8
    $csv_output = $json_obj_group | ConvertTo-Csv

    try {
        Write-Host "Saving coalesced files..."
        
        Write-Host "--> Saving: $save_path\$time-Strontic-xCyclopedia-COMBINED.json"
        Set-Content -Path "$save_path\$time-Strontic-xCyclopedia-COMBINED.json" -Value $json_output -Encoding UTF8
        
        Write-Host "--> Saving: $save_path\$time-Strontic-xCyclopedia-COMBINED.csv"
        Set-Content -Path "$save_path\$time-Strontic-xCyclopedia-COMBINED.csv" -Value $csv_output -Encoding UTF8

        Write-Host "Writing Output Files: Success"
    } catch {
        Write-Host "Writing Output Files: FAILED"
        if($verbose_output) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
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

Coalesce-Json -target_files C:\temp\strontic-xcyclopedia\SY\2020-06-04T16-05-38-Strontic-xCyclopedia.json,C:\temp\strontic-xcyclopedia\2020-06-04T14-36-06-Strontic-xCyclopedia.json