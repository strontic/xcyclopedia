<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Synopsis: Combine JSON files into a single file. Only works with PowerShell-compatible JSON files.
    License: MIT License; Copyright (c) 2020 strontic
#>

function Coalesce-Json {

    param (
        [string[]]$target_files,                             #List of JSON files (comma-delimited) to combine. NOTE: The first file listed takes precedence in case of duplicates.
        [string]$save_path = "c:\temp\strontic-xcyclopedia", #Path to save the combined JSON file.
        [bool]$verbose_output = $true,
        [bool]$save_json = $true,                            #Save file as JSON
        [bool]$save_csv = $true                              #Save file as CSV
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
    
    #Create directory for saving output
    New-Item -ItemType Directory -Force -Path "$save_path" | Out-Null

    # Define CSV columns/headers (Used in Select-Object statement)
    # Note: If the header name is not defined here, or it does not match the property names defined in the source JSON file, then it will no be included.
    $csv_props = @(
        @{ Name = 'file_name'                ; Expression = { $_.file_name } }
        @{ Name = 'file_path'                ; Expression = { $_.file_path } }
        @{ Name = 'hash_md5'                 ; Expression = { $_.hash_md5 } }
        @{ Name = 'hash_sha1'                ; Expression = { $_.hash_sha1 } }
        @{ Name = 'hash_sha256'              ; Expression = { $_.hash_sha256 } }
        @{ Name = 'hash_sha384'              ; Expression = { $_.hash_sha384 } }
        @{ Name = 'hash_sha512'              ; Expression = { $_.hash_sha512 } }
        @{ Name = 'hash_ssdeep'              ; Expression = { $_.hash_ssdeep } }
        @{ Name = 'hash_imp'                 ; Expression = { $_.hash_imp } }
        @{ Name = 'hash_pesha1'              ; Expression = { $_.hash_pesha1 } }
        @{ Name = 'hash_pe256'               ; Expression = { $_.hash_pe256 } }
        @{ Name = 'signature_status'         ; Expression = { $_.signature_status } }
        @{ Name = 'signature_status_message' ; Expression = { $_.signature_status_message } }
        @{ Name = 'signature_serial'         ; Expression = { $_.signature_serial } }
        @{ Name = 'signature_thumbprint'     ; Expression = { $_.signature_thumbprint } }
        @{ Name = 'signature_issuer'         ; Expression = { $_.signature_issuer } }
        @{ Name = 'signature_subject'        ; Expression = { $_.signature_subject } }
        @{ Name = 'meta_description'         ; Expression = { $_.meta_description } }
        @{ Name = 'meta_original_filename'   ; Expression = { $_.meta_original_filename } }
        @{ Name = 'meta_product_name'        ; Expression = { $_.meta_product_name } }
        @{ Name = 'meta_comments'            ; Expression = { $_.meta_comments } }
        @{ Name = 'meta_company_name'        ; Expression = { $_.meta_company_name } }
        #@{ Name = 'meta_file_name'          ; Expression = { $_.meta_file_name } }
        @{ Name = 'meta_file_version'        ; Expression = { $_.meta_file_version } }
        @{ Name = 'meta_product_version'     ; Expression = { $_.meta_product_version } }
        #@{ Name = 'meta_isdebug'            ; Expression = { $_.meta_isdebug } }
        #@{ Name = 'meta_ispatched'          ; Expression = { $_.meta_ispatched } }
        #@{ Name = 'meta_isprerelease'       ; Expression = { $_.meta_isprerelease } }
        #@{ Name = 'meta_isprivatebuild'     ; Expression = { $_.meta_isprivatebuild } }
        #@{ Name = 'meta_isspecialbuild'     ; Expression = { $_.meta_isspecialbuild } }
        @{ Name = 'meta_language'            ; Expression = { $_.meta_language } }
        @{ Name = 'meta_legal_copyright'     ; Expression = { $_.meta_legal_copyright } }
        @{ Name = 'meta_legal_trademarks'    ; Expression = { $_.meta_legal_trademarks } }
        #@{ Name = 'meta_private_build'      ; Expression = { $_.meta_private_build } }
        #@{ Name = 'meta_special_build'      ; Expression = { $_.meta_special_build } }
        #@{ Name = 'meta_file_version_raw'   ; Expression = { $_.meta_file_version_raw } }
        #@{ Name = 'meta_product_version_raw'; Expression = { $_.meta_product_version_raw } }
        @{ Name = 'meta_machinetype'         ; Expression = { $_.meta_machinetype } }
        @{ Name = 'output'                   ; Expression = { ($_.output).Substring(0,[math]::min(($_.output).Length,32000)) } } #limit to 32k characters due to cell overflow
        @{ Name = 'error'                    ; Expression = { ($_.error).Substring(0,[math]::min(($_.output).Length,32000)) } }   #limit to 32k characters due to cell overflow
        @{ Name = 'children'                 ; Expression = { $_.children } }
        @{ Name = 'runtime_window_title'     ; Expression = { $_.runtime_window_title } }
        @{ Name = 'filescan_vtdetection'     ; Expression = { $_.filescan_vtdetection } }
        @{ Name = 'filescan_vtlink'          ; Expression = { $_.filescan_vtlink } }
    )

    # Get Date
    $time = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"

    $json_obj_group = [PSCustomObject]@{}

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

            try { $json_obj_group | Add-Member -NotePropertyName $json_item_name -NotePropertyValue $json_item_value -ErrorAction Stop } catch { write-host "Failed adding $json_item_name. $json_item_value" }

        }
    }

    try {
        Write-Host "Saving coalesced files..."

        if ($save_json) {

            # Convert output to JSON
            $json_output = $json_obj_group | ConvertTo-Json -Depth 4 -ErrorAction Stop | Convert-UnicodeToUTF8

            #Save to file
            Write-Host "--> Saving: $save_path\$time-Strontic-xCyclopedia-COMBINED.json"
            Set-Content -Path "$save_path\$time-Strontic-xCyclopedia-COMBINED.json" -Value $json_output -Encoding UTF8 -ErrorAction Stop

        }

        if ($save_csv) {

            #Remove comment property
            $json_obj_group.PSObject.Properties.Remove('comment') #removes comment property which is only used for the JSON file
        
            # Convert output to CSV
            # Note: The first object in $json_obj_group defines the column header names.
            # Note2: This part ".PSObject.Properties | ForEach-Object { $_.value }" is needed for transposing the columns/rows.
            $csv_output = $json_obj_group.PSObject.Properties | Sort-Object -Property Name | ForEach-Object { $_.value } | Select-Object -Property $csv_props | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop

            #Save to file
            Write-Host "--> Saving: $save_path\$time-Strontic-xCyclopedia-COMBINED.csv"
            Set-Content -Path "$save_path\$time-Strontic-xCyclopedia-COMBINED.csv" -Value $csv_output -Encoding UTF8 -ErrorAction Stop

        }

        Write-Host "Writing Output Files: Success"

    } 
    catch {

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

#Coalesce-Json -target_files filepath1,filepath2