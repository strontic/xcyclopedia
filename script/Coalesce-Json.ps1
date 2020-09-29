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

    # Get Date
    $time = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"

    # Define the header names. This is only used for export to CSV file -- not JSON. 
    # If the header name is not defined here, or it does not match the property names defined in the source JSON file, then it will no be included.
    $header = [PSCustomObject]@{
        file_name = $null
        file_path = $null
        hash_md5 = $null
        hash_sha1 = $null
        hash_sha256 = $null
        hash_sha384 = $null
        hash_sha512 = $null
        hash_ssdeep = $null
        hash_imp    = $null
        hash_pesha1 = $null
        hash_pe256  = $null
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
        meta_machinetype = $null
		output = $null
		error = $null
		children = $null
        runtime_window_title = $null
        filescan_vtdetection = $null
        filescan_vtlink = $null
    }

    $json_obj_group = [PSCustomObject]@{}
    $json_obj_group | Add-Member  -NotePropertyName header -NotePropertyValue $header

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

    try {
        Write-Host "Saving coalesced files..."

        if ($save_csv) {

            # Convert output to CSV
            # Note: The first object in $file_objects defines the column header names.
            # Note2: This part ".PSObject.Properties | ForEach-Object { $_.value }" is needed for transposing the columns/rows.
            $csv_output = $json_obj_group.PSObject.Properties | Sort-Object -Property Name | ForEach-Object { $_.value } | ConvertTo-Csv -NoTypeInformation

            #Save to file
            Write-Host "--> Saving: $save_path\$time-Strontic-xCyclopedia-COMBINED.csv"
            Set-Content -Path "$save_path\$time-Strontic-xCyclopedia-COMBINED.csv" -Value $csv_output -Encoding UTF8

        }

        if ($save_json) {

            # Convert output to JSON
            $json_obj_group.PSObject.Properties.Remove('header') #removes column headers which is only needed for the CSV file
            $json_output = $json_obj_group | ConvertTo-Json -Depth 4 | Convert-UnicodeToUTF8

            #Save to file
            Write-Host "--> Saving: $save_path\$time-Strontic-xCyclopedia-COMBINED.json"
            Set-Content -Path "$save_path\$time-Strontic-xCyclopedia-COMBINED.json" -Value $json_output -Encoding UTF8

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