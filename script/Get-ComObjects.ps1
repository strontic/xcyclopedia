<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Synopsis: Iterate through all COM Objects by CLSID. Gather ProgIDs, File Paths, Descriptions, and any other data present in the Classes Root. COM Methods can also be collected. Saves as JSON and CSV.
    Warning: Please be advised, if "create_instance" is enabled, this script may cause the system to become unstable, crash, or restart/shutdown. Use this option at your own risk.
    License: MIT License; Copyright (c) 2021 strontic
#>

<# Todo: Add CSV Output #>
<# Todo: Filter out byte/binary data in key values. Reg type: REG_BINARY #>
<# Todo: Fix JobWatchdog. It doesn't seem to be working properly. #>
<# Todo: Remove default PS properties when getting job data. (PSComputerName, RunspaceId, and PSShowComputerName). Done. Needs testing. #>

# set-executionpolicy unrestricted -force

function Get-ComObjects {

    param (
        [string]$save_path     = "c:\xCyclopedia\out\Get-ComObjects", #path to save output
        [bool]$transcript_file = $true,  # Write console output to a file (job.txt)
        [bool]$create_instance = $false, # UNSAFE! System crash may occur. When enabled, a COM instance is created for CLSID. This is required for determining COM methods.
        [bool]$verbose         = $false
    )

    $ProgressPreference = "SilentlyContinue" # This might prevent the Win32 internal error: "The handle is invalid" (0x6)

    # Create directory where files will be saved
    New-Item -ItemType Directory -Force -Path "$save_path" | Out-Null

    # Change directory to save path
    Set-Location $save_path

    # Get Date
    $time = Get-Date -Format "yyyy-MM-ddTHH-mm-ss"

    # Start transcript
    if($transcript_file) {
        try { Stop-Transcript } catch{}
        Start-Transcript "$save_path\$time-job.txt"
    }

    $comment = [PSCustomObject]@{
        author = '@strontic20'
        website = 'strontic.com'
        github = 'github.com/strontic/xcyclopedia'
        synopsis = 'Gather metadata of COM Objects'
        license = 'MIT License; Copyright (c) 2021 strontic'
        rundate = Get-Date -Format "yyyy-MM-dd"
    }

    #### Get a list of all CLSIDs from the registry (HKCR)
    Write-Host "--> Getting list of COM Objects (CLSIDs)"
    $clsid_list = Get-ChildItem "Registry::HKEY_CLASSES_ROOT\CLSID" -Name -Include ("*-*") #only include CLSIDs with dashes (filters out one called "CLSID")

    $Script:queue_data_object = $null
    $Script:queue_data_object = [PSCustomObject]@{}
    $Script:queue_data_object | Add-Member -NotePropertyName "comment" -NotePropertyValue $comment

    #TESTING
    #$clsid_list = Get-ChildItem "Registry::HKEY_CLASSES_ROOT\CLSID" -Name -Include ("{FBF23B40-E3F0-101B-8488-00AA003E56F8}") #test multiple parent and child datapoints
    #$clsid_list = Get-ChildItem "Registry::HKEY_CLASSES_ROOT\CLSID" -Name -Include ("{F5078F35-C551-11D3-89B9-0000F81FE221}") #test instance creation
    #$clsid_list = Get-ChildItem "Registry::HKEY_CLASSES_ROOT\CLSID" -Name -Include ("{0E94CA61-50B3-4ACD-8276-1A281F3357F3}") #test for avoidance of powershell crash

    $i = 1
    #########################################
    ##### Enumerate CLSID Registry Keys #####
    #########################################
    foreach ($clsid in $clsid_list) {

        Write-Progress -activity "(Part 1) Enumerating CLSID . . . " -status "Progress: $i of $($clsid_list.Count) (current CLSID: $clsid)" -percentComplete (($i / $clsid_list.Count)  * 100)

        Write-Host "--> Enumerating CLSID $clsid... " -NoNewline

        $clsid_keys_object = $null
        $clsid_keys_object = [PSCustomObject]@{}

        # Get root-level CLSID registry keys
        $clsid_parent = $null
        $clsid_parent = Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid"
        foreach ($clsid_parent_property in ($clsid_parent.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"})) { #filter out PowerShell custom properties

            $clsid_keys_object | Add-Member -NotePropertyName $clsid_parent_property.Name -NotePropertyValue $clsid_parent_property.Value

        }
        
        #Get Child Registry Keys (depth=1). It get the child items recursively but only stores the first depth.
        $clsid_children = $clsid_children_object = $null
        $clsid_children_object = [PSCustomObject]@{}
        $clsid_children = Get-ChildItem "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid" -Recurse -Exclude "Implemented Categories","ShellEx","MayChangeDefaultMenu"
        foreach ($clsid_child in $clsid_children) {

            $clsid_child_name = $null
            $clsid_child_name = $clsid_child.PSChildName -replace '^(\d)$','($1)' # add parenthesis around single integers. single integers cannot be used as a NotePropertyName value.

            $clsid_children_object_properties = [PSCustomObject]@{}

            foreach ($clsid_child_property in (($clsid_child | Get-ItemProperty).PSObject.Properties | Where-Object {$_.Name -notlike "PS*"})) {

                $clsid_child_property_name = $clsid_child_property_value = $null
                $clsid_child_property_name = $clsid_child_property.Name
                $clsid_child_property_value = $clsid_child_property.Value

                $clsid_children_object_properties | Add-Member -NotePropertyName $clsid_child_property_name -NotePropertyValue $clsid_child_property_value

            }

            #Add child reg keys to clsid_children_object (if there are any values)
            if("$clsid_children_object_properties") { $clsid_children_object | Add-Member -NotePropertyName $clsid_child_name -NotePropertyValue $clsid_children_object_properties -ErrorAction SilentlyContinue }

        }

        #Add all children properties (nested keys/values) to clsid_keys_object
        if("$clsid_children_object") { $clsid_keys_object | Add-Member -NotePropertyName "Registry" -NotePropertyValue $clsid_children_object }

        $Script:queue_data_object | Add-Member -NotePropertyName "$clsid" -NotePropertyValue $clsid_keys_object

        Write-Host "Done."

        $i++

    }
                            
    ######################################
    #### SCRIPTBLOCK FOR JOB QUEUEING ####
    ####      Instantiate CLSIDs      ####
    ######################################
    $scriptblock = {

        param(
            [Parameter(Position=0,mandatory=$true)]
            $clsid,
            [Parameter(Position=1,mandatory=$false)]
            [bool]$create_instance,
            [Parameter(Position=2,mandatory=$false)]
            [bool]$job_verbose
        )

        #if ($create_instance -AND ($clsid -notin $clsid_skip_instance)) {
        if ($create_instance) {

            #$clsid_parent_object = $null
            #$clsid_parent_object = [PSCustomObject]@{}

            $instance = $clean_up_result = $clsid_instance_object = $null
            $clsid_instance_object = [PSCustomObject]@{}

            Write-Host "----> Creating Instance for CLSID $clsid..." -NoNewline
            
            try { $instance = [activator]::CreateInstance([type]::GetTypeFromCLSID($clsid)) }
            catch { 
                Write-Host "FAILED: Unable to create instance" -ForegroundColor Red
                if($job_verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
            }

            if ($null -ne $instance) { #if instance exists

                $instance_type = $null
                $instance_type = ($instance.GetType())

                # The following member names will be skipped:
                $powershell_default_members = "ToString","GetLifetimeService","InitializeLifetimeService","CreateObjRef","Equals","GetHashCode","GetType"

                #Create two PSCustomObjects for storing the instance methods and properties
                $clsid_instance_methods = $clsid_instance_properties = $null
                $clsid_instance_methods = [PSCustomObject]@{}
                $clsid_instance_properties = [PSCustomObject]@{}
                foreach ($instance_member in ($instance.PSObject.Members | Where-Object {$_.Name -notin $powershell_default_members})) {

                    if ($instance_member.Name) { #ensure the definition is not null
                        if($instance_member.MemberType -eq "Method"){
                            $clsid_instance_methods | Add-Member -NotePropertyName $instance_member.Name -NotePropertyValue "$instance_member"
                        }
                        if($instance_member.MemberType -eq "Property"){
                            $clsid_instance_properties | Add-Member -NotePropertyName $instance_member.Name -NotePropertyValue "$instance_member"
                        }
                    }

                }

                #Add values to clsid_instance_object (ensure source vars are not empty). 
                # Note: In the "if" statements, the quotations around PSCustomObjects, "$clsid_instance_methods" and "$clsid_instance_properties" are intentional. Without them, it will always be True.
                if($instance_type)               { $clsid_instance_object | Add-Member -NotePropertyName "Type" -NotePropertyValue "$($instance_type.Name)" }
                if("$clsid_instance_methods")    { $clsid_instance_object | Add-Member -NotePropertyName "Methods" -NotePropertyValue $clsid_instance_methods }
                if("$clsid_instance_properties") { $clsid_instance_object | Add-Member -NotePropertyName "Properties" -NotePropertyValue $clsid_instance_properties }

                #$clsid_parent_object | Add-Member -NotePropertyName "Instance" -NotePropertyValue $clsid_instance_object

                Write-Host "Success." -NoNewline -ForegroundColor Green

                # Release COM Object and clean up
                Write-Host " Releasing COM Object..." -NoNewline
                try{ $instance.Quit() | Out-Null } catch {} #only works with some COM objects (e.g. word and excel)
                if ( $instance_type.Name -eq "__ComObject" ) { 
                    $clean_up_result = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($instance)
                    if ($clean_up_result -lt 0) { Write-Host "Release Failed." -NoNewline -ForegroundColor Yellow}
                }
                elseif ($job_verbose) {
                    Write-Host "Unable to release. Object type is `"$($instance_type.Name)`" (Expected: `"ComObject`")" -NoNewline -ForegroundColor Magenta 
                }
                [System.GC]::Collect() # force garbage collection
                #[System.GC]::WaitForPendingFinalizers() # wait until completion. can cause script to freeze indefinitely.
                Remove-Variable instance,instance_type,clsid_instance_methods,clsid_instance_properties
                Write-Host " Done."

                #Return $clsid_parent_object
                Return $clsid_instance_object

            }

        }
    
    } ####  END SCRIPTBLOCK  ####

    ################################
    ######### EXECUTE JOBS #########
    ################################
    Start-JobQueue -input_object $clsid_list -scriptblock $scriptblock -unsafe_methods $create_instance -start_job_verbose $verbose -max_parallel_jobs 220 -max_lifetime_seconds 10

    ################################
    ######### WRITE OUTPUT #########
    ################################
    $json_output = $null
    #$json_output = $clsid_objects | ConvertTo-Json -Depth 5
    $json_output = $Script:queue_data_object | ConvertTo-Json -Depth 5

    # Save output to files
    Write-Host "--> Writing files..." -NoNewline
    try {
        Set-Content -Path "$save_path\$time-Strontic-xCyclopedia_COM.json" -Value $json_output -Encoding UTF8 -ErrorAction Stop
        #if ($convert_to_csv) { Set-Content -Path "$save_path\$time-Strontic-xCyclopedia_COM.csv" -Value $csv_output -Encoding UTF8 -ErrorAction Stop}
        Write-Host "Done."
    } catch {
        Write-Host "Writing JSON/CSV Files: FAILED. Unable to write output files for JSON and/or CSV"
        if($verbose) { Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black } #verbose output
    }

    ################################
    ########## CLEAN UP ############
    ################################
    Remove-Variable clsid_objects,json_output,csv_output,queue_data_object,clsid_list -ErrorAction SilentlyContinue
    Write-Host "Script Complete."
    # Stop transcript
    if($transcript_file) { Stop-Transcript }


}

function Start-JobQueue {

    # Starts job queue from a list of strings and scriptblock

    param(
        [Parameter(Position=0,mandatory=$true)]
        [string[]]$input_object,             # Array of strings that will be used for iteration
        [Parameter(Position=1,mandatory=$true)]
        [scriptblock]$scriptblock,           # scriptblock object to be used for jobs
        [int]$max_parallel_jobs = 10,        # maximum number of jobs running concurrently.
        [int]$max_lifetime_seconds = 60,     # maximum lifetime of a job, after which it should be forcefully stopped.
        [bool]$delete_existing_jobs = $true, # clear out any existing child jobs
        [bool]$start_job_verbose = $false,   # verbose
        [bool]$unsafe_methods = $false       # customizable argument (e.g. whether to instantiate unstable processes)
    )
    
    # create script-scoped variable if it doesn't already exist
    if (!$Script:queue_data_object) { $Script:queue_data_object = [PSCustomObject]@{} }
    $progress_counter = 1

    Add-JobWatchdog

    #Clean up: Clear any existing PS jobs
    if ($delete_existing_jobs) { Remove-Job * -Force }

    foreach($input_item in $input_object) {

        $job_started = $false
        Write-Progress -activity "(Part 2) Starting Jobs . . . " -status "Progress: $progress_counter of $($input_object.Count) (current job: $input_item)" -percentComplete (($progress_counter / $input_object.Count)  * 100)

        while ($job_started -eq $false) {

            if ((Get-Job -State "Running").Count -lt $max_parallel_jobs) {

                Write-Host "--> Starting job $input_item..." -NoNewline
                try {
                    Start-Job -ScriptBlock $scriptblock -ArgumentList $input_item,$unsafe_methods,$start_job_verbose -Name "$input_item" | Out-Null 
                    Write-Host "Success." -ForegroundColor Green
                }
                catch { Write-Host "FAILED." -ForegroundColor Red }
                $progress_counter++
                $job_started = $true
            }
            else { 
                Get-JobData
                Clear-StaleJobs -max_lifetime_seconds $max_lifetime_seconds
            }
            
            #For every queue loop, get any results
            Get-JobData

        }

        #TESTING
        #Break

    }

    Write-Host "All jobs started. Receiving remaining data..."
    Get-RemainingJobs -max_lifetime_seconds $max_lifetime_seconds

    #Clean up: Clear any remaining PS jobs that are somehow still running.
    Clear-StaleJobs -max_lifetime_seconds 0

    Write-Host "Queue Complete."

    #TESTING
    #$Script:queue_data_object

}

function Get-JobData {

    # Get data from any completed jobs that are unreceived (hasmoredata=true).

    $completed_jobs = Get-Job -State "Completed" -HasMoreData $true | Where-Object { $_.Name -ne "NuclearJobKiller" }

    foreach ($completed_job in $completed_jobs){
        Write-Host "--> Recieving job data for $($completed_job.Name)..." -NoNewline
        try{
            $job_data = $null
            $job_data = Receive-Job $completed_job

            # Remove default PS properties that are added when receiving a job.
            if ("$job_data") {
                $job_data.PSObject.Properties.Remove('PSComputerName') | Out-Null
                $job_data.PSObject.Properties.Remove('RunspaceId') | Out-Null
                $job_data.PSObject.Properties.Remove('PSShowComputerName') | Out-Null
            }
            
            # try adding to existing object parent. if it doesn't exist, create a new one.
            if ("$job_data") {
                try { $Script:queue_data_object."$($completed_job.Name)" | Add-Member -NotePropertyName "Instance" -NotePropertyValue $job_data -ErrorAction Stop }
                catch { $Script:queue_data_object | Add-Member -NotePropertyName $completed_job.Name -NotePropertyValue $job_data }
                
                Write-Host "Success." -ForegroundColor Green
            }
            else {Write-Host "FAILED. The received object is empty." -ForegroundColor Red}
            
        }
        catch {
            Write-Host "FAILED." -ForegroundColor Red
            Write-Host "Message: [$($_.Exception.Message)"] -ForegroundColor Red -BackgroundColor Black
        }
    }
}

function Clear-StaleJobs {

    # Stop jobs that run longer than x seconds

    param(
        [int]$max_lifetime_seconds = 60
    )

    # Add backup watchdog, in case the script hangs on the "Remove-Job" function referenced below. Default enforcement time is double the maximum.
    Start-JobWatchdog -enforcement_seconds ($max_lifetime_seconds*2)

    $running_jobs = Get-Job -State "Running" | Where-Object { $_.Name -ne "NuclearJobKiller" }

    foreach ($running_job in $running_jobs){

        if( (((Get-Date)-($running_job.PSBeginTime)).TotalSeconds) -gt $max_lifetime_seconds ) {

            #Testing
            #$run_seconds = ((Get-Date)-($running_job.PSBeginTime)).TotalSeconds
            #Write-Host "$($running_job.Name) has been running for $run_seconds seconds"

            Write-Host "--> Disposing of stale job $($running_job.Name)..." -NoNewline -ForegroundColor Yellow
            try { 
                Remove-Job $running_job -Force -ErrorAction Stop  # Forces the removal of the stale job. If this hangs, then the watchdog should be able to kill the associated process.
                Write-Host "Done."
            }
            Catch { Write-Host "FAILED."}
        }

        #Check if JobWatchdog (aka NuclearJobKiller) has any results
        Receive-JobWatchdog

    }

}

function Add-JobWatchdog {

    # This prepares the watchdog as a scriptblock, in case the parent script freezes, it will stop all child processes (jobs). 
    # Note: the scriptblock variable is script-scope so it is accessible outside of this function.

    if(!$Script:scriptblock_watchdog) {
    
        $Script:scriptblock_watchdog = {
    
            param (
                [Parameter(Position=0,mandatory=$true)]
                [string[]]$list_of_child_procs,
                [Parameter(Position=1,mandatory=$false)]
                [int]$max_lifetime_seconds_nuclear
            )
        
            $child_jobs_gs = $child_jobs_stale = $null
        
            Start-Sleep -Seconds $max_lifetime_seconds_nuclear
        
            # Convert to Get-Process
            $child_jobs_gs = $list_of_child_procs | ForEach-Object { Get-Process -pid $_ | Where-Object {$_.Name -eq "Powershell"} }
        
            # Get processes where lifetime exceeds a certain number of seconds
            $child_jobs_stale = $child_jobs_gs | Where-Object { (((Get-Date)-$_.StartTime).totalseconds) -gt $max_lifetime_seconds_nuclear }
        
            # Stop the stale processes that have exceeded specified time.
            $child_jobs_stale | ForEach-Object { Stop-Process -id $_.ProcessId -Force }
        
            Write-Host "NuclearJobKiller: Stopped $($child_jobs_stale.Count) out of $($child_jobs_gs.Count) stale jobs"
        
        }
    }

}

function Start-JobWatchdog {

    # Starts a temporary watchdog that will stop all child processes (jobs), in case the parent script hangs on one of those jobs.

    param (
        [Parameter(Position=0,mandatory=$false)]
        [int]$enforcement_seconds = 60
    )

    if(!$Script:scriptblock_watchdog) { Add-JobWatchdog } #if the variable is null, initialize it with Add-JobWatchdog


    $child_jobs = $null
    $child_jobs = (Get-WmiObject win32_process | Where-Object { ($_.ParentProcessId -eq $pid) -AND ($_.ProcessName -eq "powershell.exe") } | Select-Object -ExpandProperty ProcessId)
    
    Remove-Job -Name "NuclearJobKiller" -Force -ErrorAction SilentlyContinue | Out-Null
    Start-Job -ScriptBlock $Script:scriptblock_watchdog -ArgumentList $child_jobs,$enforcement_seconds -Name "NuclearJobKiller" | Out-Null

}

function Receive-JobWatchdog {

    # Gets results of watchdog (aka NuclearJobKiller)

    $watchdog_job = $null
    $watchdog_job = Get-Job -Name "NuclearJobKiller" -HasMoreData $true

    return ($watchdog_job | ForEach-Object { Receive-Job $_ })
    
}

function Get-RemainingJobs {

    # Wait for remaining jobs to finish and Get-JobData

    param(
        [int]$max_lifetime_seconds = 60  # default 60 seconds
    )

    $queue_hasmoredata = $false
    
    #Check if jobs has data or their state is Running.
    if ((Get-Job -State "Completed" -HasMoreData $true) -OR (Get-Job -State "Running" | Where-Object {$_.Name -ne "NuclearJobKiller"})) {$queue_hasmoredata = $true}
    
    while ($queue_hasmoredata) {
        
        Start-Sleep -Seconds 1
        
        if (Get-Job -State "Completed" -HasMoreData $true) {
            Get-JobData
        }
        elseif (Get-Job -State "Running" | Where-Object {$_.Name -ne "NuclearJobKiller"}) {
            Clear-StaleJobs -max_lifetime_seconds $max_lifetime_seconds
        }
        else {$queue_hasmoredata = $false}
    }
    
}

Get-ComObjects -verbose $true