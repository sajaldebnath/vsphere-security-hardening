#requires -version 3

###########################################################################################
# Title     :   Security Audit Report for VMware Environment
# Filename  :   Get-Security.ps1          
# Created by:   Sajal Debnath           
# Date      :   01-09-2015                
# Version   :   1.0        
# Update    :   This is the first version
# E-mail    :   debnathsajal@gmail.com
###########################################################################################

<# 
    .Synopsis 
   Get-Security does a security audit of a vSphere environment as per VMware best practices. 
    .DESCRIPTION 
   The Get-Security function is designed to audit security aspects of a vSphere environment. It will check
   the vCenter, ESXi hosts and all the VMs of the given environment.
 
   By default the function will create the report in a HTML format in the path from where it was called

    .NOTES 
   Created by: Sajal Debnath 
   Modified: 9/7/2015 10:29:58 PM  
 
   Changelog: 
    * Moved the function Get-Security to the Functions file 

 
   To Do: 
    * Create a front end form where users will be able to choose the ESXihosts and VMs on which the security test will be done
    * Create separate functions for ESXi hosts check and VMs check
    * Create seprate function to get the HTML output
    * Create more proper Verbose and Debug output
    * Create more detailed logging 
    * Take input from credential file
 
 
    .EXAMPLE 
    Get-Security -vcenter vcenter.lab.com -vcuser vcadmin@lab.com -vcpassword Vmware1! -esxpassword Vmware1!

#> 




Param(
    [Parameter (Mandatory=$true, ValueFromPipeline=$false)]
    [String]$vcenter,
    [Parameter (Mandatory=$true, ValueFromPipeline=$false)]
    [String]$vcuser,
    [Parameter (Mandatory=$true, ValueFromPipeline=$false)]
    [String]$vcpassword,
    [Parameter (Mandatory=$true, ValueFromPipeline=$false)]
    [String]$esxpassword
)

# Variable Initializations

$DisplaytoScreen = "YES"


# Silencing the comments in the HTML Report

$CommentsH = $false
$CommentsA = $false
$CommentsB = $false

# Use the following area to define the colours of the HTML report
#$Colour1 = "CC0000" # Main Title - currently red
$Colour1 = "228B22" # Main Title - currently Forest Green
#$Colour2 = "7BA7C7" # Secondary Title - currently blue
$Colour2 = "82CAFA" # Secondary Title - currently Light Sky blue
$Colour3 = "FFF380" # Secondary Sub Title - Khaki1
$Colour4 = "FFF8C6" # Secondary main Title - Lemon Chiffon
$Colour5 = "58D3F7" # Very Light Cyan

$subtitle = 'Environment Security Report'

#### Log Detail Setting ####
$LogDate = Get-Date -Format T
$Date = Get-Date

#Log File Info
$LogPath = ".\"
$LogName = "Get-Security.log"
$LogFile = Join-Path -Path $LogPath -ChildPath $LogName

#Dot Source required Function Libraries
. ".\SecurityFunctions.ps1"

#Script Version
$version = "1.0"



# Call of the main function


Get-SecurityFunction -vcenter $vcenter -vcuser $vcuser -vcpassword $vcpassword -esxpassword $esxpassword




