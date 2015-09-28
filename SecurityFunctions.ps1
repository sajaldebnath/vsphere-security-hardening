# HTML creation Functions
#region Functions
function Get-CustomHTML ($Header){
$Report = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>$($Header)</title>
        <META http-equiv=Content-Type content='text/html; charset=windows-1252'>
        <script src="https://code.jquery.com/jquery-1.10.2.js"></script>
        <style type="text/css">

        TABLE       {
                        TABLE-LAYOUT: fixed; 
                        FONT-SIZE: 100%; 
                        WIDTH: 100%
                    }
        *
                    {
                        margin:0
                    }
        .hidden { display: none; }
        .unhidden { display: block; }
        .dspcont    {
    
                        BORDER-RIGHT: #bbbbbb 1px solid;
                        BORDER-TOP: #bbbbbb 1px solid;
                        PADDING-LEFT: 0px;
                        FONT-SIZE: 8pt;
                        MARGIN-BOTTOM: -1px;
                        PADDING-BOTTOM: 5px;
                        MARGIN-LEFT: 0px;
                        BORDER-LEFT: #bbbbbb 1px solid;
                        WIDTH: 95%;
                        COLOR: #000000;
                        MARGIN-RIGHT: 0px;
                        PADDING-TOP: 4px;
                        BORDER-BOTTOM: #bbbbbb 1px solid;
                        FONT-FAMILY: Tahoma;
                        POSITION: relative;
                        BACKGROUND-COLOR: #f9f9f9
                    }
                    
        .filler     {
                        BORDER-RIGHT: medium none; 
                        BORDER-TOP: medium none; 
                        DISPLAY: block; 
                        BACKGROUND: none transparent scroll repeat 0% 0%; 
                        MARGIN-BOTTOM: -1px; 
                        FONT: 100%/8px Tahoma; 
                        MARGIN-LEFT: 43px; 
                        BORDER-LEFT: medium none; 
                        COLOR: #FFFFFF; 
                        MARGIN-RIGHT: 0px; 
                        PADDING-TOP: 4px; 
                        BORDER-BOTTOM: medium none; 
                        POSITION: relative
                    }

        .pageholder {
                        margin: 0px auto;
                    }
                    
        .dsp
                    {
                        BORDER-RIGHT: #bbbbbb 1px solid;
                        PADDING-RIGHT: 0px;
                        BORDER-TOP: #bbbbbb 1px solid;
                        DISPLAY: block;
                        PADDING-LEFT: 0px;
                        FONT-WEIGHT: bold;
                        FONT-SIZE: 8pt;
                        MARGIN-BOTTOM: -1px;
                        MARGIN-LEFT: 0px;
                        BORDER-LEFT: #bbbbbb 1px solid;
                        COLOR: #000000;
                        MARGIN-RIGHT: 0px;
                        PADDING-TOP: 4px;
                        BORDER-BOTTOM: #bbbbbb 1px solid;
                        FONT-FAMILY: Tahoma;
                        POSITION: relative;
                        HEIGHT: 2.25em;
                        WIDTH: 95%;
                        TEXT-INDENT: 10px;
                    }

        .dsphead0   {
                        BACKGROUND-COLOR: #$($Colour1);
                    }
                    
        .dsphead1   {
                        
                        BACKGROUND-COLOR: #$($Colour2);
                    }
        .dsphead2   {
                        
                        BACKGROUND-COLOR: #$($Colour3);
                    }
        .dsphead3   {
                        
                        BACKGROUND-COLOR: #$($Colour4);
                    }     

        .dsphead4   {
                        BACKGROUND-COLOR: #$($Colour5);
                    }
                          
                    
    .dspcomments    {
                        BACKGROUND-COLOR:#FFFFE1;
                        COLOR: #000000;
                        FONT-STYLE: ITALIC;
                        FONT-WEIGHT: normal;
                        FONT-SIZE: 8pt;
                    }

    td              {
                        VERTICAL-ALIGN: TOP; 
                        FONT-FAMILY: Tahoma;
                        FONT-SIZE: 8pt;
                    }
                    
    th              {
                        VERTICAL-ALIGN: TOP; 
                        COLOR: #$($Colour1); 
                        TEXT-ALIGN: left;
                    }
    tr:nth-child(odd) { 
                        background-color:#d3d3d3;
                      } 
    tr:nth-child(even) { 
                        background-color:white;
                      }
                    
    BODY            {
                        margin-left: 4pt;
                        margin-right: 4pt;
                        margin-top: 6pt;
                    } 
    .MainTitle      {
                        font-family:Arial, Helvetica, sans-serif;
                        font-weight:bolder;
                        color: #FF8040;
                    }
    .SubTitle       {
                        font-family:Arial, Helvetica, sans-serif;
                        font-size:14px;
                        font-weight:bold;
                    }
    .Created        {
                        font-family:Arial, Helvetica, sans-serif;
                        font-size:10px;
                        font-weight:normal;
                        margin-top: 20px;
                        margin-bottom:5px;
                    }
    .links          {   font:Arial, Helvetica, sans-serif;
                        font-size:10px;
                        FONT-STYLE: ITALIC;
                    }
                    
        </style>
        <script type="text/javascript">
         function unhide(divID) {
         var item = document.getElementById(divID);
        if (item) {
        item.className=(item.className=='hidden')?'unhidden':'hidden';
        }
        }
        </script>  
    
    </head>
    <body >
        <div class="MainTitle"><font size="20ptx"><center>$($Header)</center></font></div>
        <hr size="8" color="#$($Colour1)">
        <div class="SubTitle">$($subtitle):$($version):: Generated on $($ENV:Computername):&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</div>
        <br/>
        <hr size="4" color="#$($Colour1)">
        <br/>
        <div class="Created">Report created on $(get-date)</div>

"@
return $Report
}

function Get-CustomHeader0 ($Title){
$Report = @"
        <div class="pageholder">        

        <h1 class="dsp dsphead0">$($Title)</h1>
    
        <div class="filler"></div>

"@
return $Report
}


function Get-CustomHeader1 ($Title){
$Report = @"
        <div class="pageholder">        

        <h1 class="dsp dsphead4">$($Title)</h1>
    
        <div class="filler"></div>

"@
return $Report
}

function Get-CustomHeader ($Title, $cmnt, $Div){
$Report = @"
        <h2 class="dsp dsphead1">$($Title)</h2>
"@
if ($CommentsH) {
    $Report += @"
            <div class="dsp dspcomments">$($cmnt)</div>
"@
}
$Report += @"
        <div class="dspcont">
        <a href="javascript:unhide('$($Div)');"><button>Show/Hide</button></a>
        <div id="$($Div)" class="hidden">
"@
return $Report
}

function Get-CustomHeaderA ($Title, $cmnt, $Div){
$Report = @"
        <h2 class="dsp dsphead2">$($Title)</h2>
"@
if ($CommentsA) {
    $Report += @"
            <div class="dsp dspcomments">$($cmnt)</div>
"@
}
$Report += @"
        <div class="dspcont">
        <a href="javascript:unhide('$($Div)');"><button>Show/Hide</button></a>
        <div id="$($Div)" class="hidden">
"@
return $Report
}

function Get-CustomHeaderB ($Title, $cmnt){
$Report = @"
        <h2 class="dsp dsphead3">$($Title)</h2>
"@
if ($CommentsB) {
    $Report += @"
            <div class="dsp dspcomments">$($cmnt)</div>
"@
}
$Report += @"
        <div class="dspcont">
"@
return $Report
}


function Get-CustomHeaderClose{

    $Report = @"
        </DIV>
        </div>
        <div class="filler"></div>
"@
return $Report
}


function Get-CustomHeaderAClose{

    $Report = @"
        </DIV>
        </div>
        <div class="filler"></div>
"@
return $Report
}

function Get-CustomHeaderBClose{

    $Report = @"
        </DIV>

        <div class="filler"></div>
"@
return $Report
}



function Get-CustomHeader0Close{
    $Report = @"
</DIV>
"@
return $Report
}


function Get-CustomHeader1Close{
    $Report = @"
</DIV>
"@
return $Report
}



function Get-CustomHTMLClose{
    $Report = @"
</div>

</body>
</html>
"@
return $Report
}


function Get-HTMLTable {
    param([array]$Content)
    $HTMLTable = $Content | ConvertTo-Html -Fragment
    $HTMLTable = $HTMLTable -replace '>RED ', ' bgcolor="RED">'
    $HTMLTable = $HTMLTable -replace '>Green ', ' bgcolor="Green">'
    return $HTMLTable
}

function Get-HTMLDetail ($Heading, $Detail){
$Report = @"
<TABLE>
    <tr>
    <th width='50%'><font color ="Midnight Blue"><b>$Heading</b></font></th>
    <td width='50%'>$($Detail)</td>
    </tr>
</TABLE>
"@
return $Report
}

function Get-HTMLBody ($Heading, $Detail){
$Report = @"
<TABLE>
    <tr>
    <td width='50%'><font color ="Midnight Blue"><b>$Heading</b></font></td>
    <td width='50%'>$($Detail)</td>
    </tr>
</TABLE>
"@
return $Report
}


function Get-HTMLLog ($Location){
$Report = @"
<TABLE>
    <tr>
    <td width='50%'><b>To Check Detailed Log Click on the link or check the location::</b></font></td>
    <td width='50%'><a href=$($Location) target='_blank'>$($Location)</a></td>
    </tr>
</TABLE>
"@
return $Report
}
#endRegion
    
# Log Write Function 

function Write-Log 
{ 
    [CmdletBinding()] 
    #[Alias('wl')] 
    [OutputType([int])] 
    Param 
    ( 
        # The string to be written to the log. 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true, 
                   Position=0)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        # The path to the log file. 
        [Parameter(Mandatory=$false, 
                   ValueFromPipelineByPropertyName=$true, 
                   Position=1)] 
        [Alias('LogPath')] 
        [string]$Path=".\Get-Security.log", 
 
        [Parameter(Mandatory=$false, 
                    ValueFromPipelineByPropertyName=$true, 
                    Position=3)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info", 
 
        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Process 
    { 
         
        if ((Test-Path $Path) -AND $NoClobber) { 
            Write-Warning "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
            } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist 
        # to create the file include path. 
        elseif (!(Test-Path $Path)) { 
            Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        else { 
            # Nothing to see here yet. 
            } 
 
        # Now do the logging and additional output based on $Level 
        switch ($Level) { 
            'Error' { 
                Write-Error $Message 
                Write-Output "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") ERROR: $Message" | Out-File -FilePath $Path -Append 
                } 
            'Warn' { 
                Write-Warning $Message 
                Write-Output "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") WARNING: $Message" | Out-File -FilePath $Path -Append 
                } 
            'Info' { 
                Write-Verbose $Message 
                Write-Output "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") INFO: $Message" | Out-File -FilePath $Path -Append 
                } 
            } 
    } 
    End 
    { 
    } 
}

# The Main Function which checks and reports the Security
Function Get-SecurityFunction{
  <# 
    .Synopsis 
   Get-Security does a security audit of a vSphere environment as per VMware best practices. 
    .DESCRIPTION 
   The Get-Security function is designed to audit security aspects of a vSphere environment. It will check
   the vCenter, ESXi hosts and all the VMs of the given environment.
 
   By default the function will create the Report in HTML format report and file if it does not  
   exist.  
    .NOTES 
   Created by: Sajal Debnath 
   Modified:  
 
   Changelog: 

 
   To Do: 
    * More elaborate Log writing 
    * More elaborate Verbose output
    * More elaborate Debug output
    * Seprate the VM and ESXi host security checking
    * Separate the HTML reporting function from this one 
 
    .EXAMPLE 
	Get-Security -vcenter <vcenter> -vcuser <user id> -vcpassword <vc password> -esxpassword <esx password>
    #> 
    [CmdletBinding()]
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
  
    Begin{
        # Adding Snapin and Importing required Modules
        Add-PSSnapin VMware.VimAutomation.Core -ea SilentlyContinue
        Import-Module 'C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Modules\VMware.VimAutomation.Vds'

        Write-Log  -LogContent 'Disconnecting from all Connected vCenter Server' -LogPath $LogFile -Level Info
        Write-Verbose 'Disconnecting from all Connected vCenter Server'
        [void] (Disconnect-VIServer -Force -server * -Confirm:$false) 

        Try{
            Write-Verbose 'Connecting to vCenter Server'
            Write-Log  -LogContent 'Connecting to vCenter Server' -LogPath $LogFile -Level Info
            [void] (Connect-VIServer -Server $vcenter -User $vcuser -Password $vcpassword)
            $vcfullname = (Get-View ServiceInstance).Content.About.FullName
        }
    
        Catch{
            Write-Debug 'Could Not Connect to vCenter Server'
            Write-Log  -LogContent 'Could Not Connect to vCenter Server' -LogPath $LogFile -Level Error
            Exit
        }



        # Decalaring the variables for datastoring
        $data = @()
        $data1 = @()
        $data2 = @()
        $data3 = @()
        $data4 = @()
        $data5 = @()
    }

    Process{
        
        # vCenter.verify-nfc-ssl

        $info = Get-AdvancedSetting -entity $vcenter -name config.nfc.useSSL
        If ($info -eq $null){ 
            $Data += [PSCustomObject] @{
            Parameter = 'vCenter.verify-nfc-ssl'
            Description = 'Check Network File Copy NFC uses SSL'
            vCenter = $vcenter
            CurrentValue = "RED Not Set"}
        }
        Else{
            $Data += [PSCustomObject] @{
            Parameter = 'vCenter.verify-nfc-ssl'
            Description = 'Check Network File Copy NFC uses SSL'
            CurrentValue = "Green $info"}
        }
        

        
        $virtualswitches = Get-VirtualSwitch -Standard

        Foreach ($virtualswitch in $virtualswitches){

        # vNetwork.reject-forged-transmit
        # List all vSwitches and their Security Settings

            $vmhost = $virtualswitch.VMHost
            $switch = $virtualswitch.Name
            If ($virtualswitch.ExtensionData.Spec.Policy.Security.ForgedTransmits){
                $value = "RED Accept"
            }
            Else{
                $value = "Green Reject"
            }
            $data1 += [PSCustomObject] @{
            Parameter = 'vNetwork.reject-forged-transmit'
            Description = 'Ensure that the Forged Transmits policy is set to reject'
            VMHost = $vmhost
            vSwitch = $switch
            CurrentValue = $value}

        # vNetwork.reject-mac-changes
        # Ensure that the “MAC Address Changes” policy is set to reject


            If ($virtualswitch.ExtensionData.Spec.Policy.Security.MacChanges){
                $value = "RED Accept"
            }
            Else{
                $value = "Green Reject"
            }
            $Data1 += [PSCustomObject] @{
            Parameter = 'vNetwork.reject-mac-changes'
            Description = 'Ensure that the MAC Address Changes policy is set to reject'
            VMHost = $vmhost
            vSwitch = $switch
            CurrentValue = $value}

        # vNetwork.reject-promiscuous-mode
        # Ensure that the “Promiscuous Mode” policy is set to reject

            If ($virtualswitch.ExtensionData.Spec.Policy.Security.PromiscuousMode){
                $value = "RED Accept"
            }
            Else{
                $value = "Green Reject"
            }
            $Data1 += [PSCustomObject] @{
            Parameter = 'vNetwork.reject-promiscuous-mode'
            Description = 'Ensure that the Promiscuous Mode policy is set to reject'
            VMHost = $vmhost
            vSwitch = $switch
            CurrentValue = $value}
        }

        
        # List all dvPortGroups and their Security Settings

        $dvsportgroups = Get-VDPortgroup

        Foreach ($dvsportgroup in $dvsportgroups){

            # vNetwork.reject-forged-transmit-dvportgroup
            # Ensure that the “Forged Transmits” policy is set to reject

            $dvswitch = $dvsportgroup.VDSwitch.Name
            $portgroup = $dvsportgroup.Name
            If ($dvsportgroup.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.MacChanges.Value){
                $value = "RED Accept"
            }
            Else{
                $value = "Green Reject"
            }
            $data2 += [PSCustomObject] @{
            Parameter = 'vNetwork.reject-mac-changes-dvportgroup'
            Description = 'Ensure that the Mac Changes policy is set to reject'
            DVSwitch = $dvswitch
            Portgroup = $portgroup
            CurrentValue = $value}

            If ($dvsportgroup.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.AllowPromiscuous.Value){
                $value = "RED Accept"
            }
            Else{
                $value = "Green Reject"
            }
            $Global:data2 += [PSCustomObject] @{
            Parameter = 'vNetwork.reject-promiscuous-mode-dvportgroup'
            Description = 'Ensure that the Promiscuous Mode policy is set to reject'
            DVSwitch = $dvswitch
            Portgroup = $portgroup
            CurrentValue = $value}

            If ($dvsportgroup.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.ForgedTransmits.Value){
                $value = "RED Accept"
            }
            Else{
                $value = "Green Reject"
            }
            $data2 += [PSCustomObject] @{
            Parameter = 'vNetwork.reject-forged-transmit-dvportgroup'
            Description = 'Ensure that the Forged Transmits policy is set to reject'
            DVSwitch = $dvswitch
            Portgroup = $portgroup
            CurrentValue = $value}

            # vNetwork.restrict-netflow-usage
            # Ensure that VDS Netflow traffic is only being sent to authorized collector IPs
            If ($dvsportgroup.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value){
                $value = "Green Configured"
            }
            Else{
                $value = "RED Not Configured"
            }
            $Data2 += [PSCustomObject] @{
            Parameter = 'vNetwork.restrict-netflow-usage'
            Description = 'Ensure that VDS Netflow traffic is only being sent to authorized collector IPs'
            DVSwitch = $dvswitch
            Portgroup = $portgroup
            CurrentValue = $value }


        }


### ESXi host security information
    
        $esxihosts = Get-VMHost

 
        ForEach ($esxihost in $esxihosts){



            Write-Log  -LogContent "Host is:  $esxihost" -LogPath $LogFile -Level Info
            Write-Log  -LogContent 'Exception Users from ESXi Host' -LogPath $LogFile -Level Info
 
             
             # Connect to each ESXi host in the cluster to retrieve the list of local users.
             Write-Verbose "Connecting to: $esxihost"
             [void] (Connect-VIServer -Server $esxihost -user 'root' -Password $esxpassword)     
             [void] (Connect-VIServer -Server $vcenter -User $vcuser -Password $vcpassword)      

            # Audit the list of users who are on the Exception Users List and whether they have administrator privleges
 
            $lockdown = Get-View ($esxihost | Get-View).ConfigManager.HostAccessManager


            If( $lockdown.LockdownMode -eq 'lockdownDisabled' ){
    
                Write-Verbose 'No Locked Down User'
                $Data3 += [PSCustomObject] @{
                    Parameter = 'ESXi.audit-exception-users'
                    Description = 'Audit the list of users who are on the Exception Users List and whether they have administrator privleges'
                    VMHost = $esxihost
                    LDUsers = "RED No Locked Down User"
                    Admin = "" }

            }
            Else{

                Write-Log  -LogContent 'Disconnecting from all Connected vCenter Server' -LogPath $LogFile -Level Info

                [void] (Disconnect-VIServer -Force -server $vcenter -Confirm:$false)

                $esxifullname = (Get-View ServiceInstance).Content.About.FullName

                $LDusers = $lockdown.QueryLockdownExceptions()
    
                #Loop through the list of Exception Users and check to see if they have accounts on
                #the ESXi server and if that account is an administrator account.
                foreach ($LDuser in $LDusers)
                {

                    Write-Verbose "Get-vmhostaccount"
                    $hostaccountname = Get-VMHostAccount   -ErrorAction SilentlyContinue  $LDuser
                    write-Verbose "Check to see if user exists"
                    if ($hostaccountname.Name){
            
                        Write-Verbose "Get-VIPermission"
                        $isadmin = Get-VIPermission -Principal $LDuser -ErrorAction SilentlyContinue | Where {$_.Role –eq “Admin”} 
                        Write-Verbose "Admin Role: " $isadmin.Role
                        if ($isadmin.Role -eq "Admin") {
                        
                            Write-Verbose $LDuser is an "Exception User with Admin accounts on " $esxihost
                            $Data3 += [PSCustomObject] @{
                            Parameter = 'ESXi.audit-exception-users'
                            Description = 'Audit the list of users who are on the Exception Users List and whether they have administrator privleges'
                            VMHost = $esxihost
                            LDUsers = "Green $LDusers"
                            Admin = "Green $LDuser" }
                        }
                    }
                [void] (Connect-VIServer -Server $vcenter -User $vcuser -Password $vcpassword)
                }
            }
            # List the SNMP Configuration of a host (single host connection required)
                
                $snmp = (Get-VMHostSnmp).Enabled

                If ($snmp -eq 'False' ){

                    $value = "RED SNMP not Configured"
                
                }
                Else{

                    $value = "Green Enabled"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.config-snmp'
                Description = 'Ensure proper SNMP configuration'
                VMHost = $esxihost
                Value = $value }


            # Disable Managed Object Browser (MOB)
                
                $status = ( $esxihost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob).Value

                If ($status -eq 'False' ){

                    $value = "Green MOB not Configured"
                
                }
                Else{

                    $value = "RED Enabled"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.disable-mob'
                Description = 'Disable Managed Object Browser (MOB)'
                VMHost = $esxihost
                Value = $value }

            # Use Active Directory for local user authentication
                
                $status = ($esxihost | Get-VMHostAuthentication).Domain

                If (!$status ){

                    $value = "RED AD not Configured"
                
                }
                Else{

                    $value = "Green $status"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.enable-ad-auth'
                Description = 'Use Active Directory for local user authentication'
                VMHost = $esxihost
                Value = $value }
 

            # Check the host profile is using vSphere Authentication proxy to add the host to the domain

                $status = ($esxihost | Get-VMHostProfile)

                If (!$status ){

                    $value = "RED Host Profile not Configured"
                
                }
                Else{
                    $status = ($esxihost | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled
                    $value = "Green $status"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.enable-auth-proxy'
                Description = 'When adding ESXi hosts to Active Directory use the vSphere Authentication Proxy to protect passwords'
                VMHost = $esxihost
                Value = $value }


            # List Iscsi Initiator and CHAP Name if defined
            
                $status = ($esxihost | Get-VMHostHba).AuthenticationProperties.ChapName

                If (!$status ){

                    $value = "RED CHAP Authentication not Configured"
                
                }
                Else{
                    $status = ($esxihost | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled
                    $value = "Green $status"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.enable-chap-auth'
                Description = 'Enable bidirectional CHAP, also known as Mutual CHAP, authentication for iSCSI traffic'
                VMHost = $esxihost
                Value = $value }

            # To check if Lockdown mode is enabled
            
                $status = $esxihost.Extensiondata.Config.adminDisabled

                If ($status -eq 'False' ){

                    $value = "RED Lockdown not Configured"
                
                }
                Else{
                    
                    $value = "Green Enabled"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.enable-normal-lockdown-mode'
                Description = 'Enable Normal Lockdown Mode to restrict access'
                VMHost = $esxihost
                Value = $value }


            # List Syslog.global.logHost for each host
                 $status = ($esxihost | Get-AdvancedSetting Syslog.global.logHost).Value

                If (!$status ){

                    $value = "RED Syslog not Configured"
                
                }
                Else{
                    
                    $value = "Green Enabled"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.enable-remote-syslog'
                Description = 'Configure remote logging for ESXi hosts'
                VMHost = $esxihost
                Value = $value }

            # To check if Lockdown mode is enabled
        
                $status = $esxihost.Extensiondata.Config.adminDisabled

                If ($status -eq 'False' ){

                    $value = "RED Strict Lockdown not Configured"
                
                }
                Else{
                    $myhost =  $esxihost | Get-View
                    $lockdown = Get-View $myhost.ConfigManager.HostAccessManager
                    $lockdown.UpdateViewData()
                    $lockdownstatus = $lockdown.LockdownMode
                    $value = "Green $lockdownstatus"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.enable-strict-lockdown-mode'
                Description = 'Enable Strict lockdown mode to restrict access'
                VMHost = $esxihost
                Value = $value }

            # List Security.PasswordQualityControl for each host

                 $status = ($esxihost| Get-AdvancedSetting Security.PasswordQualityControl).Value

                If (!$status ){

                    $value = "RED Password Policy not Configured"
                
                }
                Else{
                    
                    $value = "Green $status"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.set-password-policies'
                Description = 'Establish a password policy for password complexity'
                VMHost = $esxihost
                Value = $value }

            # List UserVars.ESXiShellInteractiveTimeOut for each host

                $status = ($esxihost | Get-AdvancedSetting UserVars.ESXiShellInteractiveTimeOut).Value

                If ($status -eq 0 ){

                    $value = "RED Timeout Value not Configured"
                
                }
                Else{
                    
                    $value = "Green $status"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.set-shell-interactive-timeout'
                Description = 'Set a timeout to automatically terminate idle ESXi Shell and SSH sessions'
                VMHost = $esxihost
                Value = $value }

            # Ensure default setting for intra-VM TPS is correct
                $status = ($esxihost | Get-AdvancedSetting -Name "Mem.ShareForceSalting").Value

                If ($status -ne 2 ){

                    $value = "RED Value correctly not Configured"
                
                }
                Else{
                    
                    $value = "Green Configured"
                }

                $Data4 += [PSCustomObject] @{
                Parameter = 'ESXi.TransparentPageSharing-intra-enabled'
                Description = 'Ensure default setting for intra-VM TPS is correct'
                VMHost = $esxihost
                Value = $value }


                [void] (Disconnect-VIServer -Force -server * -Confirm:$false) 
            
            [void] (Connect-VIServer -Server $vcenter -User $vcuser -Password $vcpassword)

            # List the NTP Settings for all hosts 

            $ntp = $esxihost | Get-VMHostNtpServer

            If (!$ntp ){

                $value = "RED NTP not Configured"
                
            }
            Else{

                $value = "Green $ntp"
            }

            $Data4 += [PSCustomObject] @{
            Parameter = 'ESXi.config-ntp'
            Description = 'Configure NTP time synchronization'
            VMHost = $esxihost
            Value = $value }


            # List Syslog.global.logDir for each host

            $logdir = ($esxihost | Get-AdvancedSetting Syslog.global.logDir).Value

            If (!$logdir ){

                $value = "RED LogDir not Configured"
                
            }
            Else{

                $value = "Green $logdir"
            }

            $Data4 += [PSCustomObject] @{
            Parameter = 'ESXi.config-persistent-logs'
            Description = 'Configure persistent logging for all ESXi host'
            VMHost = $esxihost
            Value = $value }


            # Verify Image Profile and VIB Acceptance Levels
            # List the Software AcceptanceLevel for each host

            $ESXCli = Get-EsxCli -VMHost $esxihost

            $acceptance = $ESXCli.software.acceptance.get()

            If ($acceptance -ne 'VMwareCertified' ){

                $value = "RED $acceptance"
                
            }
            Else{

                $value = "Green $acceptance"
            }

            $Data4 += [PSCustomObject] @{
            Parameter = 'ESXi.verify-acceptance-level-accepted'
            Description = 'Verify Image Profile and VIB Acceptance Levels'
            VMHost = $esxihost
            Value = $value }


            # List Net.DVFilterBindIpAddress for each host

            $status = ($esxihost | Get-AdvancedSetting Net.DVFilterBindIpAddress).Value

            If (!$status ){

                $value = "RED Not Set"
                
            }
            Else{

                $value = "Green $status"
            }

            $Data4 += [PSCustomObject] @{
            Parameter = 'vNetwork.verify-dvfilter-bind'
            Description = 'Prevent unintended use of dvfilter network APIs'
            VMHost = $esxihost
            Value = $value }
        }

        # End of ESXi hosts checking


        # VM information checking

        $vms = Get-VM 

        Foreach ($vm in $vms){

            # List the VMs and their current settings

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.copy.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-console-copy'
            Description = 'Explicitly disable copy/paste operations'
            Name = 'isolation.tools.copy.disable'
            Entity = $vm.Name
            Value = $Value }

            # Explicitly disable copy/paste operations

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.dnd.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-console-drag-n-drop'
            Description = 'Explicitly disable copy/paste operations'
            Name = 'isolation.tools.dnd.disable'
            Entity = $vm.Name
            Value = $Value }


            # List the VMs and their current settings

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.setGUIOptions.enable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-console-gui-options'
            Description = 'Explicitly disable copy/paste operations'
            Name = 'isolation.tools.setGUIOptions.enable'
            Entity = $vm.Name
            Value = $Value }


            # List the VMs and their current settings

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.paste.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-console-paste'
            Description = 'Explicitly disable copy/paste operations'
            Name = 'isolation.tools.paste.disable'
            Entity = $vm.Name
            Value = $Value }

             
            # Disable virtual disk shrinking
            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.diskShrink.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-disk-shrinking-shrink'
            Description = 'Disable virtual disk shrinking'
            Name = 'isolation.tools.diskShrink.disable'
            Entity = $vm.Name
            Value = $Value }


            # Disable virtual disk shrinking

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.diskWiper.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-disk-shrinking-wiper'
            Description = 'Disable virtual disk shrinking'
            Name = 'isolation.tools.diskWiper.disable'
            Entity = $vm.Name
            Value = $Value }

            # 
            # Disable HGFS file transfers
            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.hgfsServerSet.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-hgfs'
            Description = 'Disable HGFS file transfers'
            Name = 'isolation.tools.hgfsServerSet.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-independent-nonpersistent
            # Avoid using independent nonpersistent disks

            #List the VM's and their disk types
#            $vms | Get-HardDisk | where {$_.Persistence –ne “Persistent”} | Select Parent, Name, Filename, DiskType, Persistence

            # VM.disable-unexposed-features-autologon
            # Disable certain unexposed features

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.ghi.autologon.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-autologon'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.ghi.autologon.disable'
            Entity = $vm.Name
            Value = $Value }

            # 
            # Disable certain unexposed features

            $status = $vm | Get-AdvancedSetting -Name "isolation.bios.bbs.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-biosbbs'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.bios.bbs.disable'
            Entity = $vm.Name
            Value = $Value }

            # 
            # Disable certain unexposed features

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.getCreds.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-getcreds'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.getCreds.disable'
            Entity = $vm.Name
            Value = $Value }

            # 
            # Disable certain unexposed features

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.ghi.launchmenu.change" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-launchmenu'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.ghi.launchmenu.change'
            Entity = $vm.Name
            Value = $Value }


            # 
            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.memSchedFakeSampleStats.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-memsfss'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.memSchedFakeSampleStats.disable'
            Entity = $vm.Name
            Value = $Value }

            # 
            # Disable certain unexposed features
            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.ghi.protocolhandler.info.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-protocolhandler'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.ghi.protocolhandler.info.disable'
            Entity = $vm.Name
            Value = $Value }


            # VM.disable-unexposed-features-shellaction

            $status = $vm | Get-AdvancedSetting -Name "isolation.ghi.host.shellAction.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-shellaction'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.ghi.host.shellAction.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-toporequest

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.dispTopoRequest.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-toporequest'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.dispTopoRequest.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-trashfolderstate

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.trashFolderState.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-trashfolderstate'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.trashFolderState.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-trayicon

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.ghi.trayicon.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-trayicon'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.ghi.trayicon.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-unity
            # Disable certain unexposed features

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.unity.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-unity'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.unity.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-unity-interlock

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.unityInterlockOperation.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-unity-interlock'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.unityInterlockOperation.disable'
            Entity = $vm.Name
            Value = $Value }


            # VM.disable-unexposed-features-unitypush
 
            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.unity.push.update.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-unitypush'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.unity.push.update.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-unity-taskbar
 
            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.unity.taskbar.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-unity-taskbar'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.unity.taskbar.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-unity-unityactive

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.unityActive.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-unity-unityactive'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.unityActive.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-unity-windowcontents

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.unity.windowContents.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-unity-windowcontents'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.unity.windowContents.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-versionget
            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.vmxDnDVersionGet.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-versionget'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.vmxDnDVersionGet.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-unexposed-features-versionset

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.guestDnDVersionSet.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-unexposed-features-versionset'
            Description = 'Disable certain unexposed features'
            Name = 'isolation.tools.guestDnDVersionSet.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-vix-messages

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.vixMessage.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-vix-messages'
            Description = 'Disable VIX messages from the VM'
            Name = 'isolation.tools.vixMessage.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disable-VMtools-autoinstall

            $status = $vm | Get-AdvancedSetting -Name "isolation.tools.autoInstall.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.disable-VMtools-autoinstall'
            Description = 'Disable tools auto install'
            Name = 'isolation.tools.autoInstall.disable'
            Entity = $vm.Name
            Value = $Value }

            # VM.disconnect-devices-floppy
            # Disconnect unauthorized devices
            # Check for Floppy Devices attached to VMs
#            $vms | Get-FloppyDrive | Select Parent, Name, ConnectionState

            # VM.disconnect-devices-parallel
            # Check for Parallel ports attached to VMs
#            $vms | Get-ParallelPort


            # VM.disconnect-devices-serial
            # Disconnect unauthorized devices

            # Check for Serial ports attached to VMs
#            $vms | Get-SerialPort

            # VM.limit-setinfo-size

            $status = $vm | Get-AdvancedSetting -Name "tools.setInfo.sizeLimit" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.limit-setinfo-size'
            Description = 'Disable tools auto install'
            Name = 'tools.setInfo.sizeLimit'
            Entity = $vm.Name
            Value = $Value }

            # List the VMs and their current settings

            $status = $vm | Get-AdvancedSetting -Name "RemoteDisplay.vnc.enabled" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'RemoteDisplay.vnc.enabled'
            Description = 'Remote Display VNC enabled'
            Name = 'RemoteDisplay.vnc.enabled'
            Entity = $vm.Name
            Value = $Value }

            # VM.prevent-device-interaction-connect
 
            $status = $vm | Get-AdvancedSetting -Name "isolation.device.connectable.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.prevent-device-interaction-connect'
            Description = 'Prevent unauthorized removal, connection and modification of devices'
            Name = 'isolation.device.connectable.disable'
            Entity = $vm.Name
            Value = $Value }


            # VM.prevent-device-interaction-edit

            $status = $vm | Get-AdvancedSetting -Name "isolation.device.edit.disable" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.prevent-device-interaction-edit'
            Description = 'Prevent unauthorized removal, connection and modification of devices'
            Name = 'isolation.device.edit.disable'
            Entity = $vm.Name
            Value = $Value }
    
            # VM.restrict-host-info

            $status = $vm | Get-AdvancedSetting -Name "tools.guestlib.enableHostInfo" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.restrict-host-info'
            Description = 'Restrict Host Information'
            Name = 'tools.guestlib.enableHostInfo'
            Entity = $vm.Name
            Value = $Value }

            # VM.TransparentPageSharing-inter-VM-Enabled
 
            $status = $vm | Get-AdvancedSetting -Name "Mem.ShareForceSalting" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.TransparentPageSharing-inter-VM-Enabled'
            Description = 'List the VMs and their current settings'
            Name = 'Mem.ShareForceSalting'
            Entity = $vm.Name
            Value = $Value }

            # VM.verify-network-filter
 
            $status = $vm | Get-AdvancedSetting -Name "ethernet*.filter*.name*" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.verify-network-filter'
            Description = 'List the VMs and their current settings'
            Name = 'ethernet*.filter*.name*'
            Entity = $vm.Name
            Value = $Value }

            # VM.verify-PCI-Passthrough

            $status = $vm | Get-AdvancedSetting -Name "pciPassthru*.present" 

            If ($status.Value -eq 'true' ){

                $value = "Green Configured"
                
            }
            Else{
                    
                $value = "RED Not Configured"
            }

            $Data5 += [PSCustomObject] @{
            Parameter = 'VM.verify-PCI-Passthrough'
            Description = 'List the VMs and their current settings'
            Name = 'pciPassthru*.present'
            Entity = $vm.Name
            Value = $Value }
        }

    }
  
    End{
        
            Write-Log  -LogContent 'Completed Successfully' -LogPath $LogFile -Level Info

            # Start the HTML Report
            $MyReport = Get-CustomHTML "Infrastructure Security Report"

            # Set the HTML Header for the report 

            $MyReport += Get-CustomHeader0 ("vCenter Server: " + $vcenter + "  --  " + "vCenter Version and Build: " + $vcfullname )


            #$MyReport += Get-CustomHeader1 "Total Infrastructure Capacity ----" 

            # Entire Infrastructure Report 

            $MyReport += Get-CustomHeaderA "vCenter Security Information ::" "" "head2"

            $MyReport += Get-HTMLTable ($data | Select Parameter, Description, vCenter, CurrentValue )


            $MyReport += Get-CustomHeaderAClose

            #$MyReport += Get-CustomHeader1Close


            # vSwitch Related Report 


            $MyReport += Get-CustomHeader1 "vSwitch Related Report ----" 

            $MyReport += Get-CustomHeaderA "vSwitch Related Security Report ::" "" "head3"

            $MyReport += Get-HTMLTable ( $data1 | Select Parameter, Description, VMHost, vSwitch, CurrentValue)

            $MyReport += Get-CustomHeaderAClose

            $MyReport += Get-CustomHeader1Close

            # Portgroup Related Report 


            $MyReport += Get-CustomHeader1 "PortGroup Related Report ----" 

            $MyReport += Get-CustomHeaderA "PortGroup Wise Security Report ::" "" "head4"

            $MyReport += Get-HTMLTable ( $data2 | Select Parameter, Description, DVSwitch, PortGroup, CurrentValue)

            $MyReport += Get-CustomHeaderAClose

            $MyReport += Get-CustomHeader1Close

            # Host Wise Report 

            $MyReport += Get-CustomHeader1 "ESXi Host Security Level ----" 

            $MyReport += Get-CustomHeaderA "Locked Down User with Admin Rights ::" "" "head5"
            $MyReport += Get-HTMLTable ( $data3 | Where-Object { $_.VMHost -eq $esxihost} | Select Parameter, Description, VMhost, LDUsers, Admin)

            $MyReport += Get-CustomHeaderAClose

            $MyReport += Get-CustomHeaderA "Host Wise Security Report ::" "" "head6"

            Foreach ($esxihost in $esxihosts){

                $MyReport += Get-CustomHeaderB "ESXi Host :: $esxihost :: Version: $esxifullname"  

                 
                $MyReport += Get-HTMLTable ( $data4 | Where-Object { $_.VMHost -eq $esxihost} | Select Parameter, Description, VMhost, Value)

                $MyReport += Get-CustomHeaderBClose  
            }
            $MyReport += Get-CustomHeaderAClose
            $MyReport += Get-CustomHeader1Close



            # VM Wise Report 

            $MyReport += Get-CustomHeader1 "VM Security Level ----" 

            $MyReport += Get-CustomHeaderA "VM Wise Security Report ::" "" "head7"

            Foreach ($vm in $vms){

                $MyReport += Get-CustomHeaderB "VM :: $vm "  

                 
                $MyReport += Get-HTMLTable ( $data5 | Where-Object { $_.Entity -eq $vm.Name} | Select Parameter, Description, Name, Entity, Value)

                $MyReport += Get-CustomHeaderBClose  
            }
            $MyReport += Get-CustomHeaderAClose
            $MyReport += Get-CustomHeader1Close


            $MyReport += Get-CustomHeader0Close
            $MyReport += Get-CustomHTMLClose

            $MyReport += Get-CustomHeader0Close
            $MyReport += Get-CustomHTMLClose


            #Uncomment the following lines to save the htm file in a central location
            if ($DisplayToScreen) {
                Write-Verbose "Displaying HTML results"
                if (-not (test-path .\Report\)) {
                    mkdir .\Report | Out-Null
                }
            $Filename = ".\Report\" + $vcenter + "_Security_Report" + "_" + $Date.Day + "-" + $Date.Month + "-" + $Date.Year + "-" + $Date.Hour +"-" + $Date.Minute +".html"
            $MyReport | out-file -encoding ASCII -filepath $Filename
            Invoke-Item $Filename
            }
       
    }
}

