[cmdletbinding(SupportsShouldProcess,DefaultParametersetName='Default')]
param (
    [Parameter(Mandatory = $true)]
    [String]
    $AdminSDHolderDN,

    [Parameter(Mandatory = $false)]
    [PSCredential]
    $ADCredential,

    [Parameter(Mandatory = $true)]
    [String[]]
    $MailTo,

    [Parameter(Mandatory = $false)]
    [String[]]
    $MailCC,

    [Parameter(Mandatory = $false)]
    [String[]]
    $MailBCC,

    [Parameter(Mandatory = $true)]
    [String]
    $MailSubject,

    [Parameter(Mandatory = $true)]
    [PSCredential]
    $MailCredential
)

if ($ADCredential) {
    $PSDefaultParameterValues.Add("*-AD*:Credential",$ADCredential)
}


$SDHolderBaseName='AdminSDHolder'
$UpdateLog=@()
$SpecialDescendantTypes=@("User","Group","Computer")
$schemaIDGUID=@{}
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
    ForEach-Object {$schemaIDGUID.add($_.name,[System.GUID]$_.schemaIDGUID)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
    ForEach-Object {$schemaIDGUID.add($_.name,[System.GUID]$_.rightsGUID)}
$ErrorActionPreference = 'Continue'

function Compare-Sddl ($Sddl) {
    [string](($Sddl -replace '\(\)?|\)\(?','|').split('|') | Sort-Object)
}

$AdminSDHolders=Get-ADObject -SearchBase "$AdminSDHolderDN" `
    -Filter "Name -like '$($SDHolderBaseName)*' -and ObjectClass -eq 'container'" | `
    Where-Object {$_.Name -ne $SDHolderBaseName} | `
    Select-Object *,@{Name="AdminCount";Expression={[System.Int32]($_.Name -replace $SDHolderBaseName,'')}}

$AdminGroupObjects=Get-ADGroup -Filter "AdminCount -gt 1" -Properties AdminCount
$AdminObjects=@()

foreach ($AdminGroupObject in $AdminGroupObjects) {
    $AdminObjects+=$AdminGroupObject | Get-ADGroupMember -Recursive | Get-ADObject -Properties AdminCount | `
        Select-Object *,@{Name="DesiredAdminCount";Expression={$AdminGroupObject.AdminCount}}
}

foreach ($AdminGroupObject in $AdminGroupObjects) {
    $AdminObjects+=$AdminGroupObject | Get-ADObject -Properties AdminCount | `
        Select-Object *,@{Name="DesiredAdminCount";Expression={$_.AdminCount}}
}

# Get-ADComputer -Filter "ServicePrincipalName -like 'MSServerClusterMgmtAPI/*'" | ForEach-Object {Get-Acl -Path "AD:$($_.DistinguishedName)"}
$ACLFileList=@()

$AdminObjects | Group-Object ObjectGUID | ForEach-Object {
    $ObjectState=$_.Group | Sort-Object DesiredAdminCount | Select-Object -First 1
    if (!($ObjectState.AdminCount -is [System.Int32]) -or $ObjectState.DesiredAdminCount -le $ObjectState.AdminCount) {
        if ($ObjectState.DesiredAdminCount -ne $ObjectState.AdminCount) {
            $UpdateLog+="$($ObjectState.DistinguishedName) `r`n`thas an AdminCount of '$($ObjectState.AdminCount)', `r`n`tDesired AdminCount is '$($ObjectState.DesiredAdminCount)', `r`n`t`tSetting AdminCount`r`n"
            Get-ADObject -Identity $ObjectState.DistinguishedName | Set-ADObject -Replace @{"AdminCount"=$ObjectState.DesiredAdminCount}
        }
        $AdminSDHolder=$AdminSDHolders | Where-Object {$_.AdminCount -eq $ObjectState.DesiredAdminCount}
        $NewACL=Get-Acl -Path "AD:\$($AdminSDHolder.DistinguishedName)"
        $WorkingACL=$NewACL
        if ($SpecialDescendantTypes -contains $ObjectState.ObjectClass) {
            $WorkingACL.Access | Where-Object {$schemaIDGUID[$ObjectState.ObjectClass] -eq $_.InheritedObjectType} | ForEach-Object {
                $ModifiedACE=New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
                    $_.IdentityReference,
                    $_.ActiveDirectoryRights,
                    $_.AccessControlType,
                    $_.ObjectType,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]'None',
                    [guid]'00000000-0000-0000-0000-000000000000'
                    )
                $NewACL.RemoveAccessRuleSpecific($_)
                $NewACL.AddAccessRule($ModifiedACE)
            }
        }
        @('Owner','Group') | ForEach-Object {
            $CurrentACL=Get-Acl -Path "AD:\$($ObjectState.DistinguishedName)"
            if ($CurrentACL."Get$_"([System.Security.Principal.NTAccount]) -ne $NewACL."Get$_"([System.Security.Principal.NTAccount])) {
                $UpdateLog+="$($ObjectState.DistinguishedName) `r`n`thas an $_ of '$($CurrentACL."$_")', `r`n`tDesired $_ is '$($NewACL."$_")', `r`n`t`tSetting $_`r`n"
                $CurrentACL."Set$_"($NewACL."Get$_"([System.Security.Principal.NTAccount]))
                Set-Acl -Path $CurrentACL.Path -AclObject $CurrentACL
            }
        }
        $CurrentACL=Get-Acl -Path "AD:\$($ObjectState.DistinguishedName)"
        if ((Compare-Sddl $CurrentACL.Sddl) -ne (Compare-Sddl $NewACL.Sddl)) {
            $CurrentACLFileName="$($PSScriptRoot)\$($ObjectState.Name)-Current_$(Get-Date -Format dd-MM-yy_HH_mm_ss).xml"
            $NewACLFileName="$($PSScriptRoot)\$($ObjectState.Name)-New_$(Get-Date -Format dd-MM-yy_HH_mm_ss).xml"
            $CurrentACL | Export-Clixml $CurrentACLFileName
            $NewACL | Export-Clixml $NewACLFileName
            $ACLFileList+=$CurrentACLFileName
            $ACLFileList+=$NewACLFileName
            $UpdateLog+="$($ObjectState.DistinguishedName) `r`n`thas a SDDL that is incorrect, `r`n`t`tSetting ACL`r`n"
            Set-Acl -Path "AD:\$($ObjectState.DistinguishedName)" -AclObject $NewACL
        }
    }
}


if ($UpdateLog.Count -gt 0) {
    $Message=New-Object Net.Mail.MailMessage
	
	$Message.From=$MailCredential.UserName
    $Message.ReplyTo=$MailCredential.UserName
    
    $MailTo | ForEach-Object {$Message.To.Add($_)}
    $MailCC | ForEach-Object {$Message.Cc.Add($_)}
    $MailBCC | ForEach-Object {$Message.Bcc.Add($_)}
    $Message.Subject=$MailSubject
    $Message.IsBodyHtml=$false
    $Message.Body=$UpdateLog
    $ACLFileList | ForEach-Object {$Message.Attachments.Add($_)}
    
    $SMTPMessage=New-Object Net.Mail.SmtpClient($MailServer)
	
	$SMTPMessage.EnableSSL=$true
	$SMTPMessage.Port=25
	$SMTPMessage.Credentials=$MailCredential
	$SMTPMessage.Send($Message)
}
