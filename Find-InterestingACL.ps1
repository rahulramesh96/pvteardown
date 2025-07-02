What does the below code do?

function Find-InterestingDomainAcl {
<#
.SYNOPSIS

Finds object ACLs in the current (or specified) domain with modification
rights set to non-built in objects.

Thanks Sean Metcalf (@pyrotek3) for the idea and guidance.

Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: Get-DomainObjectAcl, Get-DomainObject, Convert-ADName

.DESCRIPTION

This function enumerates the ACLs for every object in the domain with Get-DomainObjectAcl,
and for each returned ACE entry it checks if principal security identifier
is *-1000 (meaning the account is not built in), and also checks if the rights for
the ACE mean the object can be modified by the principal. If these conditions are met,
then the security identifier SID is translated, the domain object is retrieved, and
additional IdentityReference* information is appended to the output object.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER ResolveGUIDs

Switch. Resolve GUIDs to their display names.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Find-InterestingDomainAcl

Finds interesting object ACLS in the current domain.

.EXAMPLE

Find-InterestingDomainAcl -Domain dev.testlab.local -ResolveGUIDs

Finds interesting object ACLS in the ev.testlab.local domain and
resolves rights GUIDs to display names.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-InterestingDomainAcl -Credential $Cred -ResolveGUIDs

.OUTPUTS

PowerView.ACL

Custom PSObject with ACL entries.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $Domain,

        [Switch]
        $ResolveGUIDs,

        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ACLArguments = @{}
        if ($PSBoundParameters['ResolveGUIDs']) { $ACLArguments['ResolveGUIDs'] = $ResolveGUIDs }
        if ($PSBoundParameters['RightsFilter']) { $ACLArguments['RightsFilter'] = $RightsFilter }
        if ($PSBoundParameters['LDAPFilter']) { $ACLArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $ACLArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $ACLArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ACLArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ACLArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ACLArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ACLArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ACLArguments['Credential'] = $Credential }

        $ObjectSearcherArguments = @{
            'Properties' = 'samaccountname,objectclass'
            'Raw' = $True
        }
        if ($PSBoundParameters['Server']) { $ObjectSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ObjectSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ObjectSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ObjectSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ObjectSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ObjectSearcherArguments['Credential'] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }

        # ongoing list of built-up SIDs
        $ResolvedSIDs = @{}
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $ACLArguments['Domain'] = $Domain
            $ADNameArguments['Domain'] = $Domain
        }

        Get-DomainObjectAcl @ACLArguments | ForEach-Object {

            if ( ($_.ActiveDirectoryRights -match 'GenericAll|Write|Create|Delete') -or (($_.ActiveDirectoryRights -match 'ExtendedRight') -and ($_.AceQualifier -match 'Allow'))) {
                # only process SIDs > 1000
                if ($_.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if ($ResolvedSIDs[$_.SecurityIdentifier.Value]) {
                        $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass = $ResolvedSIDs[$_.SecurityIdentifier.Value]

                        $InterestingACL = New-Object PSObject
                        $InterestingACL | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                        $InterestingACL | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                        $InterestingACL | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $InterestingACL | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                        }
                        else {
                            $InterestingACL | Add-Member NoteProperty 'ObjectAceType' 'None'
                        }
                        $InterestingACL | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                        $InterestingACL | Add-Member NoteProperty 'AceType' $_.AceType
                        $InterestingACL | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                        $InterestingACL | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceName' $IdentityReferenceName
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDomain' $IdentityReferenceDomain
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDN' $IdentityReferenceDN
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceClass' $IdentityReferenceClass
                        $InterestingACL
                    }
                    else {
                        $IdentityReferenceDN = Convert-ADName -Identity $_.SecurityIdentifier.Value -OutputType DN @ADNameArguments
                        # "IdentityReferenceDN: $IdentityReferenceDN"

                        if ($IdentityReferenceDN) {
                            $IdentityReferenceDomain = $IdentityReferenceDN.SubString($IdentityReferenceDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            # "IdentityReferenceDomain: $IdentityReferenceDomain"
                            $ObjectSearcherArguments['Domain'] = $IdentityReferenceDomain
                            $ObjectSearcherArguments['Identity'] = $IdentityReferenceDN
                            # "IdentityReferenceDN: $IdentityReferenceDN"
                            $Object = Get-DomainObject @ObjectSearcherArguments

                            if ($Object) {
                                $IdentityReferenceName = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match 'computer') {
                                    $IdentityReferenceClass = 'computer'
                                }
                                elseif ($Object.Properties.objectclass -match 'group') {
                                    $IdentityReferenceClass = 'group'
                                }
                                elseif ($Object.Properties.objectclass -match 'user') {
                                    $IdentityReferenceClass = 'user'
                                }
                                else {
                                    $IdentityReferenceClass = $Null
                                }

                                # save so we don't look up more than once
                                $ResolvedSIDs[$_.SecurityIdentifier.Value] = $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass

                                $InterestingACL = New-Object PSObject
                                $InterestingACL | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                                $InterestingACL | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                                $InterestingACL | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $InterestingACL | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                                }
                                else {
                                    $InterestingACL | Add-Member NoteProperty 'ObjectAceType' 'None'
                                }
                                $InterestingACL | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                                $InterestingACL | Add-Member NoteProperty 'AceType' $_.AceType
                                $InterestingACL | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                                $InterestingACL | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceName' $IdentityReferenceName
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDomain' $IdentityReferenceDomain
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDN' $IdentityReferenceDN
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceClass' $IdentityReferenceClass
                                $InterestingACL
                            }
                        }
                        else {
                            Write-Warning "[Find-InterestingDomainAcl] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName"
                        }
                    }
                }
            }
        }
    }
}

Set-Alias Invoke-ACLScanner Find-InterestingDomainAcl
