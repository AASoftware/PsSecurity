# Import necessary .NET classes
Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

# Define input parameters
$domainController = "dc01"
$domain = "prime.pri"
$username = "aleks0001"
$password = "Testblabla1!"

function Get-DirectoryEntry {
    param (
        [string]$domainController,
        [string]$domain,
        [string]$username,
        [string]$password
    )
    
    $ldapPath = "LDAP://$domainController.$domain"
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    $credential = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, "$username@$domain", $password)
    return $credential
}

function Get-AllUserAccounts {
    param (
        [System.DirectoryServices.DirectoryEntry]$credential
    )
    
    $users = @{}
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($credential)
    $directorySearcher.Filter = "(&(objectClass=user)(objectCategory=person))"
    $directorySearcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
    $directorySearcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
    $directorySearcher.PageSize = 1000

    try {
        $searchResults = $directorySearcher.FindAll()
        foreach ($result in $searchResults) {
            $userEntry = $result.GetDirectoryEntry()
            $sAMAccountName = $userEntry.Properties["sAMAccountName"].Value
            $distinguishedName = $userEntry.Properties["distinguishedName"].Value
            
            if ($sAMAccountName -and $distinguishedName) {
                $users[$sAMAccountName] = $distinguishedName
            }
        }
    } catch {
        Write-Error "Error retrieving user accounts: $_"
    }
    return $users
}

function Get-AllGroups {
    param (
        [System.DirectoryServices.DirectoryEntry]$credential
    )
    
    $groups = @{}
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($credential)
    $directorySearcher.Filter = "(&(objectClass=group)(objectCategory=group))"
    $directorySearcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
    $directorySearcher.PropertiesToLoad.Add("member") | Out-Null
    $directorySearcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
    $directorySearcher.PageSize = 1000

    try {
        $searchResults = $directorySearcher.FindAll()
        foreach ($result in $searchResults) {
            $groupEntry = $result.GetDirectoryEntry()
            $sAMAccountName = $groupEntry.Properties["sAMAccountName"].Value
            $members = $groupEntry.Properties["member"]
            $distinguishedName = $groupEntry.Properties["distinguishedName"].Value
            
            if ($sAMAccountName -and $distinguishedName) {
                $groups[$sAMAccountName] = @{
                    DN = $distinguishedName
                    Members = $members
                }
            }
        }
    } catch {
        Write-Error "Error retrieving groups: $_"
    }
    return $groups
}

function Get-UserGroups {
    param (
        [string]$userDN,
        [hashtable]$groups,
        [string[]]$processedGroups = @()
    )
    
    $userGroups = @()
    foreach ($group in $groups.GetEnumerator()) {
        if ($group.Value.Members -contains $userDN -and $processedGroups -notcontains $group.Key) {
            $userGroups += $group.Key
            $processedGroups += $group.Key
            $userGroups += Get-UserGroups -userDN $group.Value.DN -groups $groups -processedGroups $processedGroups
        }
    }
    return $userGroups
}

function Get-UsersWithSPN {
    param (
        [System.DirectoryServices.DirectoryEntry]$credential
    )
    
    $usersWithSPN = @()
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($credential)
    $directorySearcher.Filter = "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))"
    $directorySearcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
    $directorySearcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
    $directorySearcher.PageSize = 1000

    try {
        $searchResults = $directorySearcher.FindAll()
        foreach ($result in $searchResults) {
            $userEntry = $result.GetDirectoryEntry()
            $sAMAccountName = $userEntry.Properties["sAMAccountName"].Value
            $spns = $userEntry.Properties["servicePrincipalName"]

            if ($sAMAccountName -and $spns.Count -gt 0) {
                $usersWithSPN += $sAMAccountName
            }
        }
    } catch {
        Write-Error "Error retrieving users with SPN: $_"
    }
    return $usersWithSPN
}

function Get-UsersWithNoKerberosPreAuth {
    param (
        [System.DirectoryServices.DirectoryEntry]$credential
    )

    $usersWithNoKerberosPreAuth = @()
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($credential)
    $directorySearcher.Filter = "(&(objectClass=user)(objectCategory=person))"
    $directorySearcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
    $directorySearcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
    $directorySearcher.PageSize = 1000

    try {
        $searchResults = $directorySearcher.FindAll()
        foreach ($result in $searchResults) {
            $userEntry = $result.GetDirectoryEntry()
            $sAMAccountName = $userEntry.Properties["sAMAccountName"].Value
            $userAccountControl = [int]$userEntry.Properties["userAccountControl"].Value
            
            # Bit for "Do not require Kerberos preauthentication" is 0x00040000
            if ($userAccountControl -eq 4260352) {
                $usersWithNoKerberosPreAuth += $sAMAccountName
            }
        }
    } catch {
        Write-Error "Error retrieving users without Kerberos preauthentication: $_"
    }
    return $usersWithNoKerberosPreAuth
}

function Write-OutputToFile {
    param (
        [string]$outputFile,
        [hashtable]$userGroups,
        [hashtable]$allUsers,
        [string[]]$usersWithSPN,
        [string[]]$usersWithNoKerberosPreAuth
    )

    $outputContent = @()

    # User list
    $outputContent += "Users:"
    $outputContent += ""
    foreach ($user in $allUsers.Keys) {
        $outputContent += $user
    }
    $outputContent += ""
    
    # SPN user list
    $outputContent += "Users with SPN set:"
    $outputContent += ""
    foreach ($user in $usersWithSPN) {
        $outputContent += $user
    }
    $outputContent += ""

    # Users without Kerberos preauthentication
    $outputContent += "Users with 'Do not require Kerberos preauthentication':"
    $outputContent += ""
    foreach ($user in $usersWithNoKerberosPreAuth) {
        $outputContent += $user
    }
    $outputContent += ""
    
    # Group memberships
    $outputContent += "Group Membership Recursively:"
    $outputContent += ""
    
    foreach ($user in $userGroups.Keys) {
        $outputContent += "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        $outputContent += "$user"
        
        $userGroupList = $userGroups[$user]
        if ($userGroupList.Count -gt 0) {
            foreach ($group in $userGroupList) {
                $outputContent += $group
            }
        } else {
            $outputContent += "No groups found"
        }

        $outputContent += "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        $outputContent += ""
    }

    # Ensure the directory exists
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }

    # Write output to file
    $outputFile = "$outputDirectory\output.txt"
    $outputContent | Set-Content -Path $outputFile
    Write-Output "Report successfully created: $outputFile"
}

# Create DirectoryEntry object with credentials
$credential = Get-DirectoryEntry -domainController $domainController -domain $domain -username $username -password $password

# Query all users and groups
$allUsers = Get-AllUserAccounts -credential $credential
$allGroups = Get-AllGroups -credential $credential

# Determine user-group mapping
$userGroups = @{}
foreach ($user in $allUsers.Keys) {
    $userDN = $allUsers[$user]
    $userGroupList = Get-UserGroups -userDN $userDN -groups $allGroups
    $userGroups[$user] = $userGroupList | Sort-Object -Unique
}

# Query users with SPN
$usersWithSPN = Get-UsersWithSPN -credential $credential

# Query users without Kerberos preauthentication
$usersWithNoKerberosPreAuth = Get-UsersWithNoKerberosPreAuth -credential $credential

# Write output to file
Write-OutputToFile -outputFile "C:\temp\output.txt" -userGroups $userGroups -allUsers $allUsers -usersWithSPN $usersWithSPN -usersWithNoKerberosPreAuth $usersWithNoKerberosPreAuth

function Get-ObjectPermissions {
    param (
        [System.DirectoryServices.DirectoryEntry]$entry
    )

    $permissions = @()
    $acl = $entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    
    foreach ($rule in $acl) {
        $sid = $rule.IdentityReference.Value
        $accessRights = $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow

        $permissions += [PSCustomObject]@{
            SID = $sid
            UserOrGroup = Translate-SID -sid $sid
            GenericAll = $accessRights -and ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
            GenericWrite = $accessRights -and ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
            WriteOwner = $accessRights -and ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)
            WriteDACL = $accessRights -and ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)
            AllExtendedRights = $accessRights -and ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
            ForceChangePassword = $accessRights -and ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ChangePassword)
            Path = $entry.Path
        }
    }

    return $permissions
}

function Translate-SID {
    param (
        [string]$sid
    )

    try {
        $securityIdentifier = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $ntAccount = $securityIdentifier.Translate([System.Security.Principal.NTAccount])
        return $ntAccount.Value
    } catch {
        return "Unknown or unresolved"
    }
}

function Get-AllObjects {
    param (
        [System.DirectoryServices.DirectoryEntry]$credential,
        [string]$filter
    )
    
    $objects = @()
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($credential)
    $directorySearcher.Filter = $filter
    $directorySearcher.PageSize = 1000

    try {
        $searchResults = $directorySearcher.FindAll()
        foreach ($result in $searchResults) {
            $entry = $result.GetDirectoryEntry()
            $objects += $entry
        }
    } catch {
        Write-Error "Error retrieving objects: $_"
    }
    return $objects
}

function Write-OutputToFile {
    param (
        [string]$outputFile,
        [array]$permissions
    )

    # Remove unresolvable SIDs and special users/groups
    $filteredPermissions = $permissions | Where-Object { 
        $_.UserOrGroup -ne "Unknown or unresolved" -and
        $_.UserOrGroup -notin @(
            "NT AUTHORITY\SYSTEM",
            "NT AUTHORITY\SELF",
            "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS",
            "CREATOR OWNER"
        )
    }

    $outputContent = @()
    $outputContent += "User/Group and their permissions:"
    $outputContent += ""

    foreach ($perm in $filteredPermissions) {
        $outputContent += "SID: $($perm.SID)"
        $outputContent += "User/Group: $($perm.UserOrGroup)"
        $outputContent += "Object Path: $($perm.Path)"
        $outputContent += "GenericAll: $($perm.GenericAll)"
        $outputContent += "GenericWrite: $($perm.GenericWrite)"
        $outputContent += "WriteOwner: $($perm.WriteOwner)"
        $outputContent += "WriteDACL: $($perm.WriteDACL)"
        $outputContent += "AllExtendedRights: $($perm.AllExtendedRights)"
        $outputContent += "ForceChangePassword: $($perm.ForceChangePassword)"
        $outputContent += "------------------------------"
        $outputContent += ""
    }

    # Ensure the directory exists
    $outputDirectory = "C:\temp"
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }

    # Write output to file
    $outputFile = "$outputDirectory\permissions_summary.txt"
    $outputContent | Set-Content -Path $outputFile
    Write-Output "Report successfully created: $outputFile"
}

function Get-UserAndGroupDetails {
    param (
        [string]$domain,
        [string]$username,
        [string]$password
    )
    
    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain, $username, $password)
    $principals = @()

    # Query users
    $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::new($context)
    $searcher = [System.DirectoryServices.AccountManagement.PrincipalSearcher]::new($userPrincipal)
    $userResults = $searcher.FindAll()
    foreach ($user in $userResults) {
        $principals += [PSCustomObject]@{
            Name = $user.SamAccountName
            Type = "UserPrincipal"
        }
    }

    # Query groups
    $groupPrincipal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::new($context)
    $searcher = [System.DirectoryServices.AccountManagement.PrincipalSearcher]::new($groupPrincipal)
    $groupResults = $searcher.FindAll()
    foreach ($group in $groupResults) {
        $principals += [PSCustomObject]@{
            Name = $group.SamAccountName
            Type = "GroupPrincipal"
        }
    }

    return $principals
}

# Create DirectoryEntry object with credentials
$credential = Get-DirectoryEntry -domainController $domainController -domain $domain -username $username -password $password

# Query all users and groups
$allPrincipals = Get-UserAndGroupDetails -domain $domain -username $username -password $password
$permissions = @()

# Retrieve permissions for all users and groups
foreach ($principal in $allPrincipals) {
    # Retrieve in DirectoryEntry format
    $entry = Get-AllObjects -credential $credential -filter "(samAccountName=$($principal.Name))"
    foreach ($object in $entry) {
        $objectPermissions = Get-ObjectPermissions -entry $object
        $permissions += $objectPermissions
    }
}

# Write output to file
Write-OutputToFile -outputFile "C:\temp\permissions_summary.txt" -permissions $permissions
