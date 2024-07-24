# PsSecurity
Powershell Security Toolset
Alpha 0.1
bug in generic All membership

Overview:

This PowerShell script is designed for comprehensive analysis and documentation of permissions and group memberships in an Active Directory (AD) environment. It operates without requiring administrative privileges or specific Active Directory modules, making it accessible for users with standard permissions. The tool relies on plain PowerShell and imports necessary .NET assemblies to perform its tasks.

Key Features:

No Administrative Privileges Required:

The script does not require administrative rights to execute. It can run with standard user permissions.
No Active Directory Modules Needed:

Utilizes plain PowerShell without the need for additional Active Directory modules.

.NET Assemblies:

Imports .NET assemblies (System.DirectoryServices and System.DirectoryServices.AccountManagement) to interact with AD and perform operations.

Directory Access:

Connects to an AD domain controller using provided credentials.
Retrieves and processes data related to users and groups.

User and Group Retrieval:

User Accounts: 

Enumerates all user accounts within the AD domain.

Groups: 

Enumerates all groups within the AD domain and their members.

Recursive Group Memberships:

For each user, identifies all groups they belong to, including nested groups.
Recursively traverses through group memberships to provide a complete view of group affiliations.

Service Principal Names (SPNs):

Identifies users with Service Principal Names (SPNs) set, which are used for Kerberos authentication.

Kerberos Preauthentication:

Detects users configured with the "Do not require Kerberos preauthentication" setting, which may pose a security risk.

Permissions Analysis:

Retrieves detailed permissions for AD objects (users and groups) including:

Generic All: Full control permissions.

Generic Write: Permissions to write properties.

Write Owner: Permissions to change the owner of the object.

Write DACL: Permissions to modify the 
Discretionary Access Control List.

All Extended Rights: Permissions related to extended rights.

Force Change Password: Permissions to force a password change.

Output Generation:

Creates a report summarizing:

User List: All user accounts.

Users with SPNs: Users having SPNs set.

Users with No Kerberos Preauthentication: Users with the specified setting.

Recursive Group Memberships: Detailed group memberships for each user.

Permissions Summary: Detailed permissions for users and groups, excluding common or special accounts.

File Export:

Writes the collected data to text files located in C:\temp, ensuring that the directory exists before creating the files.

Usage:

Set the AD domain controller, domain, username, and password.

Execution:

Run the PowerShell script. It will connect to the domain controller, gather the necessary data, and generate a detailed report.

Review:

Review the output files for information on user and group memberships, permissions, SPNs, and Kerberos preauthentication settings.
Benefits
Provides a detailed view of AD permissions and group memberships.
Identifies potential security risks associated with SPNs and Kerberos settings.
Facilitates auditing and compliance efforts by documenting permissions and access rights.
Operates without requiring administrative privileges or specific AD modules.
