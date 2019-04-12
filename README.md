# Custom Admin Count

## This contains the Powershell for extending AdminCount logic to something custom that you control

## Information

The idea with this script is to extend the mysterious AdminCount process to something that can be customized
and used for more than just 1 ACL or privilege level. While arguably JEA can fill this need, I see this as an
and/or scenario in that regard. Whether you use this so that less than DA tiers can administer with ADUC or
using the principle of least privilege for the service account running your JEA endpoint, there is value here :).

## Features

Legend:  
_ACE = Access control entry (singular)_  
_ACL = Access control list (multiple ACE's), along with owner,group_  

* Decouples permissions from the standard OU based permissions dependencies

* Uses the same concepts as the built in Protected ACL Holder based on the AdminCount integer attribute.
  * This means the membership of the object to be protected is more important than its location in the directory tree
  * The closer to 0 the objects AdminCount, the more weight used to apply the desired ACL
    * If an object is a member of a group with an AdminCount of 10 and a member of another group with an AdminCount of 20
    the Container that holds the number 10 will be used as the baseline ACL

* Fixes limitations of the built in ProtectedSDHolder process
  * When creating an ACE with 'Descendant _ObjectType_' on the underlying Container object pinning the ACL it doesn't work as AD
  doesn't do sanity checks for SDDL inheritance types
    * For example, 'Write members of Descendant Users only' when applied to a user doesn't work because the user itself needs the ACE
    with the 'This object only' inheritance type
    * Special filtering for User, Groups, and Computers built in by default (can be modified for your deployment) so that this
    behaviour translates when applied to the targetted inheritance type

* Email reporting sent if there are any changes made, with attached timestamped xml files that can be used with Import-Clixml to revert changes (Acl Object - get/set-acl)

```powershell
.\Set-AdminSDHolders.ps1 `
    -AdminSDHolderDN "OU=System,DC=example,DC=com" `
    -ADCredential $ADCredential `
    -MailTo "first-to@example.com","second-to@example.com" `
    -MailCC "first-cc@example.com","second-cc@example.com" `
    -MailBCC "first-bcc@example.com","second-bcc@example.com" `
    -MailSubject "example.com - AdminCount modification report" `
    -MailCredential $MailCredential
```