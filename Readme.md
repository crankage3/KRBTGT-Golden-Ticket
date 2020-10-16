# KRBTGT & Thycotic's Secret Server

**This script leverges the script provided by Microsoft and can be used for password changing. 
This original script can be found [here](https://github.com/microsoft/New-KrbtgtKeys.ps1/blob/master/New-KrbtgtKeys.ps1).**


## How to use in Secret Server 
1. **Create Script in Secret Server (Powershell)**
    1. Go to Admin -> Scripts
    2. Under the "Powershell" tab, click "Create New"
    3. Copy the Script "KRBTGT Secret Server Script.ps1" and click "Ok"
2. **Create Password Type that uses the Script that was created.**
    1. Go to Admin -> Remote Password Changing
    2. Click "Configure Password Changing"
    3. Click "New"
    4. Select "Powershell Script" as the Base Password Changer, enter name and save. ("Example: KRBTGT Password Change)
    5. Under "Password Change Commands" select the script created and enter the following as args: ` -InvokeMachine $INVOKE MACHINE -targetAdforest $TARGET AD FOREST -targetaddomain $TARGET AD DOMAIN -accountscope $Account Scope -dcaccountlist $AD Domain Controller Account(s) -username $[1]$USERNAME -password $[1]$PASSWORD -runoption $RUN OPTION -logpath $LOG PATH`
    6. Save
3. **Create a Secret Template that using the Password type previously created.**
    1. Go to Admin -> Secret Templates
    2. Click "Create New"
    3. Create the following Secret Fields
        - Field
        - Field
        - Field
        - Field
        - Field
        - Field
    4. Click "Configure Password Changing
    5. Click "Edit"
    6. Check "Enable Password Changing 
    7. Select the Password Type from above for "Password Type To Use"
    8. Fill in other password change setting desired.
    9. Save