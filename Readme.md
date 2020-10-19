# KRBTGT & Thycotic's Secret Server

**This script leverges the script provided by Microsoft and can be used for password changing. 
This original script can be found [here](https://github.com/microsoft/New-KrbtgtKeys.ps1/blob/master/New-KrbtgtKeys.ps1).**


## How to use in Secret Server 
The script leverages the powershell cmdlet "Invoke-Command". In order for the script to work, the environment and user that's running the script must be able to remote into the target machine. 

For help with environment setup, [go here](https://docs.thycotic.com/ss/10.8.0/api-scripting/configuring-winrm-powershell/index.md).

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
        - "Invoke Machine" -> Machine to Invoke Into
        - "Target AD Forest" -> Target AD Forest - (Can be empty)
        - "Target AD Domain" -> Target AD Domain - (Can be empty)
        - "Account Scope" -> Script Scope to run 1 - 4
            - 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain (DEFAULT)***
            - 2 - Scope of KrbTgt in use by specific RODC - Single RODC in the AD Domain
            - 3 - Scope of KrbTgt in use by specific RODC - Multiple RODCs in the AD Domain
            - 4 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain
        - "AD Domain Controller Account(s)" -> AD Domain Controller Account to Target
        - "Run Option" -> Run Option
            - 1 - Informational Mode (No Changes At All)
            - 2 - Simulation Mode (Temporary Canary Object Created, No Password Reset!)
            - 3 - Simulation Mode - Use KrbTgt TEST/BOGUS Accounts (Password Will Be Reset Once!)
            - 4 - Real Reset Mode - Use KrbTgt PROD/REAL Accounts - (Password Will Be Reset Once!) (DEFAULT)***
            - 8 - Create TEST KrbTgt Accounts
            - 9 - Cleanup TEST KrbTgt Accounts
            - 0 - Exit Script 
        - "Log Path" -> Desired Log Path (will log to "Invoke Machine")
        - "Fake Password" -> Fake Password (Secret Server Workaroud)

    4. Click "Configure Password Changing
    5. Click "Edit"
    6. Check "Enable Password Changing 
    7. Select the Password Type from above for "Password Type To Use"
    8. Fill in other password change setting desired.
    9. Save