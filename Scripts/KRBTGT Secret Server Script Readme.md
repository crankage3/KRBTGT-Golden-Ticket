# KRBTGT & Thycotic's Secret Server

**This script leverges the script provided by Microsoft and can be used for password changing. 
This original script can be found [here](https://github.com/microsoft/New-KrbtgtKeys.ps1/blob/master/New-KrbtgtKeys.ps1).**

Script Args are as follows:
- **invokemachine**: Machine that script will work in. Preferably one of the Domain Controllers

- **targetforest**: - For the AD forest to be targeted, please provide the FQDN or leave empty for the current AD forest

- **targetaddomain**: For the AD domain to be targeted, please provide the FQDN or leave empty for the current AD domain:

- **accountscope**: - The Scope of the KRBTGT Accounts to Target
    - #1 - Scope of KrbTgt in use by all RWDCs in the AD Domain (DEFAULT)***
    - #2 - Scope of KrbTgt in use by specific RODC - Single RODC in the AD Domain
    - #3 - Scope of KrbTgt in use by specific RODC - Multiple RODCs in the AD Domain
    - #4 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain

- **dcaccountlist**: Comma-Separated List of FQDN RODC of Krbtgt Accout Passwords To Reset
    ***(MUST not be empty if using account scope 2 or 3)***

- **username**: Username for other creds to invoke command creds

- **password**: Password for other creds to invoke command  creds

- **runoption**:  Run Option 
    - #1 - Informational Mode (No Changes At All)
    - #2 - Simulation Mode (Temporary Canary Object Created, No Password Reset!)
    - #3 - Simulation Mode - Use KrbTgt TEST/BOGUS Accounts (Password Will Be Reset Once!)
    - #4 - Real Reset Mode - Use KrbTgt PROD/REAL Accounts - (Password Will Be Reset Once!) (DEFAULT)***
    - #8 - Create TEST KrbTgt Accounts
    - #9 - Cleanup TEST KrbTgt Accounts
    - #0 - Exit Script 