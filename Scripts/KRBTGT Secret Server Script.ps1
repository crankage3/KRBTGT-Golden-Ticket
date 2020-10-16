<#
	-invokemachine: Machine that script will work in. Preferably one of the Domain Controllers

	-targetforest: - For the AD forest to be targeted, please provide the FQDN or leave empty for the current AD forest

	-targetaddomain: For the AD domain to be targeted, please provide the FQDN or leave empty for the current AD domain:
	
	-accountscope: - THE SCOPE OF THE KRBTGT ACCOUNT(S) TO TARGET
		#1 - Scope of KrbTgt in use by all RWDCs in the AD Domain (DEFAULT)***
		#2 - Scope of KrbTgt in use by specific RODC - Single RODC in the AD Domain
		#3 - Scope of KrbTgt in use by specific RODC - Multiple RODCs in the AD Domain
		#4 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain

	-dcaccountlist: Comma-Separated List of FQDN RODC of Krbtgt Accout Passwords To Reset
		(*** MUST not be empty if using account scope 2 or 3 ***)

	-username: Username for other creds to invoke command creds
	
	-password: Password for other creds to invoke command  creds
	
	-runoption:  Maybe add a run option?
		#1 - Informational Mode (No Changes At All)
		#2 - Simulation Mode (Temporary Canary Object Created, No Password Reset!)
		#3 - Simulation Mode - Use KrbTgt TEST/BOGUS Accounts (Password Will Be Reset Once!)
		#4 - Real Reset Mode - Use KrbTgt PROD/REAL Accounts (Password Will Be Reset Once!) (DEFAULT)***
 		#8 - Create TEST KrbTgt Accounts
		#9 - Cleanup TEST KrbTgt Accounts
		#0 - Exit Script 
#>
function RunGoldenTicketScript {
	param(
    	[Parameter()]
        [string]$POC_AdForestFQDN,
		
    	[Parameter()]
        [string]$POC_DomainFQDN,
				
		[Parameter()]
        [string]$POC_KRBTGT_Account_Scope,
		
		[Parameter()]
        [string]$POC_DomainControllerFQDN_List,
        		
        [Parameter()]
		[string]$POC_RunOption,

        [Parameter()]
		[string]$POC_LogPath
		)
	
	$ver
	Function Logging($dataToLog, $lineType) {
		$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
		Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
		if($lineType -eq "ERROR"){
			Write-Error $dataToLog
		}
	}

	Function portConnectionCheck($fqdnServer,$port,$timeOut) {
		$tcpPortSocket = $null
		$portConnect = $null
		$tcpPortWait = $null
		$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
		$portConnect = $tcpPortSocket.BeginConnect($fqdnServer,$port,$null,$null)
		$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut,$false)
		If(!$tcpPortWait) {
			$tcpPortSocket.Close()
			Return "ERROR"
		} Else {

			$ErrorActionPreference = "SilentlyContinue"
			$tcpPortSocket.EndConnect($portConnect) | Out-Null
			If (!$?) {
				Return "ERROR"
			} Else {
				Return "SUCCESS"
			}
			$tcpPortSocket.Close()
			$ErrorActionPreference = "Continue"
		}
	}

	Function loadPoSHModules($PoSHModule) {
		$retValue = $null
		If(@(Get-Module | Where-Object{$_.Name -eq $PoSHModule}).count -eq 0) {
			If(@(Get-Module -ListAvailable | Where-Object{$_.Name -eq $PoSHModule} ).count -ne 0) {
				Import-Module $PoSHModule
				Logging "PoSH Module '$PoSHModule' Has Been Loaded..." "SUCCESS"
				$retValue = "HasBeenLoaded"
			} Else {
				Logging "PoSH Module '$PoSHModule' Is Not Available To Load..." "ERROR"
				Logging "Aborting Script..." "ERROR"
				$retValue = "NotAvailable"
			}
		} Else {
			Logging "PoSH Module '$PoSHModule' Already Loaded..." "SUCCESS"
			$retValue = "AlreadyLoaded"
		}
		Return $retValue
	}

	Function testAdminRole($adminRole) {

		$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

		(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
	}

	Function createTempCanaryObject($targetedADdomainRWDC, $krbTgtSamAccountName, $execDateTimeCustom1, $localADforest, $remoteCredsUsed, $adminCreds) {

		$targetedADdomainDefaultNC = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDC).defaultNamingContext
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDC -Credential $adminCreds).defaultNamingContext
		}

		$containerForTempCanaryObject = $null
		$containerForTempCanaryObject = "CN=Users," + $targetedADdomainDefaultNC

		$targetObjectToCheckName = $null
		$targetObjectToCheckName = "_adReplTempObject_" + $krbTgtSamAccountName + "_" + $execDateTimeCustom1

		$targetObjectToCheckDescription = "...!!!.TEMP OBJECT TO CHECK AD REPLICATION IMPACT.!!!..."

		$targetObjectToCheckDN = $null
		$targetObjectToCheckDN = "CN=" + $targetObjectToCheckName + "," + $containerForTempCanaryObject
		Logging "  --> RWDC To Create Object On..............: '$targetedADdomainRWDC'"
		Logging "  --> Full Name Temp Canary Object..........: '$targetObjectToCheckName'"
		Logging "  --> Description...........................: '$targetObjectToCheckDescription'"
		Logging "  --> Container For Temp Canary Object......: '$containerForTempCanaryObject'"
		Logging ""

		Try {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				New-ADObject -Type contact -Name $targetObjectToCheckName -Path $containerForTempCanaryObject -DisplayName $targetObjectToCheckName -Description $targetObjectToCheckDescription -Server $targetedADdomainRWDC
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				New-ADObject -Type contact -Name $targetObjectToCheckName -Path $containerForTempCanaryObject -DisplayName $targetObjectToCheckName -Description $targetObjectToCheckDescription -Server $targetedADdomainRWDC -Credential $adminCreds
			}
		} Catch {
			Logging "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDC]!..." "ERROR"
			Logging "" "ERROR"
		}

		$targetObjectToCheck = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))" -Server $targetedADdomainRWDC
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))" -Server $targetedADdomainRWDC -Credential $adminCreds
		}
		If ($targetObjectToCheck) {
			$targetObjectToCheckDN = $null
			$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName
			Logging "  --> Temp Canary Object [$targetObjectToCheckDN] CREATED on RWDC [$targetedADdomainRWDC]!..." "REMARK"
			Logging "" "REMARK"
		}
		Return $targetObjectToCheckDN
	}

	Function confirmPasswordIsComplex($pwd) {
		Process {
			$criteriaMet = 0

			If ($pwd -cmatch '[A-Z]') {$criteriaMet++}

			If ($pwd -cmatch '[a-z]') {$criteriaMet++}

			If ($pwd -match '\d') {$criteriaMet++}

			If ($pwd -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$criteriaMet++}

			If ($criteriaMet -lt 3) {Return $false}
			If ($pwd.Length -lt 8) {Return $false}
			Return $true
		}
	}

	Function generateNewComplexPassword([int]$passwordNrChars) {
		Process {
			$iterations = 0
			Do {
				If ($iterations -ge 20) {
					Logging "  --> Complex password generation failed after '$iterations' iterations..." "ERROR"
					Logging "" "ERROR"
					EXIT
				}
				$iterations++
				$pwdBytes = @()
				$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
				Do {
					[byte[]]$byte = [byte]1
					$rng.GetBytes($byte)
					If ($byte[0] -lt 33 -or $byte[0] -gt 126) {
						CONTINUE
					}
					$pwdBytes += $byte[0]
				}
				While ($pwdBytes.Count -lt $passwordNrChars)
					$pwd = ([char[]]$pwdBytes) -join ''
				} 
			Until (confirmPasswordIsComplex $pwd)
			Return $pwd
		}
	}

	Function setPasswordOfADAccount($targetedADdomainRWDC, $krbTgtSamAccountName, $localADforest, $remoteCredsUsed, $adminCreds) {

		$krbTgtObjectBefore = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDC
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDC -Credential $adminCreds
		}

		$krbTgtObjectBeforeDN = $null
		$krbTgtObjectBeforeDN = $krbTgtObjectBefore.DistinguishedName

		$krbTgtObjectBeforePwdLastSet = $null
		$krbTgtObjectBeforePwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectBefore.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

		$metadataObjectBefore = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$metadataObjectBefore = Get-ADReplicationAttributeMetadata $krbTgtObjectBeforeDN -Server $targetedADdomainRWDC
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$metadataObjectBefore = Get-ADReplicationAttributeMetadata $krbTgtObjectBeforeDN -Server $targetedADdomainRWDC -Credential $adminCreds
		}
		$metadataObjectBeforeAttribPwdLastSet = $null
		$metadataObjectBeforeAttribPwdLastSet = $metadataObjectBefore | Where-Object{$_.AttributeName -eq "pwdLastSet"}
		$orgRWDCNTDSSettingsObjectDNBefore = $null
		$orgRWDCNTDSSettingsObjectDNBefore = $metadataObjectBeforeAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
		$metadataObjectBeforeAttribPwdLastSetOrgRWDCFQDN = $null
		If ($orgRWDCNTDSSettingsObjectDNBefore) {			

			$orgRWDCServerObjectDNBefore = $null
			$orgRWDCServerObjectDNBefore = $orgRWDCNTDSSettingsObjectDNBefore.SubString(("CN=NTDS Settings,").Length)

			$orgRWDCServerObjectObjBefore = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				$orgRWDCServerObjectObjBefore = ([ADSI]"LDAP://$targetedADdomainRWDC/$orgRWDCServerObjectDNBefore")
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				$orgRWDCServerObjectObjBefore = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainRWDC/$orgRWDCServerObjectDNBefore"),$($adminCreds.UserName), $($adminCreds.GetNetworkCredential().password))
			}
			$metadataObjectBeforeAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObjBefore.dnshostname[0]
		} Else {
			$metadataObjectBeforeAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
		}
		$metadataObjectBeforeAttribPwdLastSetOrgTime = $null
		$metadataObjectBeforeAttribPwdLastSetOrgTime = Get-Date $($metadataObjectBeforeAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
		$metadataObjectBeforeAttribPwdLastSetVersion = $null
		$metadataObjectBeforeAttribPwdLastSetVersion = $metadataObjectBeforeAttribPwdLastSet.Version
		
		Logging "  --> RWDC To Reset Password On.............: '$targetedADdomainRWDC'"
		Logging "  --> sAMAccountName Of KrbTgt Account......: '$krbTgtSamAccountName'"
		Logging "  --> Distinguished Name Of KrbTgt Account..: '$krbTgtObjectBeforeDN'"

		$passwordNrChars = 64
		Logging "  --> Number Of Chars For Pwd Generation....: '$passwordNrChars'"

		$newKrbTgtPassword = $null
		$newKrbTgtPassword = (generateNewComplexPassword $passwordNrChars).ToString()

		$newKrbTgtPasswordSecure = $null
		$newKrbTgtPasswordSecure = ConvertTo-SecureString $newKrbTgtPassword -AsPlainText -Force

		Try {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				Set-ADAccountPassword -Identity $krbTgtObjectBeforeDN -Server $targetedADdomainRWDC -Reset -NewPassword $newKrbTgtPasswordSecure
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				Set-ADAccountPassword -Identity $krbTgtObjectBeforeDN -Server $targetedADdomainRWDC -Reset -NewPassword $newKrbTgtPasswordSecure -Credential $adminCreds
			}
		} Catch {
			Logging ""
			Logging "  --> Setting the new password for [$krbTgtObjectBeforeDN] FAILED on RWDC [$targetedADdomainRWDC]!..." "ERROR"
			Logging "" "ERROR"
		}

		$krbTgtObjectAfter = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$krbTgtObjectAfter = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDC
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$krbTgtObjectAfter = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDC -Credential $adminCreds
		}

		$krbTgtObjectAfterDN = $null
		$krbTgtObjectAfterDN = $krbTgtObjectAfter.DistinguishedName

		$krbTgtObjectAfterPwdLastSet = $null
		$krbTgtObjectAfterPwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectAfter.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

		$metadataObjectAfter = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$metadataObjectAfter = Get-ADReplicationAttributeMetadata $krbTgtObjectAfterDN -Server $targetedADdomainRWDC
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$metadataObjectAfter = Get-ADReplicationAttributeMetadata $krbTgtObjectAfterDN -Server $targetedADdomainRWDC -Credential $adminCreds
		}
		$metadataObjectAfterAttribPwdLastSet = $null
		$metadataObjectAfterAttribPwdLastSet = $metadataObjectAfter | Where-Object{$_.AttributeName -eq "pwdLastSet"}
		$orgRWDCNTDSSettingsObjectDNAfter = $null
		$orgRWDCNTDSSettingsObjectDNAfter = $metadataObjectAfterAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
		$metadataObjectAfterAttribPwdLastSetOrgRWDCFQDN = $null
		If ($orgRWDCNTDSSettingsObjectDNAfter) {			

			$orgRWDCServerObjectDNAfter = $null
			$orgRWDCServerObjectDNAfter = $orgRWDCNTDSSettingsObjectDNAfter.SubString(("CN=NTDS Settings,").Length)

			$orgRWDCServerObjectObjAfter = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				$orgRWDCServerObjectObjAfter = ([ADSI]"LDAP://$targetedADdomainRWDC/$orgRWDCServerObjectDNAfter")
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				$orgRWDCServerObjectObjAfter = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainRWDC/$orgRWDCServerObjectDNAfter"),$($adminCreds.UserName), $($adminCreds.GetNetworkCredential().password))
			}
			$metadataObjectAfterAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObjAfter.dnshostname[0]
		} Else {
			$metadataObjectAfterAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
		}
		$metadataObjectAfterAttribPwdLastSetOrgTime = $null
		$metadataObjectAfterAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAfterAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
		$metadataObjectAfterAttribPwdLastSetVersion = $null
		$metadataObjectAfterAttribPwdLastSetVersion = $metadataObjectAfterAttribPwdLastSet.Version
		Logging ""
		Logging "  --> Previous Password Set Date/Time.......: '$krbTgtObjectBeforePwdLastSet'"
		If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
			Logging "  --> New Password Set Date/Time............: '$krbTgtObjectAfterPwdLastSet'"
		}
		Logging ""
		Logging "  --> Previous Originating RWDC.............: '$metadataObjectBeforeAttribPwdLastSetOrgRWDCFQDN'"
		If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
			Logging "  --> New Originating RWDC..................: '$metadataObjectAfterAttribPwdLastSetOrgRWDCFQDN'"
		}
		Logging ""
		Logging "  --> Previous Originating Time.............: '$metadataObjectBeforeAttribPwdLastSetOrgTime'"
		If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
			Logging "  --> New Originating Time..................: '$metadataObjectAfterAttribPwdLastSetOrgTime'"
		}
		Logging ""
		Logging "  --> Previous Version Of Attribute Value...: '$metadataObjectBeforeAttribPwdLastSetVersion'"
		If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
			Logging "  --> New Version Of Attribute Value........: '$metadataObjectAfterAttribPwdLastSetVersion'"
		}

		If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
			Logging ""
			Logging "  --> The new password for [$krbTgtObjectAfterDN] HAS BEEN SET on RWDC [$targetedADdomainRWDC]!..." "REMARK"
			Logging "" "REMARK"
		}
	}

	Function replicateSingleADObject($sourceDCNTDSSettingsObjectDN, $targetDCFQDN, $objectDN, $contentScope, $localADforest, $remoteCredsUsed, $adminCreds) {

		$rootDSE = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$rootDSE = [ADSI]"LDAP://$targetDCFQDN/rootDSE"
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$rootDSE = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetDCFQDN/rootDSE"),$($adminCreds.UserName), $($adminCreds.GetNetworkCredential().password))
		}

		If ($contentScope -eq "Full") {
			$rootDSE.Put("replicateSingleObject",$sourceDCNTDSSettingsObjectDN+":"+$objectDN)
		}

		If ($contentScope -eq "Secrets") {
			$rootDSE.Put("replicateSingleObject",$sourceDCNTDSSettingsObjectDN+":"+$objectDN+":SECRETS_ONLY")
		}	

		$rootDSE.SetInfo()
	}

	Function deleteTempCanaryObject($targetedADdomainRWDC, $targetObjectToCheckDN, $localADforest, $remoteCredsUsed, $adminCreds) {

		Try {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				Remove-ADObject -Identity $targetObjectToCheckDN -Server $targetedADdomainRWDC -Confirm:$false
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				Remove-ADObject -Identity $targetObjectToCheckDN -Server $targetedADdomainRWDC -Credential $adminCreds -Confirm:$false
			}
		} Catch {
			Logging "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE DELETED on RWDC [$targetedADdomainRWDC]!..." "ERROR"
			Logging "  --> Manually delete the Temp Canary Object [$targetObjectToCheckDN] on RWDC [$targetedADdomainRWDC]!..." "ERROR"
			Logging "" "ERROR"
		}

		$targetObjectToCheck = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainRWDC
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainRWDC -Credential $adminCreds
		}
		If (!$targetObjectToCheck) {
			Logging "  --> Temp Canary Object [$targetObjectToCheckDN] DELETED on RWDC [$targetedADdomainRWDC]!..." "REMARK"
			Logging "" "REMARK"
		}
	}

	Function checkADReplicationConvergence($targetedADdomainFQDN, $targetedADdomainSourceRWDCFQDN, $targetObjectToCheckDN, $listOfDCsToCheckObjectOnStart, $listOfDCsToCheckObjectOnEnd, $modeOfOperationNr, $localADforest, $remoteCredsUsed, $adminCreds) {

		$startDateTime = Get-Date

		$c = 0

		$continue = $true

		$delay = 0.1
		
		While($continue) {
			$c++
			#$oldpos = $host.UI.RawUI.CursorPosition
			Logging ""
			Logging "  =================================================================== CHECK $c ==================================================================="
			Logging ""

			Start-Sleep $delay

			$replicated = $true

			ForEach ($dcToCheck in $listOfDCsToCheckObjectOnStart) {

				$dcToCheckHostName = $null
				$dcToCheckHostName = $dcToCheck."Host Name"

				$dcToCheckIsPDC = $null
				$dcToCheckIsPDC = $dcToCheck.PDC

				$dcToCheckSiteName = $null
				$dcToCheckSiteName = $dcToCheck."Site Name"

				$dcToCheckDSType = $null
				$dcToCheckDSType = $dcToCheck."DS Type"

				$dcToCheckIPAddress = $null
				$dcToCheckIPAddress = $dcToCheck."IP Address"

				$dcToCheckReachability = $null
				$dcToCheckReachability = $dcToCheck.Reachable

				$dcToCheckSourceRWDCNTDSSettingsObjectDN = $null
				$dcToCheckSourceRWDCNTDSSettingsObjectDN = $dcToCheck."Source RWDC DSA"

				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {

					$objectOnSourceOrgRWDC = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
						$objectOnSourceOrgRWDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $targetedADdomainSourceRWDCFQDN
					}
					If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
						$objectOnSourceOrgRWDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCreds
					}

					$objectOnSourceOrgRWDCPwdLastSet = $null
					$objectOnSourceOrgRWDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnSourceOrgRWDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
				}

				If ($dcToCheckHostName -eq $targetedADdomainSourceRWDCFQDN) {
					Logging "  - Contacting DC in AD domain ...[$($dcToCheckHostName.ToUpper())]...(SOURCE RWDC)"
					Logging "     * DC is Reachable..." "SUCCESS"

					If ($modeOfOperationNr -eq 2) {
						Logging "     * Object [$targetObjectToCheckDN] exists in the AD database" "SUCCESS"
					}

					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {
						Logging "     * The new password for Object [$targetObjectToCheckDN] exists in the AD database" "SUCCESS"
					}
					Logging ""
					CONTINUE
				}
				
				Logging "  - Contacting DC in AD domain ...[$($dcToCheckHostName.ToUpper())]..."
				If ($dcToCheckReachability) {

					Logging "     * DC is Reachable..." "SUCCESS"

					If ($dcToCheckHostName -ne $targetedADdomainSourceRWDCFQDN) {

						$sourceDCNTDSSettingsObjectDN = $dcToCheckSourceRWDCNTDSSettingsObjectDN

						If ($modeOfOperationNr -eq 2) {
							$contentScope = "Full"
						}

						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {

							If ($dcToCheckDSType -eq "Read/Write") {
								$contentScope = "Full"
							}

							If ($dcToCheckDSType -eq "Read-Only") {
								$contentScope = "Secrets"
							}
						}

						replicateSingleADObject $sourceDCNTDSSettingsObjectDN $dcToCheckHostName $targetObjectToCheckDN $contentScope $localADforest $remoteCredsUsed $adminCreds
					}

					If ($modeOfOperationNr -eq 2) {
						$targetObjectToCheck = $null
						If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
							$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $dcToCheckHostName
						}
						If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
							$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $dcToCheckHostName -Credential $adminCreds
						}
					}

					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {

						$objectOnTargetDC = $null
						If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
							$objectOnTargetDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $dcToCheckHostName
						}
						If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
							$objectOnTargetDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $dcToCheckHostName -Credential $adminCreds
						}

						$objectOnTargetDCPwdLastSet = $null
						$objectOnTargetDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnTargetDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
					}
				} Else {

					Logging "     * DC is NOT reachable..." "ERROR"
				}
				
				If ($dcToCheckReachability) {


					If ($targetObjectToCheck -Or $objectOnTargetDCPwdLastSet -eq $objectOnSourceOrgRWDCPwdLastSet) {

						If ($modeOfOperationNr -eq 2) {
							Logging "     * Object [$targetObjectToCheckDN] now does exist in the AD database" "SUCCESS"
						}

						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {
							Logging "     * The new password for Object [$targetObjectToCheckDN] now does exist in the AD database" "SUCCESS"
						}
						Logging "" "SUCCESS"

						If (!($listOfDCsToCheckObjectOnEnd | Where-Object{$_."Host Name" -eq $dcToCheckHostName})) {

							$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time

							$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
							$listOfDCsToCheckObjectOnEndObj."Host Name" = $dcToCheckHostName

							$listOfDCsToCheckObjectOnEndObj.PDC = $null
							$listOfDCsToCheckObjectOnEndObj.PDC = $dcToCheckIsPDC

							$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
							$listOfDCsToCheckObjectOnEndObj."Site Name" = $dcToCheckSiteName

							$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
							$listOfDCsToCheckObjectOnEndObj."DS Type" = $dcToCheckDSType

							$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
							$listOfDCsToCheckObjectOnEndObj."IP Address" = $dcToCheckIPAddress

							$listOfDCsToCheckObjectOnEndObj.Reachable = $null
							$listOfDCsToCheckObjectOnEndObj.Reachable = $dcToCheckReachability

							$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
							$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainSourceRWDCFQDN

							$listOfDCsToCheckObjectOnEndObj.Time = ("{0:n2}" -f ((Get-Date) - $startDateTime).TotalSeconds)

							$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj
						}
					} Else {

						If ($modeOfOperationNr -eq 2) {
							Logging "     * Object [$targetObjectToCheckDN] does NOT exist yet in the AD database" "WARNING"
						}

						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {
							Logging "     * The new password for Object [$targetObjectToCheckDN] does NOT exist yet in the AD database" "WARNING"
						}
						Logging "" "WARNING"

						$replicated = $false
					}
				} Else {

					Logging "     * Unable to connect to DC and check for Object [$targetObjectToCheckDN]..." "ERROR"
					Logging "" "WARNING"

					If (!($listOfDCsToCheckObjectOnEnd | Where-Object{$_."Host Name" -eq $dcToCheckHostName})) {

						$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time

						$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
						$listOfDCsToCheckObjectOnEndObj."Host Name" = $dcToCheckHostName

						$listOfDCsToCheckObjectOnEndObj.PDC = $null
						$listOfDCsToCheckObjectOnEndObj.PDC = $dcToCheckIsPDC

						$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
						$listOfDCsToCheckObjectOnEndObj."Site Name" = $dcToCheckSiteName

						$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
						$listOfDCsToCheckObjectOnEndObj."DS Type" = $dcToCheckDSType

						$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
						$listOfDCsToCheckObjectOnEndObj."IP Address" = $dcToCheckIPAddress

						$listOfDCsToCheckObjectOnEndObj.Reachable = $null
						$listOfDCsToCheckObjectOnEndObj.Reachable = $dcToCheckReachability

						$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
						$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainSourceRWDCFQDN

						$listOfDCsToCheckObjectOnEndObj.Time = "<Fail>"

						$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj
					}
				}
			}

			If ($replicated) {

				$continue = $false
			} Else {

				#$host.UI.RawUI.CursorPosition = $oldpos
			}
		}

		$endDateTime = Get-Date

		$duration = "{0:n2}" -f ($endDateTime.Subtract($startDateTime).TotalSeconds)
		Logging ""
		Logging "  --> Start Time......: $(Get-Date $startDateTime -format 'yyyy-MM-dd HH:mm:ss')"
		Logging "  --> End Time........: $(Get-Date $endDateTime -format 'yyyy-MM-dd HH:mm:ss')"
		Logging "  --> Duration........: $duration Seconds"
		Logging ""

		If ($modeOfOperationNr -eq 2) {

			$targetObjectToCheck = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainSourceRWDCFQDN
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCreds
			}

			If ($targetObjectToCheck) {

				deleteTempCanaryObject $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $localADforest $remoteCredsUsed $adminCreds
			}
		}

		$listOfDCsToCheckObjectOnEnd = $listOfDCsToCheckObjectOnEnd | Sort-Object -Property @{Expression = "Time"; Descending = $False} | Format-Table -Autosize
		Logging ""
		Logging "List Of DCs In AD Domain '$targetedADdomainFQDN' And Their Timing..."
		Logging ""
		Logging "$($listOfDCsToCheckObjectOnEnd | Out-String)"
		Logging ""
	}

	Function createTestKrbTgtADAccount($targetedADdomainRWDC, $krbTgtSamAccountName, $krbTgtUse, $targetedADdomainDomainSID, $localADforest, $remoteCredsUsed, $adminCreds) {

		$targetedADdomainDefaultNC = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDC).defaultNamingContext
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDC -Credential $adminCreds).defaultNamingContext
		}

		$containerForTestKrbTgtAccount = $null
		$containerForTestKrbTgtAccount = "CN=Users," + $targetedADdomainDefaultNC

		$testKrbTgtObjectSamAccountName = $null
		$testKrbTgtObjectSamAccountName = $krbTgtSamAccountName

		$testKrbTgtObjectName = $null
		$testKrbTgtObjectName = $testKrbTgtObjectSamAccountName

		$testKrbTgtObjectDescription = $null

		If ($krbTgtUse -eq "RWDC") {
			$testKrbTgtObjectDescription = "Test Copy Representing '$($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST')))' - Key Distribution Center Service Account"
		}

		If ($krbTgtUse -eq "RODC") {
			$testKrbTgtObjectDescription = "Test Copy Representing '$($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST')))' - Key Distribution Center service account for read-only domain controller"
		}	

		$testKrbTgtObjectDN = $null
		$testKrbTgtObjectDN = "CN=" + $testKrbTgtObjectName + "," + $containerForTestKrbTgtAccount
		Logging "  --> RWDC To Create Object On..............: '$targetedADdomainRWDC'"
		Logging "  --> Full Name Test KrbTgt Account.........: '$testKrbTgtObjectName'"
		Logging "  --> Description...........................: '$testKrbTgtObjectDescription'"
		Logging "  --> Container Test KrbTgt Account.........: '$containerForTestKrbTgtAccount'"

		If ($krbTgtUse -eq "RWDC") {
			$deniedRODCPwdReplGroupRID = "572"
			$deniedRODCPwdReplGroupObjectSID  = $targetedADdomainDomainSID + "-" + $deniedRODCPwdReplGroupRID
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				$deniedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $deniedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDC).Name
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				$deniedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $deniedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDC -Credential $adminCreds).Name
			}
			Logging "  --> Made Member Of RODC PRP Group.........: '$deniedRODCPwdReplGroupObjectName'"
		}

		If ($krbTgtUse -eq "RODC") {
			$allowedRODCPwdReplGroupRID = "571"
			$allowedRODCPwdReplGroupObjectSID  = $targetedADdomainDomainSID + "-" + $allowedRODCPwdReplGroupRID
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				$allowedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $allowedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDC).Name
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				$allowedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $allowedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDC -Credential $adminCreds).Name
			}		
			Logging "  --> Made Member Of RODC PRP Group.........: '$allowedRODCPwdReplGroupObjectName'"
		}
		Logging ""

		$testKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Server $targetedADdomainRWDC
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Server $targetedADdomainRWDC -Credential $adminCreds
		}
		If ($testKrbTgtObject) {

			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY EXISTS on RWDC [$targetedADdomainRWDC]!..." "REMARK"
			Logging "" "REMARK"
		} Else {

			$passwordNrChars = 64

			$krbTgtPassword = $null
			$krbTgtPassword = (generateNewComplexPassword $passwordNrChars).ToString()

			$krbTgtPasswordSecure = $null
			$krbTgtPasswordSecure = ConvertTo-SecureString $krbTgtPassword -AsPlainText -Force

			Try {
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
					New-ADUser -SamAccountName $testKrbTgtObjectSamAccountName -Name $testKrbTgtObjectName -DisplayName $testKrbTgtObjectName -Path $containerForTestKrbTgtAccount -AccountPassword $krbTgtPasswordSecure -Enabled $False -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDC
				}
				If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
					New-ADUser -SamAccountName $testKrbTgtObjectSamAccountName -Name $testKrbTgtObjectName -DisplayName $testKrbTgtObjectName -Path $containerForTestKrbTgtAccount -AccountPassword $krbTgtPasswordSecure -Enabled $False -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDC -Credential $adminCreds
				}
			} Catch {
				Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDC]!..." "ERROR"
				Logging "" "ERROR"
			}

			$testKrbTgtObject = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				$testKrbTgtObject = Get-ADObject -LDAPFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))" -Server $targetedADdomainRWDC
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				$testKrbTgtObject = Get-ADObject -LDAPFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))" -Server $targetedADdomainRWDC -Credential $adminCreds
			}
			If ($testKrbTgtObject) {
				$testKrbTgtObjectDN = $null
				$testKrbTgtObjectDN = $testKrbTgtObject.DistinguishedName
				Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] CREATED on RWDC [$targetedADdomainRWDC]!..." "REMARK"
				Logging "" "REMARK"
			}
		}
		If ($testKrbTgtObject) {

			If ($krbTgtUse -eq "RWDC") {

				$membershipDeniedPRPGroup = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
					$membershipDeniedPRPGroup = Get-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Server $targetedADdomainRWDC | Where-Object{$_.distinguishedName -eq $testKrbTgtObjectDN}
				}
				If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
					$membershipDeniedPRPGroup = Get-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Server $targetedADdomainRWDC -Credential $adminCreds | Where-Object{$_.distinguishedName -eq $testKrbTgtObjectDN}
				}
				If ($membershipDeniedPRPGroup) {

					Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY MEMBER OF [$deniedRODCPwdReplGroupObjectName]!..." "REMARK"
					Logging "" "REMARK"
				} Else {

					If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
						Add-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDC
					}
					If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
						Add-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDC -Credential $adminCreds
					}
					Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ADDED AS MEMBER OF [$deniedRODCPwdReplGroupObjectName]!..." "REMARK"
					Logging "" "REMARK"
				}
			}

			If ($krbTgtUse -eq "RODC") {

				$membershipAllowedPRPGroup = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
					$membershipAllowedPRPGroup = Get-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Server $targetedADdomainRWDC | Where-Object{$_.distinguishedName -eq $testKrbTgtObjectDN}
				}
				If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
					$membershipAllowedPRPGroup = Get-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Server $targetedADdomainRWDC -Credential $adminCreds | Where-Object{$_.distinguishedName -eq $testKrbTgtObjectDN}
				}
				If ($membershipAllowedPRPGroup) {

					Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY MEMBER OF [$allowedRODCPwdReplGroupObjectName]!..." "REMARK"
					Logging "" "REMARK"
				} Else {

					If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
						Add-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDC
					}
					If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
						Add-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDC -Credential $adminCreds
					}
					Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ADDED AS MEMBER OF [$allowedRODCPwdReplGroupObjectName]!..." "REMARK"
					Logging "" "REMARK"
				}
			}
		}
	}

	Function deleteTestKrbTgtADAccount($targetedADdomainRWDC, $krbTgtSamAccountName) {

		$testKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
			$testKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainRWDC
		}
		If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
			$testKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainRWDC -Credential $adminCreds
		}
		If ($testKrbTgtObject) {

			$testKrbTgtObjectDN = $null
			$testKrbTgtObjectDN = $testKrbTgtObject.DistinguishedName
			Logging "  --> RWDC To Delete Object On..............: '$targetedADdomainRWDC'"
			Logging "  --> Test KrbTgt Account DN................: '$testKrbTgtObjectDN'"
			Logging ""
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				Remove-ADUser -Identity $testKrbTgtObjectDN -Server $targetedADdomainRWDC -Confirm:$false
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				Remove-ADUser -Identity $testKrbTgtObjectDN -Server $targetedADdomainRWDC -Credential $adminCreds -Confirm:$false
			}
			$testKrbTgtObject = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $remoteCredsUsed -eq $false)) {
				$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Server $targetedADdomainRWDC
			}
			If ($localADforest -eq $false -And $remoteCredsUsed -eq $true) {
				$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Server $targetedADdomainRWDC -Credential $adminCreds
			}
			If (!$testKrbTgtObject) {
				Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] DELETED on RWDC [$targetedADdomainRWDC]!..." "REMARK"
				Logging "" "REMARK"
			} Else {
				Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] FAILED TO BE DELETED on RWDC [$targetedADdomainRWDC]!..." "ERROR"
				Logging "  --> Manually delete the Test KrbTgt Account [$testKrbTgtObjectDN] on RWDC [$targetedADdomainRWDC]!..." "ERROR"
				Logging "" "ERROR"
			}
		} Else {

			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] DOES NOT EXIST on RWDC [$targetedADdomainRWDC]!..." "WARNING"
			Logging "" "WARNING"
		}
	}

	#Logging location here
	$loggingPathLocation = if ([string]::IsNullOrEmpty($POC_LogPath)) {$env:TMP} Else {$POC_LogPath}
	
	set-location -Path $loggingPathLocation
	$version = "v2.5, 2020-02-17"

	#Clear-Host
	
	#INCHANGE
	#$uiConfig = (Get-Host).UI.RawUI
	#$uiConfig.WindowTitle = "+++ RESET KRBTGT ACCOUNT PASSWORD FOR RWDCs/RODCs +++"
	#$uiConfig.ForegroundColor = "Yellow"
	#$uiConfigBufferSize = $uiConfig.BufferSize
	#$uiConfigBufferSize.Width = 240
	#$uiConfigBufferSize.Height = 9999
	#$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
	#$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
	#$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
	#$uiConfigScreenSize = $uiConfig.WindowSize
	#If ($uiConfigScreenSizeMaxWidth -lt 240) {
	#	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
	#} Else {
	#	$uiConfigScreenSize.Width = 240
	#}
	#If ($uiConfigScreenSizeMaxHeight -lt 75) {
	#	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
	#} Else {
	#	$uiConfigScreenSize.Height = 75
	#}
	#$uiConfig.BufferSize = $uiConfigBufferSize
	#$uiConfig.WindowSize = $uiConfigScreenSize

	$execDateTime = Get-Date
	$execDateTimeYEAR = $execDateTime.Year
	$execDateTimeMONTH = $execDateTime.Month
	$execDateTimeDAY = $execDateTime.Day
	$execDateTimeHOUR = $execDateTime.Hour
	$execDateTimeMINUTE = $execDateTime.Minute
	$execDateTimeSECOND = $execDateTime.Second
	$execDateTimeCustom = [STRING]$execDateTimeYEAR + "-" + $("{0:D2}" -f $execDateTimeMONTH) + "-" + $("{0:D2}" -f $execDateTimeDAY) + "_" + $("{0:D2}" -f $execDateTimeHOUR) + "." + $("{0:D2}" -f $execDateTimeMINUTE) + "." + $("{0:D2}" -f $execDateTimeSECOND)
	$execDateTimeCustom1 = [STRING]$execDateTimeYEAR + $("{0:D2}" -f $execDateTimeMONTH) + $("{0:D2}" -f $execDateTimeDAY) + $("{0:D2}" -f $execDateTimeHOUR) + $("{0:D2}" -f $execDateTimeMINUTE) + $("{0:D2}" -f $execDateTimeSECOND)
	$adRunningUserAccount = $ENV:USERDOMAIN + "\" + $ENV:USERNAME
    #IN - Check if another thing
	$currentScriptFolderPath = pwd
	$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name

	[string]$logFilePath = Join-Path $currentScriptFolderPath $($localComputerName + "_Reset-KrbTgt-Password-For-RWDCs-And-RODCs.log")
	
	Logging ""
	Logging "                                          **********************************************************" "MAINHEADER"
	Logging "                                          *                                                        *" "MAINHEADER"
	Logging "                                          *  --> Reset KrbTgt Account Password For RWDCs/RODCs <-- *" "MAINHEADER"
	Logging "                                          *                                                        *" "MAINHEADER"
	Logging "                                          *     Re-Written By: Jorge de Almeida Pinto [MVP-EMS]    *" "MAINHEADER"
	Logging "                                          *                                                        *" "MAINHEADER"
	Logging "                                          *   BLOG: http://jorgequestforknowledge.wordpress.com/   *" "MAINHEADER"
	Logging "                                          *                                                        *" "MAINHEADER"
	Logging "                                          *                    $version                    *" "MAINHEADER"
	Logging "                                          *                                                        *" "MAINHEADER"
	Logging "                                          **********************************************************" "MAINHEADER"
	Logging ""



	#AdForest
	$poc_activeDirectoryForest = if ($null -eq $POC_AdForestFQDN) {$POC_AdForestFQDN} else {$POC_AdForestFQDN.Trim()}

	#AdTargetToman
	$poc_activeDirectoryDomain = if ($null -eq $POC_DomainFQDN) {$POC_DomainFQDN} else {$POC_DomainFQDN.Trim()}
	
	#AdTargetDomainController  - CAN BE A LIST IF SCOPE OPTION 3
	$poc_activeDirectoryDomainController = if ($POC_DomainControllerFQDN_List -eq $null) {$POC_DomainControllerFQDN_List} else {$POC_DomainControllerFQDN_List.Trim()}
	
	#Account Scope For Password Change 
	$poc_KRBTGT_Account_Scope = if ($null -eq $POC_KRBTGT_Account_Scope) {$POC_KRBTGT_Account_Scope} else {$POC_KRBTGT_Account_Scope.Trim()}
	
	#Run Option: Log Info, Test Password Change, Real Password Change Etc.
	$poc_runOption = if ($POC_RunOption -eq $null) {$POC_RunOption} else {$POC_RunOption.Trim()}

	Logging ""
	Logging "Do you want to read information about the script, its functions, its behavior and the impact? [YES | NO]: " "ACTION-NO-NEW-LINE"
	$yesOrNo = $null

	$yesOrNo = "no"
	If ($yesOrNo.ToUpper() -ne "NO") {
		$yesOrNo = "YES"
	}
	Logging ""
	Logging "  --> Chosen: $yesOrNo" "REMARK"
	Logging ""
	If ($yesOrNo.ToUpper() -ne "NO") {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "INFORMATION ABOUT THE SCRIPT, ITS FUNCTIONS AND BEHAVIOR, AND IMPACT TO THE ENVIRONMENT - PLEASE READ CAREFULLY..." "HEADER"
		Logging ""
		Logging "-----" "REMARK"
		Logging "This PoSH script provides the following functions:" "REMARK"
		Logging "-----" "REMARK"
		Logging " - Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST or PROD KrbTgt accounts" "REMARK"
		Logging " - Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST or PROD KrbTgt accounts" "REMARK"
		Logging "     * A single RODC in a specific AD domain" "REMARK"
		Logging "     * A specific list of in a specific AD domain" "REMARK"
		Logging "     * All RODCs in a specific AD domain" "REMARK"
		Logging " - Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:" "REMARK"
		Logging "     * From a security perspective as mentioned in:" "REMARK"
		Logging "       https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/" "REMARK"
		Logging "     * From an AD recovery perspective as mentioned in:" "REMARK"
		Logging "       https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password" "REMARK"
		Logging " - For all scenarios, an informational mode, which is mode 1 with no changes" "REMARK"
		Logging " - For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary" "REMARK"
		Logging "     object that is created and deleted afterwards" "REMARK"
		Logging " - For all scenarios, a simulation mode, which is mode 3 where the password reset of the chosen TEST KrbTgt account is actually executed" "REMARK"
		Logging "     and replication of it is monitored through the environment for its duration" "REMARK"
		Logging " - For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen PROD KrbTgt account is actually executed" "REMARK"
		Logging "     and replication of it is monitored through the environment for its duration" "REMARK"
		Logging " - The creation of Test KrbTgt Accounts" "REMARK"
		Logging " - The cleanup of previously created Test KrbTgt Accounts" "REMARK"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging "-----" "REMARK"
		Logging "This PoSH script has the following behavior:" "REMARK"
		Logging "-----" "REMARK"
		Logging ""
		Logging " - Mode 1 is INFORMATIONAL MODE..." "REMARK-IMPORTANT"
		Logging "     * Safe to run at any time as there are not changes in any way!" "REMARK-IMPORTANT"
		Logging "     * Analyzes the environment and check for issues that may impact mode 2, 3 or 4!" "REMARK-IMPORTANT"
		Logging "     * For the targeted AD domain, it always retrieves all RWDCs, and all RODCs if applicable." "REMARK-IMPORTANT"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging " - Mode 2 is SIMULATION MODE USING A TEMPORARY CANARY OBJECT..." "REMARK-MORE-IMPORTANT"
		Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
		Logging "     * Creates the temporary canary object and, depending on the scope, it will check if it exists in the AD database of the remote DC(s)" "REMARK-MORE-IMPORTANT"
		Logging "       (RWDC/RODC)." "REMARK-MORE-IMPORTANT"
		Logging "     * When simulating the KrbTgt account for RWDCs, the creation of the object is against the RWDC with the PDC Emulator FSMO followed" "REMARK-MORE-IMPORTANT"
		Logging "       by the 'replicate single object' operation against every available/reachable RWDC. This is a way to estimate the total replication" "REMARK-MORE-IMPORTANT"
		Logging "       time for mode 4." "REMARK-MORE-IMPORTANT"
		Logging "     * When simulating the KrbTgt account for RODCs, the creation of the object is against the RWDC the RODC is replicating from if" "REMARK-MORE-IMPORTANT"
		Logging "       available. If not available the creation is against the RWDC with the PDC Emulator FSMO. Either way it is followed by the 'replicate" "REMARK-MORE-IMPORTANT"
		Logging "       single object' operation against the RODC. This is a way to estimate the total replication time for mode 4." "REMARK-MORE-IMPORTANT"
		Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
		Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
		Logging "     * When performing the 'replicate single object' operation, it will always be for the full object, no matter if the remote DC is an RWDC" "REMARK-MORE-IMPORTANT"
		Logging "       or an RODC" "REMARK-MORE-IMPORTANT"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging " - Mode 3 is SIMULATION MODE USING TEST/BOGUS KRBTGT ACCOUNTS..." "REMARK-MORE-IMPORTANT"
		Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
		Logging "     * Instead of using PROD/REAL KrbTgt Account(s), it uses pre-created TEST/BOGUS KrbTgt Accounts(s) for the password reset!" "REMARK-MORE-IMPORTANT"
		Logging "       * For RWDCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_TEST' (All RWDCs) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
		Logging "       * For RODCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' (RODC Specific) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
		Logging "     * Resets the password of the TEST/BOGUS KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MORE-IMPORTANT"
		Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MORE-IMPORTANT"
		Logging "       RWDC." "REMARK-MORE-IMPORTANT"
		Logging "     * When simulating the KrbTgt account for RWDCs, the password reset is done for the TEST/BOGUS KrbTgt Accounts(s) against the RWDC with" "REMARK-MORE-IMPORTANT"
		Logging "       the PDC Emulator FSMO followed by the 'replicate single object' operation against every available/reachable RWDC. No RODCs are involved" "REMARK-MORE-IMPORTANT"
		Logging "       as those do not use the KrbTgt account in use by the RWDCs and also do not store/cache its password. This is a way to estimate the" "REMARK-MORE-IMPORTANT"
		Logging "       total replication time for mode 4." "REMARK-MORE-IMPORTANT"
		Logging "     * When simulating the KrbTgt account for RODCs, the password reset is done for the TEST/BOGUS KrbTgt Accounts(s) against the RWDC the" "REMARK-MORE-IMPORTANT"
		Logging "       RODC is replicating from if available/reachable. If not available the password reset is against the RWDC with the PDC Emulator FSMO." "REMARK-MORE-IMPORTANT"
		Logging "       Either way it is followed by the 'replicate single object' operation against the RODC that uses that KrbTgt account. Only the RODC" "REMARK-MORE-IMPORTANT"
		Logging "       that uses the specific KrbTgt account is checked against to see if the change has reached it, but only if the RODC is available/reachable." "REMARK-MORE-IMPORTANT"
		Logging "       This is a way to estimate the total replication time for mode 4." "REMARK-MORE-IMPORTANT"
		Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
		Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
		Logging "     * When performing the 'replicate single object' operation, it will always be for the full object if the target DC is an RWDC. If the" "REMARK-MORE-IMPORTANT"
		Logging "       target DC is an RODC, then it will be for the partial object (secrets only)." "REMARK-MORE-IMPORTANT"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging " - Mode 4 is REAL RESET MODE USING PROD/REAL KRBTGT ACCOUNTS..." "REMARK-MOST-IMPORTANT"
		Logging "     * Also executes everything from mode 1!" "REMARK-MOST-IMPORTANT"
		Logging "     * Now it does use the PROD/REAL KrbTgt Accounts(s) for the password reset!" "REMARK-MOST-IMPORTANT"
		Logging "       * For RWDCs it uses the PROD/REAL KrbTgt account 'krbtgt' (All RWDCs)" "REMARK-MOST-IMPORTANT"
		Logging "       * For RODCs it uses the PROD/REAL KrbTgt account 'krbtgt_<Numeric Value>' (RODC Specific)" "REMARK-MOST-IMPORTANT"
		Logging "     * Resets the password of the PROD/REAL KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MOST-IMPORTANT"
		Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MOST-IMPORTANT"
		Logging "       RWDC." "REMARK-MOST-IMPORTANT"
		Logging "     * When simulating the KrbTgt account for RWDCs, the password reset is done for the PROD/REAL KrbTgt Accounts(s) against the RWDC with" "REMARK-MOST-IMPORTANT"
		Logging "       the PDC Emulator FSMO followed by the 'replicate single object' operation against every available/reachable RWDC. No RODCs are involved" "REMARK-MOST-IMPORTANT"
		Logging "       as those do not use the KrbTgt account in use by the RWDCs and also do not store/cache its password. Once the replication is" "REMARK-MOST-IMPORTANT"
		Logging "       complete, the total impact time will be displayed." "REMARK-MOST-IMPORTANT"
		Logging "     * When simulating the KrbTgt account for RODCs, the password reset is done for the PROD/REAL KrbTgt Accounts(s) against the RWDC the" "REMARK-MOST-IMPORTANT"
		Logging "       RODC is replicating from if available/reachable. If not available the password reset is against the RWDC with the PDC Emulator FSMO." "REMARK-MOST-IMPORTANT"
		Logging "       Either way it is followed by the 'replicate single object' operation against the RODC that uses that KrbTgt account. Only the RODC" "REMARK-MOST-IMPORTANT"
		Logging "       that uses the specific KrbTgt account is checked against to see if the change has reached it, but only if the RODC is available/reachable." "REMARK-MOST-IMPORTANT"
		Logging "       Once the replication is complete, the total impact time will be displayed." "REMARK-MOST-IMPORTANT"
		Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MOST-IMPORTANT"
		Logging "       the change made reached it or not." "REMARK-MOST-IMPORTANT"
		Logging "     * When performing the 'replicate single object' operation, it will always be for the full object if the target DC is an RWDC. If the" "REMARK-MOST-IMPORTANT"
		Logging "       target DC is an RODC, then it will be for the partial object (secrets only)." "REMARK-MOST-IMPORTANT"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging " - Mode 8 is CREATE TEST KRBTGT ACCOUNTS MODE..." "REMARK-IMPORTANT"
		Logging "     * Creates so called TEST/BOGUS KrbTgt Account(s) to simulate the password reset with." "REMARK-IMPORTANT"
		Logging "     * Has no impact on the PROD/REAL KrbTgt Account(s)." "REMARK-IMPORTANT"
		Logging "     * For RWDCs it creates (in disabled state!) the TEST/BOGUS KrbTgt account 'krbtgt_TEST' and adds it to the AD group 'Denied RODC" "REMARK-IMPORTANT"
		Logging "       Password Replication Group'." "REMARK-IMPORTANT"
		Logging "     * For RODCs, if any in the AD domain, it creates (in disabled state!) the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' and" "REMARK-IMPORTANT"
		Logging "       adds it to the AD group 'Allowed RODC Password Replication Group'. To determine the specific KrbTgt account in use by an RODC, the" "REMARK-IMPORTANT"
		Logging "       script reads the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging " - Mode 9 is CLEANUP TEST KRBTGT ACCOUNTS MODE..." "REMARK-IMPORTANT"
		Logging "     * Cleanup (delete) the so called TEST/BOGUS KrbTgt Account(s) that were used to simulate the password reset with." "REMARK-IMPORTANT"
		Logging "     * For RWDCs it deletes the TEST/BOGUS KrbTgt account 'krbtgt_TEST' if it exists." "REMARK-IMPORTANT"
		Logging "     * For RODCs, if any in the AD domain, it deletes the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' if it exists. To determine" "REMARK-IMPORTANT"
		Logging "       the specific KrbTgt account in use by an RODC, the script reads the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging " - ADDITIONAL INFO - BEHAVIOR..." "REMARK-IMPORTANT"
		Logging "     * If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC)," "REMARK-IMPORTANT"
		Logging "       and therefore something else. It could for example be a Riverbed appliance in 'RODC mode'." "REMARK-IMPORTANT"
		Logging "     * The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object" "REMARK-IMPORTANT"
		Logging "       (CO) that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication." "REMARK-IMPORTANT"
		Logging "       Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the 'source' server is" "REMARK-IMPORTANT"
		Logging "       determined. In case the RODC is not available or its 'source' server is not available, the RWDC with the PDC FSMO is used to reset" "REMARK-IMPORTANT"
		Logging "       the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if" "REMARK-IMPORTANT"
		Logging "       not available the check is skipped." "REMARK-IMPORTANT"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging " - ADDITIONAL INFO - OBSERVED IMPACT..." "REMARK-IMPORTANT"
		Logging "     * Within an AD domain, all RWDCs use the account 'krbtgt' to encrypt/sign Kerberos tickets trusted by all RWDCs" "REMARK-IMPORTANT"
		Logging "     * Within an AD domain, every RODC uses its own 'krbtgt_<Numeric Value>' account to encrypt/sign Kerberos tickets trusted by only that RODC" "REMARK-IMPORTANT"
		Logging "       and that account is specified in the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
		Logging "     * RODCs are cryptographically isolated from other RODCs and the RWDCs, whether these are in the same AD site or not. Any Kerberos TGT/Service" "REMARK-IMPORTANT"
		Logging "       tickets issued by an RODC are only valid against that RODC and any resource that has a secure channel with that RODC. That's why when an" "REMARK-IMPORTANT"
		Logging "       RODC is compromised the scope of impact is only for that RODC and any resource using it, and not the complete AD domain." "REMARK-IMPORTANT"
		Logging "     * Kerberos PAC validation failures: Until the new KrbTgt account password is replicated to all DCs in the domain using that KrbTgt account," "REMARK-IMPORTANT"
		Logging "       applications which attempt KDC PAC validation may experience KDC PAC validation failures. This is possible  when a client in one AD site" "REMARK-IMPORTANT"
		Logging "       is accessing an application leveraging the Kerberos Authentication protocol that is in a different AD site. If that application is not a" "REMARK-IMPORTANT"
		Logging "       trusted part of the operating system, it may attempt to validate the PAC of the client's Kerberos Service Ticket against the KDC (DC) in" "REMARK-IMPORTANT"
		Logging "       its AD site. If the DC in its site does not yet have the new KrbTgt account password, this KDC PAC validation will fail. This will likely" "REMARK-IMPORTANT"
		Logging "       manifest itself to the client as authentication errors for that application. Once all DCs using a specific KrbTgt account have the new" "REMARK-IMPORTANT"
		Logging "       password some affected clients may recover gracefully and resume functioning normally. If not, rebooting the affected client(s) will" "REMARK-IMPORTANT"
		Logging "       resolve the issue. This issue may not occur if the replication of the new KrbTgt account password is timely and successful and no" "REMARK-IMPORTANT"
		Logging "       applications attempt KDC PAC validation against an out of sync DC during that time." "REMARK-IMPORTANT"
		Logging "     * Kerberos TGS request failures: Until the new KrbTgt account password is replicated to all DCs in the domain that use that KrbTgt account," "REMARK-IMPORTANT"
		Logging "       a client may experience Kerberos authentication failures. This is when a client in one AD site has obtained a Kerberos Ticket Granting" "REMARK-IMPORTANT"
		Logging "       Ticket (TGT) from an RWDC that has the new KrbTgt account password, but then subsequently attempts to obtain a Kerberos Service Ticket" "REMARK-IMPORTANT"
		Logging "       via a TGS request against an RWDC in a different AD site. If that RWDC does not also have the new KrbTgt account password, it will not" "REMARK-IMPORTANT"
		Logging "       be able to decrypt the client''s TGT, which will result in a TGS request failure.  This will manifest itself to the client as authenticate" "REMARK-IMPORTANT"
		Logging "       errors. However, it should be noted that this impact is very unlikely, because it is very unlikely that a client will attempt to obtain a" "REMARK-IMPORTANT"
		Logging "       service ticket from a different RWDC than the one from which their TGT was obtained, especially during the relatively short impact" "REMARK-IMPORTANT"
		Logging "       duration of Mode 4." "REMARK-IMPORTANT"
		Logging ""
		Logging ""
		Logging "First, read the info above, then..." "ACTION"
		Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		#$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Logging ""
		Logging ""
		Logging "    >>> It is highly recommended to use the following order of execution: <<<" "REMARK-MORE-IMPORTANT"
		Logging "     - Mode 1 - Informational Mode (No Changes At All)" "REMARK-MORE-IMPORTANT"
		Logging "     - Mode 8 - Create TEST KrbTgt Accounts" "REMARK-MORE-IMPORTANT"
		Logging "     - Mode 2 - Simulation Mode (Temporary Canary Object Created, No Password Reset!)" "REMARK-MORE-IMPORTANT"
		Logging "     - Mode 3 - Simulation Mode - Use KrbTgt TEST/BOGUS Accounts (Password Will Be Reset Once!)" "REMARK-MORE-IMPORTANT"
		Logging "     - Mode 4 - Real Reset Mode - Use KrbTgt PROD/REAL Accounts (Password Will Be Reset Once!)" "REMARK-MORE-IMPORTANT"
		Logging "     - Mode 9 - Cleanup TEST KrbTgt Accounts (Could be skipped to reuse accounts the next time!)" "REMARK-MORE-IMPORTANT"
		Logging ""
	}

	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "LOADING REQUIRED POWERSHELL MODULES..." "HEADER"
	Logging ""

	$poshModuleAD = loadPoSHModules ActiveDirectory
	If ($poshModuleAD -eq "NotAvailable") {
		Logging ""
		EXIT
	}
	Logging ""

	$poshModuleGPO = loadPoSHModules GroupPolicy
	If ($poshModuleGPO -eq "NotAvailable") {
		Logging ""
		EXIT
	}
	Logging ""

	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "SELECT THE MODE OF OPERATION..." "HEADER"
	Logging ""
	Logging "Which mode of operation do you want to execute?"
	Logging ""
	Logging " - 1 - Informational Mode (No Changes At All)"
	Logging ""
	Logging " - 2 - Simulation Mode (Temporary Canary Object Created, No Password Reset!)"
	Logging ""
	Logging " - 3 - Simulation Mode - Use KrbTgt TEST/BOGUS Accounts (Password Will Be Reset Once!)"
	Logging ""
	Logging " - 4 - Real Reset Mode - Use KrbTgt PROD/REAL Accounts (Password Will Be Reset Once!)"
	Logging ""
	Logging ""
	Logging " - 8 - Create TEST KrbTgt Accounts"
	Logging " - 9 - Cleanup TEST KrbTgt Accounts"
	Logging ""
	Logging ""
	Logging " - 0 - Exit Script"
	Logging ""
	Logging "Please specify the mode of operation: " "ACTION-NO-NEW-LINE"


	$modeOfOperationNr = $poc_runOption
	
	Logging ""

	If (($modeOfOperationNr -ne 1 -And $modeOfOperationNr -ne 2 -And $modeOfOperationNr -ne 3 -And $modeOfOperationNr -ne 4 -And $modeOfOperationNr -ne 8 -And $modeOfOperationNr -ne 9) -Or $modeOfOperationNr -notmatch "^[\d\.]+$") {
		Logging "  --> Chosen mode: Mode 0 - Exit Script..." "REMARK"
		Logging ""
		
		EXIT
	}

	If ($modeOfOperationNr -eq 1) {
		Logging "  --> Chosen Mode: Mode 1 - Informational Mode (No Changes At All)..." "REMARK"
		Logging ""
	}

	If ($modeOfOperationNr -eq 2) {
		Logging "  --> Chosen Mode: Mode 2 - Simulation Mode (Temporary Canary Object Created, No Password Reset!)..." "REMARK"
		Logging ""
	}

	If ($modeOfOperationNr -eq 3) {
		Logging "  --> Chosen Mode: Mode 3 - Simulation Mode - Use KrbTgt TEST/BOGUS Accounts (Password Will Be Reset Once!)..." "REMARK"
		Logging ""
	}

	If ($modeOfOperationNr -eq 4) {
		Logging "  --> Chosen Mode: Mode 4 - Real Reset Mode - Use KrbTgt PROD/REAL Accounts (Password Will Be Reset Once!)..." "REMARK"
		Logging ""
	}

	If ($modeOfOperationNr -eq 8) {
		Logging "  --> Chosen Mode: Mode 8 - Create TEST KrbTgt Accounts..." "REMARK"
		Logging ""
	}

	If ($modeOfOperationNr -eq 9) {
		Logging "  --> Chosen Mode: Mode 9 - Cleanup TEST KrbTgt Accounts..." "REMARK"
		Logging ""
	}

	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "SPECIFY THE TARGET AD FOREST..." "HEADER"
	Logging ""

	$currentADDomainOfLocalComputer = $null
	$currentADDomainOfLocalComputer = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
	$currentADForestOfLocalComputer = $null
	$currentADForestOfLocalComputer = (Get-ADDomain $currentADDomainOfLocalComputer).Forest

	Logging "For the AD forest to be targeted, please provide the FQDN or press [ENTER] for the current AD forest: " "ACTION-NO-NEW-LINE"
	$targetedADforestFQDN = $null

	$targetedADforestFQDN = $poc_activeDirectoryForest

	If ($targetedADforestFQDN -eq "" -Or $null -eq $targetedADforestFQDN) {
		$targetedADforestFQDN = $currentADForestOfLocalComputer
	}
	Logging ""
	Logging "  --> Selected AD Forest: '$targetedADforestFQDN'..." "REMARK"

	$adForestValidity = $false

	Try {
		[System.Net.Dns]::gethostentry($targetedADforestFQDN) | Out-Null
		$adForestValidity = $true
	} Catch {
		$adForestValidity = $false
	}
	If ($targetedADforestFQDN -eq $currentADForestOfLocalComputer) {
		$localADforest = $true
		$remoteADforest = $false
		$adForestLocation = "Local"
	} Else {
		$localADforest = $false
		$remoteADforest = $true
		$adForestLocation = "Remote"
	}
	Logging ""
	Logging "Checking Resolvability of the specified $adForestLocation AD forest '$targetedADforestFQDN' through DNS..."
	If ($adForestValidity -eq $true) {

		Logging "" "SUCCESS"
		Logging "The specified $adForestLocation AD forest '$targetedADforestFQDN' is resolvable through DNS!" "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Else {

		Logging "" "ERROR"
		Logging "The specified $adForestLocation AD forest '$targetedADforestFQDN' IS NOT resolvable through DNS!" "ERROR"
		Logging "" "ERROR"
		Logging "Please re-run the script and provide the FQDN of an AD forest that is resolvable through DNS..." "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script...Unable to access AD Forest with current credentials" "ERROR"
		Logging "" "ERROR"

		EXIT
	}

	$adForestAccessibility = $false

	Try {

		$nearestRWDCInForestRootADDomain = $null
		$nearestRWDCInForestRootADDomain = (Get-ADDomainController -DomainName $targetedADforestFQDN -Discover).HostName[0]

		$thisADForest = $null
		$thisADForest = Get-ADForest -Identity $targetedADforestFQDN -Server $nearestRWDCInForestRootADDomain
		$adForestAccessibility = $true
		$remoteCredsUsed = $false
	} Catch {
		$adForestAccessibility = $false
		$remoteCredsUsed = $true
	}
	Logging ""
	Logging "Checking Accessibility of the specified AD forest '$targetedADforestFQDN' By Trying To Retrieve AD Forest Data..."
	If ($adForestAccessibility -eq $true) {

		Logging "" "SUCCESS"
		Logging "The specified AD forest '$targetedADforestFQDN' is accessible!" "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Else {
	
		Logging "Aborting Script...can not access AD Forest with current credentials" "ERROR"
		EXIT

		#Logging "" "WARNING"
		#Logging "The specified AD forest '$targetedADforestFQDN' IS NOT accessible!" "WARNING"
		#Logging "" "WARNING"
		#Logging "Custom credentials are needed..." "WARNING"
		#Logging "" "ERROR"
		#Logging "Continuing Script And Asking For Credentials..." "WARNING"
		#Logging "" "WARNING"
		#Logging ""
		#
		#Logging "Please provide an account (<DOMAIN FQDN>\<ACCOUNT>) that is a member of the 'Administrators' group in every AD domain of the specified AD forest: " "ACTION-NO-NEW-LINE"
		#$adminUserAccountRemoteForest = $null
		#$adminUserAccountRemoteForest = Read-Host
		#
		#If ($adminUserAccountRemoteForest -eq "" -Or $null -eq $adminUserAccountRemoteForest) {
		#	Logging ""
		#	Logging "Please provide an account (<DOMAIN FQDN>\<ACCOUNT>) that is a member of the 'Administrators' group in every AD domain of the specified AD forest: " "ACTION-NO-NEW-LINE"
		#	$adminUserAccountRemoteForest = $null
		#	$adminUserAccountRemoteForest = Read-Host
		#}
		#
		#Logging "Please provide the corresponding password of that admin account: " "ACTION-NO-NEW-LINE"
		#$adminUserPasswordRemoteForest = $null
		#$adminUserPasswordRemoteForest = Read-Host -AsSecureString
		#If ($adminUserPasswordRemoteForest -eq "" -Or $null -eq $adminUserPasswordRemoteForest) {
		#	Logging ""
		#	Logging "Please provide the corresponding password of that admin account: " "ACTION-NO-NEW-LINE"
		#	$adminUserPasswordRemoteForest = $null
		#	[System.Security.SecureString]$adminUserPasswordRemoteForest = Read-Host -AsSecureString
		#}
		#[string]$adminUserPasswordRemoteForest = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminUserPasswordRemoteForest))
		#$secureAdminUserPasswordRemoteForest = ConvertTo-SecureString $adminUserPasswordRemoteForest -AsPlainText -Force
		#$adminCreds = $null
		#$adminCreds = New-Object System.Management.Automation.PSCredential $adminUserAccountRemoteForest, $secureAdminUserPasswordRemoteForest
		#
		#Try {
		#
		#	$thisADForest = $null
		#	$thisADForest = Get-ADForest -Identity $targetedADforestFQDN -Server $nearestRWDCInForestRootADDomain -Credential $adminCreds
		#	$adForestAccessibility = $true
		#} Catch {
		#	$adForestAccessibility = $false
		#}
		#Logging ""
		#Logging "Checking Accessibility of the specified AD forest '$targetedADforestFQDN' By Trying To Retrieve AD Forest Data..."
		#If ($adForestAccessibility -eq $true) {
		#
		#	Logging "" "SUCCESS"
		#	Logging "The specified AD forest '$targetedADforestFQDN' is accessible!" "SUCCESS"
		#	Logging "" "SUCCESS"
		#	Logging "Continuing Script..." "SUCCESS"
		#	Logging "" "SUCCESS"
		#} Else {
		#
		#	Logging "" "ERROR"
		#	Logging "The specified AD forest '$targetedADforestFQDN' IS NOT accessible!" "ERROR"
		#	Logging "" "ERROR"
		#	Logging "Please re-run the script and provide the correct credentials to connect to the remote AD forest..." "ERROR"
		#	Logging "" "ERROR"
		#	Logging "Aborting Script..." "ERROR"
		#	Logging "" "ERROR"
		#
		#	EXIT
		#}
	}

	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "SELECT THE TARGET AD DOMAIN..." "HEADER"
	Logging ""

	$rootADDomainInADForest = $null
	$rootADDomainInADForest = $thisADForest.RootDomain

	$listOfADDomainsInADForest = $null
	$listOfADDomainsInADForest = $thisADForest.Domains

	$partitionsContainerDN = $null
	$partitionsContainerDN = $thisADForest.PartitionsContainer

	$adForestMode = $null
	$adForestMode = $thisADForest.ForestMode

	$tableOfADDomainsInADForest = @()
	Logging "Forest Mode/Level...: $adForestMode"

	$nrOfDomainsInForest = 0

	$listOfADDomainsInADForest | ForEach-Object{

		$nrOfDomainsInForest += 1

		$domainFQDN = $null
		$domainFQDN = $_

		$nearestRWDCInADDomain = $null
		$nearestRWDCInADDomain = (Get-ADDomainController -DomainName $domainFQDN -Discover).HostName[0]

		$domainObj = $null
		Try {
			If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
				$domainObj = Get-ADDomain $domainFQDN -Server $nearestRWDCInADDomain
			}
			If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
				$domainObj = Get-ADDomain $domainFQDN -Server $nearestRWDCInADDomain -Credential $adminCreds
			}
		} Catch {
			$domainObj = $null
		}

		$tableOfADDomainsInADForestObj = "" | Select-Object Name,DomainSID,IsRootDomain,DomainMode,IsCurrentDomain,IsAvailable,PDCFsmoOwner,NearestRWDC

		$tableOfADDomainsInADForestObj.Name = $null
		$tableOfADDomainsInADForestObj.Name = $domainFQDN

		$tableOfADDomainsInADForestObj.DomainSID = $null
		$tableOfADDomainsInADForestObj.DomainSID = $domainObj.DomainSID.Value

		$tableOfADDomainsInADForestObj.IsRootDomain = $null
		If ($rootADDomainInADForest -eq $domainFQDN) {
			$tableOfADDomainsInADForestObj.IsRootDomain = "TRUE"
		} Else {
			$tableOfADDomainsInADForestObj.IsRootDomain = "FALSE"
		}

		$tableOfADDomainsInADForestObj.DomainMode = $null
		If ($domainObj) {
			$tableOfADDomainsInADForestObj.DomainMode = $domainObj.DomainMode
		} Else {
			$tableOfADDomainsInADForestObj.DomainMode = "AD Domain Is Not Available"
		}

		$tableOfADDomainsInADForestObj.IsCurrentDomain = $null
		If ($domainFQDN -eq $currentADDomainOfLocalComputer) {
			$tableOfADDomainsInADForestObj.IsCurrentDomain = "TRUE"
		} Else {
			$tableOfADDomainsInADForestObj.IsCurrentDomain = "FALSE"
		}

		$tableOfADDomainsInADForestObj.IsAvailable = $null
		If ($domainObj) {
			$tableOfADDomainsInADForestObj.IsAvailable = "TRUE"
		} Else {
			$tableOfADDomainsInADForestObj.IsAvailable = "FALSE"
		}

		$tableOfADDomainsInADForestObj.PDCFsmoOwner = $null
		If ($domainObj) {
			$tableOfADDomainsInADForestObj.PDCFsmoOwner = $domainObj.PDCEmulator
		} Else {
			$tableOfADDomainsInADForestObj.PDCFsmoOwner = "AD Domain Is Not Available"
		}

		$tableOfADDomainsInADForestObj.NearestRWDC = $null
		If ($domainObj) {
			$tableOfADDomainsInADForestObj.NearestRWDC = $nearestRWDCInADDomain
		} Else {
			$tableOfADDomainsInADForestObj.NearestRWDC = "AD Domain Is Not Available"
		}

		$tableOfADDomainsInADForest += $tableOfADDomainsInADForestObj
	}

	Logging ""
	Logging "List Of AD Domains In AD Forest '$rootADDomainInADForest'..."
	Logging ""
	Logging "$($tableOfADDomainsInADForest | Format-Table | Out-String)"
	Logging "  --> Found [$nrOfDomainsInForest] AD Domain(s) in the AD forest '$rootADDomainInADForest'..." "REMARK"
	Logging ""

	Logging "For the AD domain to be targeted, please provide the FQDN or press [ENTER] for the current AD domain: " "ACTION-NO-NEW-LINE"
	$targetedADdomainFQDN = $null

	$targetedADdomainFQDN = $poc_activeDirectoryDomain

	If ($targetedADdomainFQDN -eq "" -Or $null -eq $targetedADdomainFQDN) {
		$targetedADdomainFQDN = $currentADDomainOfLocalComputer
	}
	Logging ""
	Logging "  --> Selected AD Domain: '$targetedADdomainFQDN'..." "REMARK"

	$adDomainValidity = $false
	$listOfADDomainsInADForest | ForEach-Object{
		$domainFQDN = $null
		$domainFQDN = $_
		If ($domainFQDN -eq $targetedADdomainFQDN) {
			$adDomainValidity = $true
		}
	}
	Logging ""
	Logging "Checking existence of the specified AD domain '$targetedADdomainFQDN' in the AD forest '$rootADDomainInADForest'..."
	If ($adDomainValidity -eq $true) {

		Logging "" "SUCCESS"
		Logging "The specified AD domain '$targetedADdomainFQDN' exists in the AD forest '$rootADDomainInADForest'!" "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Else {

		Logging "" "ERROR"
		Logging "The specified AD domain '$targetedADdomainFQDN' DOES NOT exist in the AD forest '$rootADDomainInADForest'!" "ERROR"
		Logging "" "ERROR"
		Logging "Please re-run the script and provide the FQDN of an AD domain that does exist in the AD forest '$rootADDomainInADForest'..." "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script..." "ERROR"
		Logging "" "ERROR"

		EXIT
	}

	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "TESTING IF REQUIRED PERMISSIONS ARE AVAILABLE (DOMAIN/ENTERPRISE ADMINS OR ADMINISTRATORS CREDENTIALS)..." "HEADER"
	Logging ""

	If ($localADforest -eq $true) {

		$targetedDomainObjectSID = ($tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}).DomainSID
		$domainAdminRID = "512"
		$domainAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($targetedDomainObjectSID + "-" + $domainAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
		$userIsDomainAdmin = $null
		$userIsDomainAdmin = testAdminRole $domainAdminRole
		If (!$userIsDomainAdmin) {

			$forestRootDomainObjectSID = ($tableOfADDomainsInADForest | Where-Object{$_.IsRootDomain -eq "TRUE"}).DomainSID
			$enterpriseAdminRID = "519"
			$enterpriseAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($forestRootDomainObjectSID + "-" + $enterpriseAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
			$userIsEnterpriseAdmin = $null
			$userIsEnterpriseAdmin = testAdminRole $enterpriseAdminRole
			If (!$userIsEnterpriseAdmin) {

				Logging "The user account '$adRunningUserAccount' IS NOT running with Domain/Enterprise Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "ERROR"
				Logging "The user account '$adRunningUserAccount' IS NOT a member of '$domainAdminRole' and NOT a member of '$enterpriseAdminRole'!..." "ERROR"
				Logging "" "ERROR"
				Logging "For this script to run successfully, Domain/Enterprise Administrator equivalent permissions are required..." "ERROR"
				Logging "" "ERROR"
				Logging "Aborting Script..." "ERROR"
				Logging "" "ERROR"
				
				EXIT
			} Else {

				Logging "The user account '$adRunningUserAccount' is running with Enterprise Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
				Logging "The user account '$adRunningUserAccount' is a member of '$enterpriseAdminRole'!..." "SUCCESS"
				Logging "" "SUCCESS"
				Logging "Continuing Script..." "SUCCESS"
				Logging "" "SUCCESS"
			}
		} Else {

			Logging "The user account '$adRunningUserAccount' is running with Domain Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
			Logging "The user account '$adRunningUserAccount' is a member of '$domainAdminRole'!..." "SUCCESS"
			Logging "" "SUCCESS"
			Logging "Continuing Script..." "SUCCESS"
			Logging "" "SUCCESS"
		}
	}

	If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false) {
		Try {
			Set-ADUser -Identity KRBTGT -DisplayName $((Get-ADUser -Identity KRBTGT -Properties Description -Server $targetedADdomainFQDN).Description) -Server $targetedADdomainFQDN
			Set-ADUser -Identity KRBTGT -Clear DisplayName -Server $targetedADdomainFQDN
			Logging "The user account '$adRunningUserAccount' is running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
			Logging "" "SUCCESS"
			Logging "Continuing Script..." "SUCCESS"
			Logging "" "SUCCESS"
		} Catch {
			Logging "The user account '$adRunningUserAccount' IS NOT running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "ERROR"
			Logging "" "ERROR"
			Logging "For this script to run successfully, Administrators equivalent permissions are required in the AD Domain '$targetedADdomainFQDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Aborting Script..." "ERROR"
			Logging "" "ERROR"
			
			EXIT
		}
	}
	If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
		Try {
			Set-ADUser -Identity KRBTGT -DisplayName $((Get-ADUser -Identity KRBTGT -Properties Description -Server $targetedADdomainFQDN -Credential $adminCreds).Description) -Server $targetedADdomainFQDN -Credential $adminCreds
			Set-ADUser -Identity KRBTGT -Clear DisplayName -Server $targetedADdomainFQDN -Credential $adminCreds
			Logging "The user account '$adminUserAccountRemoteForest' is running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
			Logging "" "SUCCESS"
			Logging "Continuing Script..." "SUCCESS"
			Logging "" "SUCCESS"
		} Catch {
			Logging "The user account '$adminUserAccountRemoteForest' IS NOT running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "ERROR"
			Logging "" "ERROR"
			Logging "For this script to run successfully, Administrators equivalent permissions are required in the AD Domain '$targetedADdomainFQDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Aborting Script..." "ERROR"
			Logging "" "ERROR"
			
			EXIT
		}
	}

	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "GATHERING TARGETED AD DOMAIN INFORMATION..." "HEADER"
	Logging ""

	$targetedADdomainData = $null
	$targetedADdomainData = $tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}

	$targetedADdomainNearestRWDC = $null
	$targetedADdomainNearestRWDC = $targetedADdomainData.NearestRWDC

	$thisADDomain = $null
	Try {
		If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
			$thisADDomain = Get-ADDomain $targetedADdomainFQDN -Server $targetedADdomainNearestRWDC
		}
		If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
			$thisADDomain = Get-ADDomain $targetedADdomainFQDN -Server $targetedADdomainNearestRWDC -Credential $adminCreds
		}
	} Catch {
		$thisADDomain = $null
	}
	If ($thisADDomain) {

		$targetedADdomainDomainSID = $null
		$targetedADdomainDomainSID = $thisADDomain.DomainSID.Value

		$targetedADdomainRWDCWithPDCFSMOFQDN = $null
		$targetedADdomainRWDCWithPDCFSMOFQDN = $thisADDomain.PDCEmulator

		$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN = $null
		If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
			$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN = (Get-ADDomainController $targetedADdomainRWDCWithPDCFSMOFQDN -Server $targetedADdomainNearestRWDC).NTDSSettingsObjectDN
		}
		If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
			$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN = (Get-ADDomainController $targetedADdomainRWDCWithPDCFSMOFQDN -Server $targetedADdomainNearestRWDC -Credential $adminCreds).NTDSSettingsObjectDN
		}

		$targetedADdomainDomainFunctionalMode = $null
		$targetedADdomainDomainFunctionalMode = $thisADDomain.DomainMode
		$targetedADdomainDomainFunctionalModeLevel = $null
		If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
			$targetedADdomainDomainFunctionalModeLevel = (Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -SearchBase $partitionsContainerDN -Properties "msDS-Behavior-Version" -Server $targetedADdomainNearestRWDC)."msDS-Behavior-Version"
		}
		If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
			$targetedADdomainDomainFunctionalModeLevel = (Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -SearchBase $partitionsContainerDN -Properties "msDS-Behavior-Version" -Server $targetedADdomainNearestRWDC -Credential $adminCreds)."msDS-Behavior-Version"
		}

		Try {
			$gpoObjXML = $null
			If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
				[xml]$gpoObjXML = Get-GPOReport -Domain $targetedADdomainFQDN -Guid '{31B2F340-016D-11D2-945F-00C04FB984F9}' -ReportType Xml -Server $targetedADdomainNearestRWDC
			}
			If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {

				$targetedServerSession = New-PSSession -ComputerName $targetedADdomainNearestRWDC -Credential $adminCreds -ErrorAction SilentlyContinue
				[xml]$gpoObjXML = Invoke-Command -Session $targetedServerSession -ArgumentList $targetedADdomainFQDN,$targetedADdomainNearestRWDC -ScriptBlock {
					Param (
						$targetedADdomainFQDN,
						$targetedADdomainNearestRWDC
					)
					[xml]$gpoObjXML = Get-GPOReport -Domain $targetedADdomainFQDN -Guid '{31B2F340-016D-11D2-945F-00C04FB984F9}' -ReportType Xml -Server $targetedADdomainNearestRWDC
					Return $gpoObjXML
				}
				Remove-PSSession $targetedServerSession
			}
			$targetedADdomainMaxTgtLifetimeHrs = $null
			$targetedADdomainMaxTgtLifetimeHrs = (($gpoObjXML.gpo.Computer.ExtensionData | Where-Object{$_.name -eq 'Security'}).Extension.ChildNodes | Where-Object{$_.Name -eq 'MaxTicketAge'}).SettingNumber
			$targetedADdomainMaxClockSkewMins = $null
			$targetedADdomainMaxClockSkewMins = (($gpoObjXML.gpo.Computer.ExtensionData | Where-Object{$_.name -eq 'Security'}).Extension.ChildNodes | Where-Object{$_.Name -eq 'MaxClockSkew'}).SettingNumber
			$sourceInfoFrom = "Default Domain GPO"
		} Catch {
			Logging "Could not lookup 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) from the 'Default Domain Policy' GPO, so default values will be assumed." "WARNING"
			Logging ""
			$targetedADdomainMaxTgtLifetimeHrs = 10
			$targetedADdomainMaxClockSkewMins = 5
			$sourceInfoFrom = "Assumed"
		}
	} Else {
		$targetedADdomainRWDCWithPDCFSMOFQDN = "Unavailable"
		$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN = "Unavailable"
		$targetedADdomainDomainFunctionalMode = "Unavailable"
		$targetedADdomainDomainFunctionalModeLevel = "Unavailable"
		$targetedADdomainMaxTgtLifetimeHrs = "Unavailable"
		$targetedADdomainMaxClockSkewMins = "Unavailable"
		$sourceInfoFrom = "Unavailable"
	}

	Logging "Domain FQDN...........................: '$targetedADdomainFQDN'"
	Logging "Domain Functional Mode................: '$targetedADdomainDomainFunctionalMode'"
	Logging "Domain Functional Mode Level..........: '$targetedADdomainDomainFunctionalModeLevel'"
	Logging "FQDN RWDC With PDC FSMO...............: '$targetedADdomainRWDCWithPDCFSMOFQDN'"
	Logging "DSA RWDC With PDC FSMO................: '$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN'"
	Logging "Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
	Logging "Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
	Logging "TGT Lifetime/Clock Skew Sourced From..: '$sourceInfoFrom'"
	Logging ""
	Logging "Checking Domain Functional Mode of targeted AD domain '$targetedADdomainFQDN' is high enough..."

	If ($targetedADdomainDomainFunctionalModeLevel -ne "Unavailable" -And $targetedADdomainDomainFunctionalModeLevel -ge 3) {

		Logging "" "SUCCESS"
		Logging "The specified AD domain '$targetedADdomainFQDN' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..." "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Else {

		Logging "" "ERROR"
		Logging "It CANNOT be determined the specified AD domain '$targetedADdomainFQDN' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..." "ERROR"
		Logging "" "ERROR"
		Logging "AD domains with Windows Server 2000/2003 DCs CANNOT do KDC PAC validation using the previous (N-1) KrbTgt Account Password" "ERROR"
		Logging "like Windows Server 2008 and higher DCs are able to. Windows Server 2000/2003 DCs will only attempt it with the current (N)" "ERROR"
		Logging "KrbTgt Account Password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed," "ERROR"
		Logging "authentication issues could be experience because the target server gets a PAC validation error when asking the KDC (DC)" "ERROR"
		Logging "to validate the KDC signature of the PAC that is inside the service ticket that was presented by the client to the server." "ERROR"
		Logging "This problem would potentially persist for the lifetime of the service ticket(s). And by the way... for Windows Server" "ERROR"
		Logging "2000/2003 support already ended years ago. Time to upgrade to higher version dude!" "ERROR"
		Logging "Be aware though, when increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt Account" "ERROR"
		Logging "will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new" "ERROR"
		Logging "keys for DES, RC4, AES128, AES256!" "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script..." "ERROR"
		Logging "" "ERROR"

		EXIT
	}

	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "GATHERING DOMAIN CONTROLLER INFORMATION AND TESTING CONNECTIVITY..." "HEADER"
	Logging ""

	$tableOfDCsInADDomain = @()

	$listOfRWDCsInADDomain = $null
	$listOfRWDCsInADDomain = $thisADDomain.ReplicaDirectoryServers

	$nrOfRWDCs = 0
	$nrOfReachableRWDCs = 0
	$nrOfUnReachableRWDCs = 0

	If ($listOfRWDCsInADDomain) {
		$listOfRWDCsInADDomain | ForEach-Object{

			$rwdcFQDN = $null
			$rwdcFQDN = $_

			$rwdcObj = $null
			If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
				$rwdcObj = Get-ADDomainController $rwdcFQDN -Server $targetedADdomainNearestRWDC
			}
			If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
				$rwdcObj = Get-ADDomainController $rwdcFQDN -Server $targetedADdomainNearestRWDC -Credential $adminCreds
			}

			$tableOfDCsInADDomainObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","Krb Tgt","Pwd Last Set","Org RWDC","Org Time","Ver","IP Address","OS Version",Reachable,"Source RWDC FQDN","Source RWDC DSA"

			$tableOfDCsInADDomainObj."Host Name" = $null
			$tableOfDCsInADDomainObj."Host Name" = $rwdcFQDN

			$tableOfDCsInADDomainObj.PDC = $null
			If ($rwdcObj.OperationMasterRoles -contains "PDCEmulator") {
				$tableOfDCsInADDomainObj.PDC = $True
			} Else {
				$tableOfDCsInADDomainObj.PDC = $False
			}

			$tableOfDCsInADDomainObj."Site Name" = $null
			$tableOfDCsInADDomainObj."Site Name" = $rwdcObj.Site

			$tableOfDCsInADDomainObj."DS Type" = $null
			$tableOfDCsInADDomainObj."DS Type" = "Read/Write"

			$rwdcKrbTgtSamAccountName = $null
			If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 4) {

				$rwdcKrbTgtSamAccountName = "krbtgt"
			}
			If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {

				$rwdcKrbTgtSamAccountName = "krbtgt_TEST"
			}
			$tableOfDCsInADDomainObj."Krb Tgt" = $rwdcKrbTgtSamAccountName

			$rwdcKrbTgtObject = $null
			If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
				$rwdcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rwdcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN
			}
			If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
				$rwdcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rwdcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN -Credential $adminCreds
			}
			$tableOfDCsInADDomainObj."Pwd Last Set" = $null
			$tableOfDCsInADDomainObj."Org RWDC" = $null
			$tableOfDCsInADDomainObj."Org Time" = $null
			$tableOfDCsInADDomainObj."Ver" = $null
			If ($rwdcKrbTgtObject) {

				$rwdcKrbTgtObjectDN = $null
				$rwdcKrbTgtObjectDN = $rwdcKrbTgtObject.DistinguishedName

				$rwdcKrbTgtPwdLastSet = $null
				$rwdcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rwdcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

				$tableOfDCsInADDomainObj."Pwd Last Set" = $rwdcKrbTgtPwdLastSet

				$metadataObject = $null
				If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
					$metadataObject = Get-ADReplicationAttributeMetadata $rwdcKrbTgtObjectDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN
				}
				If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
					$metadataObject = Get-ADReplicationAttributeMetadata $rwdcKrbTgtObjectDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN -Credential $adminCreds
				}			
				$metadataObjectAttribPwdLastSet = $null
				$metadataObjectAttribPwdLastSet = $metadataObject | Where-Object{$_.AttributeName -eq "pwdLastSet"}
				$orgRWDCNTDSSettingsObjectDN = $null
				$orgRWDCNTDSSettingsObjectDN = $metadataObjectAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
				$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $null
				If ($orgRWDCNTDSSettingsObjectDN) {			

					$orgRWDCServerObjectDN = $null
					$orgRWDCServerObjectDN = $orgRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)

					$orgRWDCServerObjectObj = $null
					If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
						$orgRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN")
					}
					If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
						$orgRWDCServerObjectObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
					}
					$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObj.dnshostname[0]
				} Else {
					$metadataObjectAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
				}
				$metadataObjectAttribPwdLastSetOrgTime = $null
				$metadataObjectAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
				$metadataObjectAttribPwdLastSetVersion = $null
				$metadataObjectAttribPwdLastSetVersion = $metadataObjectAttribPwdLastSet.Version

				$tableOfDCsInADDomainObj."Org RWDC" = $metadataObjectAttribPwdLastSetOrgRWDCFQDN
				$tableOfDCsInADDomainObj."Org Time" = $metadataObjectAttribPwdLastSetOrgTime
				$tableOfDCsInADDomainObj."Ver" = $metadataObjectAttribPwdLastSetVersion
			} Else {

				$tableOfDCsInADDomainObj."Pwd Last Set" = "No Such Object"
				$tableOfDCsInADDomainObj."Org RWDC" = "No Such Object"
				$tableOfDCsInADDomainObj."Org Time" = "No Such Object"
				$tableOfDCsInADDomainObj."Ver" = "No Such Object"
			}

			$tableOfDCsInADDomainObj."IP Address" = $null
			$tableOfDCsInADDomainObj."IP Address" = $rwdcObj.IPv4Address

			$tableOfDCsInADDomainObj."OS Version" = $null
			$tableOfDCsInADDomainObj."OS Version" = $rwdcObj.OperatingSystem

			$ports = 135,389	

			$connectionCheckOK = $true

			$ports | ForEach-Object{

				$port = $null
				$port = $_

				$connectionResult = $null
				$connectionResult = portConnectionCheck $rwdcFQDN $port 500
				If ($connectionResult -eq "ERROR") {
					$connectionCheckOK = $false
				}
			}
			If ($connectionCheckOK -eq $true) {

				$rwdcRootDSEObj = $null
				If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
					$rwdcRootDSEObj = [ADSI]"LDAP://$rwdcFQDN/rootDSE"
				}
				If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
					$rwdcRootDSEObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rwdcFQDN/rootDSE"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				}
				If ($rwdcRootDSEObj.Path -eq $null) {

					$tableOfDCsInADDomainObj.Reachable = $False
					$nrOfUnReachableRWDCs += 1
					
				} Else {

					$tableOfDCsInADDomainObj.Reachable = $True
					$nrOfReachableRWDCs += 1
				}
			} Else {

				$tableOfDCsInADDomainObj.Reachable = $False
				$nrOfUnReachableRWDCs += 1
			}
			If ($rwdcObj.OperationMasterRoles -contains "PDCEmulator") {

				$tableOfDCsInADDomainObj."Source RWDC FQDN" = "N.A."
				$tableOfDCsInADDomainObj."Source RWDC DSA" = "N.A."
			} Else {

				$tableOfDCsInADDomainObj."Source RWDC FQDN" = $targetedADdomainRWDCWithPDCFSMOFQDN
				$tableOfDCsInADDomainObj."Source RWDC DSA" = $targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN
			}

			$nrOfRWDCs += 1

			$tableOfDCsInADDomain += $tableOfDCsInADDomainObj
		}
	}

	$listOfRODCsInADDomain = $null
	$listOfRODCsInADDomain = $thisADDomain.ReadOnlyReplicaDirectoryServers

	$nrOfRODCs = 0
	$nrOfReachableRODCs = 0
	$nrOfUnReachableRODCs = 0
	$nrOfUnDetermined = 0

	If ($listOfRODCsInADDomain) {
		$listOfRODCsInADDomain | ForEach-Object{

			$rodcFQDN = $null
			$rodcFQDN = $_

			$rodcObj = $null
			If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
				$rodcObj = Get-ADDomainController $rodcFQDN -Server $targetedADdomainNearestRWDC
			}
			If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
				$rodcObj = Get-ADDomainController $rodcFQDN -Server $targetedADdomainNearestRWDC -Credential $adminCreds
			}

			$tableOfDCsInADDomainObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","Krb Tgt","Pwd Last Set","Org RWDC","Org Time","Ver","IP Address","OS Version",Reachable,"Source RWDC FQDN","Source RWDC DSA"

			$tableOfDCsInADDomainObj."Host Name" = $null
			$tableOfDCsInADDomainObj."Host Name" = $rodcFQDN

			$tableOfDCsInADDomainObj.PDC = $null
			$tableOfDCsInADDomainObj.PDC = $False

			$tableOfDCsInADDomainObj."Site Name" = $null
			If ($rodcObj.OperatingSystem) {
				$tableOfDCsInADDomainObj."Site Name" = $rodcObj.Site
			} Else {
				$tableOfDCsInADDomainObj."Site Name" = "Unknown"
			}

			$tableOfDCsInADDomainObj."DS Type" = $null
			$tableOfDCsInADDomainObj."DS Type" = "Read-Only"

			$rodcKrbTgtSamAccountName = $null
			If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 4) {

				If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
					$rodcKrbTgtSamAccountName = ((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDC)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDC).Name
				}
				If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
					$rodcKrbTgtSamAccountName = ((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDC -Credential $adminCreds)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDC -Credential $adminCreds).Name
				}			
			}
			If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {

				If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
					$rodcKrbTgtSamAccountName = $(((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDC)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDC).Name) + "_TEST"
				}
				If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
					$rodcKrbTgtSamAccountName = $(((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDC -Credential $adminCreds)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDC -Credential $adminCreds).Name) + "_TEST"
				}
			}

			$tableOfDCsInADDomainObj."Krb Tgt" = $null
			$tableOfDCsInADDomainObj."Krb Tgt" = $rodcKrbTgtSamAccountName

			$rodcKrbTgtObject = $null
			If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
				$rodcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rodcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN
			}
			If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
				$rodcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rodcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN -Credential $adminCreds
			}
			$tableOfDCsInADDomainObj."Pwd Last Set" = $null
			$tableOfDCsInADDomainObj."Org RWDC" = $null
			$tableOfDCsInADDomainObj."Org Time" = $null
			$tableOfDCsInADDomainObj."Ver" = $null
			If ($rodcKrbTgtObject) {

				$rodcKrbTgtObjectDN = $null
				$rodcKrbTgtObjectDN = $rodcKrbTgtObject.DistinguishedName		

				$rodcKrbTgtPwdLastSet = $null
				$rodcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rodcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

				$tableOfDCsInADDomainObj."Pwd Last Set" = $rodcKrbTgtPwdLastSet

				$metadataObject = $null
				If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
					$metadataObject = Get-ADReplicationAttributeMetadata $rodcKrbTgtObjectDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN
				}
				If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
					$metadataObject = Get-ADReplicationAttributeMetadata $rodcKrbTgtObjectDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN -Credential $adminCreds
				}
				$metadataObjectAttribPwdLastSet = $null
				$metadataObjectAttribPwdLastSet = $metadataObject | Where-Object{$_.AttributeName -eq "pwdLastSet"}
				$orgRWDCNTDSSettingsObjectDN = $null
				$orgRWDCNTDSSettingsObjectDN = $metadataObjectAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
				$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $null
				If ($orgRWDCNTDSSettingsObjectDN) {			

					$orgRWDCServerObjectDN = $null
					$orgRWDCServerObjectDN = $orgRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)

					$orgRWDCServerObjectObj = $null
					If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
						$orgRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN")
					}
					If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
						$orgRWDCServerObjectObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
					}
					$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObj.dnshostname[0]
				} Else {
					$metadataObjectAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
				}
				$metadataObjectAttribPwdLastSetOrgTime = $null
				$metadataObjectAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
				$metadataObjectAttribPwdLastSetVersion = $null
				$metadataObjectAttribPwdLastSetVersion = $metadataObjectAttribPwdLastSet.Version

				$tableOfDCsInADDomainObj."Org RWDC" = $metadataObjectAttribPwdLastSetOrgRWDCFQDN
				$tableOfDCsInADDomainObj."Org Time" = $metadataObjectAttribPwdLastSetOrgTime
				$tableOfDCsInADDomainObj."Ver" = $metadataObjectAttribPwdLastSetVersion
			} Else {

				$tableOfDCsInADDomainObj."Pwd Last Set" = "No Such Object"
				$tableOfDCsInADDomainObj."Org RWDC" = "No Such Object"
				$tableOfDCsInADDomainObj."Org Time" = "No Such Object"
				$tableOfDCsInADDomainObj."Ver" = "No Such Object"
			}

			$tableOfDCsInADDomainObj."IP Address" = $null
			If ($rodcObj.OperatingSystem) {
				$tableOfDCsInADDomainObj."IP Address" = $rodcObj.IPv4Address
			} Else {
				$tableOfDCsInADDomainObj."IP Address" = "Unknown"
			}

			$tableOfDCsInADDomainObj."OS Version" = $null
			If ($rodcObj.OperatingSystem) {
				$tableOfDCsInADDomainObj."OS Version" = $rodcObj.OperatingSystem
			} Else {
				$tableOfDCsInADDomainObj."OS Version" = "Unknown"
			}

			$ports = 135,389	

			$connectionCheckOK = $true

			$ports | ForEach-Object{

				$port = $null
				$port = $_

				$connectionResult = $null
				$connectionResult = portConnectionCheck $rodcFQDN $port 500
				If ($connectionResult -eq "ERROR") {
					$connectionCheckOK = $false
				}
			}
			If ($connectionCheckOK -eq $true) {		

				$rodcRootDSEObj = $null
				If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
					$rodcRootDSEObj = [ADSI]"LDAP://$rodcFQDN/rootDSE"
				}
				If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
					$rodcRootDSEObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rodcFQDN/rootDSE"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				}
				If ($rodcRootDSEObj.Path -eq $null) {

					$tableOfDCsInADDomainObj.Reachable = $False
					$nrOfUnReachableRODCs += 1
				} Else {

					$tableOfDCsInADDomainObj.Reachable = $True
					$nrOfReachableRODCs += 1
				}
			} Else {

				$tableOfDCsInADDomainObj.Reachable = $False
				$nrOfUnReachableRODCs += 1
			}
			If ($rodcObj.OperatingSystem) {

				If ($tableOfDCsInADDomainObj.Reachable -eq $True) {

					$rodcNTDSSettingsObjectDN = $null
					$rodcNTDSSettingsObjectDN = $rodcObj.NTDSSettingsObjectDN

					$dsDirSearcher = $null
					$dsDirSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
					$dsDirSearcher.SearchRoot = $null
					If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
						$dsDirSearcher.SearchRoot = "LDAP://$rodcFQDN/$rodcNTDSSettingsObjectDN"
					}
					If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
						$dsDirSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rodcFQDN/$rodcNTDSSettingsObjectDN"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
					}
					$dsDirSearcher.Filter = $null
					$dsDirSearcher.Filter = "(&(objectClass=nTDSConnection)(ms-DS-ReplicatesNCReason=*))"
					$sourceRWDCsNTDSSettingsObjectDN = $null
					$sourceRWDCsNTDSSettingsObjectDN = $dsDirSearcher.FindAll().Properties.fromserver

					$sourceRWDCsNTDSSettingsObjectDN | ForEach-Object{
						$sourceRWDCNTDSSettingsObjectDN = $null
						$sourceRWDCNTDSSettingsObjectDN = $_

						$sourceRWDCServerObjectDN = $null
						$sourceRWDCServerObjectDN = $sourceRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)

						If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
							$sourceRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainNearestRWDC/$sourceRWDCServerObjectDN")
						}
						If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
							$sourceRWDCServerObjectObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainNearestRWDC/$sourceRWDCServerObjectDN"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
						}

						If (($sourceRWDCServerObjectObj.dnshostname).SubString($sourceRWDCServerObjectObj.name.Length + 1) -eq $rodcObj.Domain) {

							$tableOfDCsInADDomainObj."Source RWDC FQDN" = $sourceRWDCServerObjectObj.dnshostname[0]

							$tableOfDCsInADDomainObj."Source RWDC DSA" = $sourceRWDCsNTDSSettingsObjectDN[0]
						}
					}
				} Else {

					$tableOfDCsInADDomainObj."Source RWDC FQDN" = "RODC Unreachable"
					$tableOfDCsInADDomainObj."Source RWDC DSA" = "RODC Unreachable"
				}
			} Else {

				$tableOfDCsInADDomainObj."Source RWDC FQDN" = "Unknown"
				$tableOfDCsInADDomainObj."Source RWDC DSA" = "Unknown"
			}
			If ($rodcObj.OperatingSystem) {

				$nrOfRODCs += 1
			} Else {

				$nrOfUnDetermined += 1
			}

			$tableOfDCsInADDomain += $tableOfDCsInADDomainObj
		}
	}

	$tableOfDCsInADDomain = $tableOfDCsInADDomain | Sort-Object -Property @{Expression = "DS Type"; Descending = $False}, @{Expression = "PDC"; Descending = $True}, @{Expression = "Reachable"; Descending = $True}

	$nrOfDCs = $nrOfRWDCs + $nrOfRODCs

	Logging "" "REMARK"
	Logging "List Of Domain Controllers In AD Domains '$targetedADdomainFQDN'..."
	Logging "" "REMARK"
	Logging "$($tableOfDCsInADDomain | Format-Table * -Autosize | Out-String)"
	Logging "" "REMARK"
	Logging "REMARKS:" "REMARK"
	Logging " - 'N.A.' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RWDC is considered as the master for this script." "REMARK"
	Logging " - 'RODC Unreachable' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RODC cannot be reached to determine its replicating source" "REMARK"
	Logging "     RWDC/DSA. The unavailability can be due to firewalls/networking or the RODC actually being down." "REMARK"
	Logging " - 'Unknown' in various columns means that an RODC was found that may not be a true Windows Server RODC. It may be an appliance acting as an RODC." "REMARK"
	Logging " - 'RWDC Demoted' in the column 'Org RWDC' means the RWDC existed once, but it does not exist anymore as it has been decommissioned in the past." "REMARK"
	Logging "     This is normal." "REMARK"
	Logging " - 'No Such Object' in the columns 'Pwd Last Set', 'Org RWDC', 'Org Time' or 'Ver' means the targeted object was not found in the AD domain." "REMARK"
	Logging "     Although this is possible for any targeted object, this is most likely the case when targeting the KrbTgt TEST/BOGUS accounts and if those" "REMARK"
	Logging "     do not exist yet. This may also occur for an appliance acting as an RODC as in that case no KrbTgt TEST/BOGUS account is created." "REMARK"
	Logging "" "REMARK"
	Logging "" "REMARK"
	Logging "" "REMARK"
	Logging "  --> Found [$nrOfDCs] Real DC(s) In AD Domain..." "REMARK"
	Logging "" "REMARK"
	Logging "  --> Found [$nrOfRWDCs] RWDC(s) In AD Domain..." "REMARK"
	Logging "  --> Found [$nrOfReachableRWDCs] Reachable RWDC(s) In AD Domain..." "REMARK"
	Logging "  --> Found [$nrOfUnReachableRWDCs] UnReachable RWDC(s) In AD Domain..." "REMARK"
	Logging "" "REMARK"
	Logging "  --> Found [$nrOfRODCs] RODC(s) In AD Domain..." "REMARK"
	Logging "  --> Found [$nrOfReachableRODCs] Reachable RODC(s) In AD Domain..." "REMARK"
	Logging "  --> Found [$nrOfUnReachableRODCs] UnReachable RODC(s) In AD Domain..." "REMARK"
	Logging "  --> Found [$nrOfUnDetermined] Undetermined RODC(s) In AD Domain..." "REMARK"
	Logging "" "REMARK"

	If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "SELECT THE SCOPE OF THE KRBTGT ACCOUNT(S) TO TARGET..." "HEADER"
		Logging ""
		Logging "Which KrbTgt account do you want to target?"
		Logging ""
		Logging " - 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain"
		Logging ""
		Logging " - 2 - Scope of KrbTgt in use by specific RODC - Single RODC in the AD Domain"
		Logging ""
		Logging " - 3 - Scope of KrbTgt in use by specific RODC - Multiple RODCs in the AD Domain"
		Logging ""
		Logging " - 4 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain"
		Logging ""
		Logging ""
		Logging " - 0 - Exit Script"
		Logging ""
		Logging "Please specify the scope of KrbTgt Account to target: " "ACTION-NO-NEW-LINE"

		$targetKrbTgtAccountNr = $poc_KRBTGT_Account_Scope
		Logging ""

		If (($targetKrbTgtAccountNr -ne 1 -And $targetKrbTgtAccountNr -ne 2 -And $targetKrbTgtAccountNr -ne 3 -And $targetKrbTgtAccountNr -ne 4) -Or $targetKrbTgtAccountNr -notmatch "^[\d\.]+$") {
			Logging "  --> Chosen Scope KrbTgt Account Target: 0 - Exit Script..." "REMARK"
			Logging ""
			
			EXIT
		}

		If ($targetKrbTgtAccountNr -eq 1) {
			$targetKrbTgtAccountDescription = "1 - Scope of KrbTgt in use by all RWDCs in the AD Domain..."
		}

		If ($targetKrbTgtAccountNr -eq 2) {
			$targetKrbTgtAccountDescription = "2 - Scope of KrbTgt in use by specific RODC - Single RODC in the AD Domain..."
		}

		If ($targetKrbTgtAccountNr -eq 3) {
			$targetKrbTgtAccountDescription = "3 - Scope of KrbTgt in use by specific RODC - Multiple RODCs in the AD Domain..."
		}

		If ($targetKrbTgtAccountNr -eq 4) {
			$targetKrbTgtAccountDescription = "4 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain..."
		}
		Logging "  --> Chosen Scope KrbTgt Account Target: $targetKrbTgtAccountDescription" "REMARK"
		Logging ""

		If ($targetKrbTgtAccountNr -eq 2) {
			Logging "Specify the FQDN of single RODC for which the KrbTgt Account Password must be reset: " "ACTION-NO-NEW-LINE"

			$targetRODCFQDNList = $poc_activeDirectoryDomainController
			Logging ""
			Logging "  --> Specified RODC:" "REMARK"
			Logging "       * $targetRODCFQDNList" "REMARK"
			Logging ""
		}

		If ($targetKrbTgtAccountNr -eq 3) {
			Logging "Specify a comma-separated list of FQDNs of RODCs for which the KrbTgt Account Password must be reset: " "ACTION-NO-NEW-LINE"

			$targetRODCFQDNList = $poc_activeDirectoryDomainController
			$targetRODCFQDNList = $targetRODCFQDNList.Split(",")
			Logging ""
			Logging "  --> Specified RODCs:" "REMARK"
			$targetRODCFQDNList | ForEach-Object{
				Logging "       * $($_)" "REMARK"
			}
			Logging ""
		}
	}

	If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {

		If ($modeOfOperationNr -eq 2) {
			Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
			Logging "SIMULATION MODE (MODE $modeOfOperationNr) - CREATING/REPLICATING TEMPORARY CANARY OBJECT ($targetKrbTgtAccountDescription)" "HEADER"
			Logging ""
		}

		If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {
			Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
			Logging "REAL RESET MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED KRBTGT ACCOUNT(S) ($targetKrbTgtAccountDescription)" "HEADER"
			Logging ""
		}

		Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
		$continueOrStop = $null

		$continueOrStop = "continue"

		If ($continueOrStop.ToUpper() -ne "CONTINUE") {
			$continueOrStop = "STOP"
		}
		Logging ""
		Logging "  --> Chosen: $continueOrStop" "REMARK"
		Logging ""

		If ($continueOrStop.ToUpper() -ne "CONTINUE") {
			EXIT
		}	

		If ($targetKrbTgtAccountNr -eq 1) {

			$krbTgtSamAccountName = $null
			$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Krb Tgt"

			$targetedADdomainSourceRWDCFQDN = $null
			$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"

			$krbTgtDN = $null
			If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
				$krbTgtDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainNearestRWDC).DistinguishedName
			}
			If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
				$krbTgtDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainNearestRWDC -Credential $adminCreds).DistinguishedName
			}
			Logging "+++++" "REMARK"
			Logging "+++ Processing KrbTgt Account....: '$krbTgtSamAccountName' | '$krbTgtDN' +++" "REMARK"
			Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
			Logging "+++++" "REMARK"
			Logging "" "REMARK"

			$targetedADdomainSourceRWDCIsPDC = $null
			$targetedADdomainSourceRWDCIsPDC = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True}).PDC

			$targetedADdomainSourceRWDCSiteName = $null
			$targetedADdomainSourceRWDCSiteName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Site Name"

			$targetedADdomainSourceRWDCDSType = $null
			$targetedADdomainSourceRWDCDSType = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."DS Type"

			$targetedADdomainSourceRWDCIPAddress = $null
			$targetedADdomainSourceRWDCIPAddress = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."IP Address"

			$targetedADdomainRWDCReachability = $null
			$targetedADdomainRWDCReachability = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True}).Reachable

			$targetedADdomainRWDCSourceRWDCFQDN = "N.A."

			$targetedADdomainRWDCTime = 0.00

			If ($targetedADdomainRWDCReachability) {

				If ($modeOfOperationNr -eq 2) {

					$targetObjectToCheckDN = $null
					$targetObjectToCheckDN = createTempCanaryObject $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $execDateTimeCustom1 $localADforest $remoteCredsUsed $adminCreds
					If (!$targetObjectToCheckDN) {
						EXIT
					}
				}

				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {

					$targetObjectToCheck = $null
					If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
						$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN
					}
					If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
						$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN -Credential $adminCreds
					}
					If ($targetObjectToCheck) {

						$targetObjectToCheckDN = $null
						$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName			

						$targetObjectToCheckPwdLastSet = $null
						$targetObjectToCheckPwdLastSet = Get-Date $([datetime]::fromfiletime($targetObjectToCheck.pwdLastSet))

						$expirationTimeForNMinusOneKerbTickets = $null
						$expirationTimeForNMinusOneKerbTickets = (($targetObjectToCheckPwdLastSet.AddHours($targetedADdomainMaxTgtLifetimeHrs)).AddMinutes($targetedADdomainMaxClockSkewMins)).AddMinutes($targetedADdomainMaxClockSkewMins)

						$metadataObject = $null
						If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
							$metadataObject = Get-ADReplicationAttributeMetadata $targetObjectToCheckDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN
						}
						If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
							$metadataObject = Get-ADReplicationAttributeMetadata $targetObjectToCheckDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN -Credential $adminCreds
						}
						$metadataObjectAttribPwdLastSet = $null
						$metadataObjectAttribPwdLastSet = $metadataObject | Where-Object{$_.AttributeName -eq "pwdLastSet"}
						$orgRWDCNTDSSettingsObjectDN = $null
						$orgRWDCNTDSSettingsObjectDN = $metadataObjectAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
						$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $null
						If ($orgRWDCNTDSSettingsObjectDN) {			

							$orgRWDCServerObjectDN = $null
							$orgRWDCServerObjectDN = $orgRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)

							$orgRWDCServerObjectObj = $null
							If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
								$orgRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN")
							}
							If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
								$orgRWDCServerObjectObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
							}
							$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObj.dnshostname[0]
						} Else {
							$metadataObjectAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
						}
						$metadataObjectAttribPwdLastSetOrgTime = $null
						$metadataObjectAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
						$metadataObjectAttribPwdLastSetVersion = $null
						$metadataObjectAttribPwdLastSetVersion = $metadataObjectAttribPwdLastSet.Version

						$okToReset = $null
						If ($expirationTimeForNMinusOneKerbTickets -lt [DateTime]::Now) {

							$okToReset = $True
						} Else {

							Logging "  --> According To RWDC.....................: '$targetedADdomainSourceRWDCFQDN'"
							Logging "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
							Logging "  --> Date/Time N-1 Kerberos Tickets........: '$(Get-Date $expirationTimeForNMinusOneKerbTickets -f 'yyyy-MM-dd HH:mm:ss')'"
							Logging "  --> Date/Time Now.........................: '$(Get-Date $([DateTime]::Now) -f 'yyyy-MM-dd HH:mm:ss')'"
							Logging "  --> Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
							Logging "  --> Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
							Logging "  --> Originating RWDC Previous Change......: '$metadataObjectAttribPwdLastSetOrgRWDCFQDN'"
							Logging "  --> Originating Time Previous Change......: '$metadataObjectAttribPwdLastSetOrgTime'"
							Logging "  --> Current Version Of Attribute Value....: '$metadataObjectAttribPwdLastSetVersion'"
							Logging ""
							Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR DOMAIN WIDE IMPACT'" "WARNING"
							Logging "" "WARNING"
							Logging "What do you want to do? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
							$continueOrStop = $null

							$continueOrStop = "continue"

							If ($continueOrStop.ToUpper() -ne "CONTINUE") {
								$continueOrStop = "STOP"
							}
							Logging ""
							If ($continueOrStop.ToUpper() -eq "CONTINUE") {

								$okToReset = $True
							} Else {

								$okToReset = $False
							}
							Logging "  --> Chosen: $continueOrStop" "REMARK"
							Logging ""
						}
						If ($okToReset) {

							setPasswordOfADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $remoteCredsUsed $adminCreds
						} Else {

							
							EXIT
						}
					} Else {

						Logging "  --> KrbTgt Account With sAMAccountName '$krbTgtSamAccountName' Does NOT Exist! Skipping..." "ERROR"
						Logging "" "ERROR"
					}
				}
			} Else {

			
				Logging ""
				Logging "The RWDC '$targetedADdomainSourceRWDCFQDN' to make the change on is not reachable/available..." "ERROR"
				Logging ""
			}

			If ($targetObjectToCheckDN) {

				$listOfDCsToCheckObjectOnStart = $null
				$listOfDCsToCheckObjectOnStart = ($tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read/Write"})

				$listOfDCsToCheckObjectOnEnd = @()

				$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time

				$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
				$listOfDCsToCheckObjectOnEndObj."Host Name" = $targetedADdomainSourceRWDCFQDN

				$listOfDCsToCheckObjectOnEndObj.PDC = $null
				$listOfDCsToCheckObjectOnEndObj.PDC = $targetedADdomainSourceRWDCIsPDC

				$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
				$listOfDCsToCheckObjectOnEndObj."Site Name" = $targetedADdomainSourceRWDCSiteName

				$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
				$listOfDCsToCheckObjectOnEndObj."DS Type" = $targetedADdomainSourceRWDCDSType

				$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
				$listOfDCsToCheckObjectOnEndObj."IP Address" = $targetedADdomainSourceRWDCIPAddress

				$listOfDCsToCheckObjectOnEndObj.Reachable = $null
				$listOfDCsToCheckObjectOnEndObj.Reachable = $targetedADdomainRWDCReachability

				$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
				$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainRWDCSourceRWDCFQDN

				$listOfDCsToCheckObjectOnEndObj.Time = $null
				$listOfDCsToCheckObjectOnEndObj.Time = $targetedADdomainRWDCTime

				$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj

				checkADReplicationConvergence $targetedADdomainFQDN $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $listOfDCsToCheckObjectOnStart $listOfDCsToCheckObjectOnEnd $modeOfOperationNr $localADforest $remoteCredsUsed $adminCreds
			}
		}

		If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {

			$collectionOfReachableRODCsToProcess = $null
			$collectionOfReachableRODCsToProcess = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown" -And $_."Source RWDC FQDN" -ne "RODC Unreachable" -And $targetRODCFQDNList -contains $_."Host Name"}

			$collectionOfUnReachableRODCsToProcess = $null
			$collectionOfUnReachableRODCsToProcess = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -eq "RODC Unreachable" -And $targetRODCFQDNList -contains $_."Host Name"}

			$collectionOfUnknownRODCsToProcess = $null
			$collectionOfUnknownRODCsToProcess = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -eq "Unknown" -And $targetRODCFQDNList -contains $_."Host Name"}
		}

		If ($targetKrbTgtAccountNr -eq 4) {

			$collectionOfReachableRODCsToProcess = $null
			$collectionOfReachableRODCsToProcess = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown" -And $_."Source RWDC FQDN" -ne "RODC Unreachable"}

			$collectionOfUnReachableRODCsToProcess = $null
			$collectionOfUnReachableRODCsToProcess = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -eq "RODC Unreachable"}

			$collectionOfUnknownRODCsToProcess = $null
			$collectionOfUnknownRODCsToProcess = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -eq "Unknown"}
		}

		If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3 -Or $targetKrbTgtAccountNr -eq 4) {

			If ($collectionOfReachableRODCsToProcess) {
				$collectionOfReachableRODCsToProcess | ForEach-Object{

					$rodcToProcess = $null
					$rodcToProcess = $_

					$krbTgtSamAccountName = $null
					$krbTgtSamAccountName = $rodcToProcess."Krb Tgt"

					$rodcFQDNTarget = $null
					$rodcFQDNTarget = $rodcToProcess."Host Name"

					$rodcSiteTarget = $null
					$rodcSiteTarget = $rodcToProcess."Site Name"

					$targetedADdomainSourceRWDCFQDN = $null
					$targetedADdomainSourceRWDCFQDN = $rodcToProcess."Source RWDC FQDN"

					$krbTgtObject = $null
					If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
						$krbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainSourceRWDCFQDN
					}
					If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
						$krbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCreds
					}

					$krbTgtObjectDN = $null
					$krbTgtObjectDN = $krbTgtObject.DistinguishedName
					Logging "+++++" "REMARK"
					Logging "+++ Processing KrbTgt Account....: '$krbTgtSamAccountName' | '$krbTgtObjectDN' +++" "REMARK"
					Logging "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" "REMARK"
					Logging "+++++" "REMARK"
					Logging "" "REMARK"

					$targetedADdomainSourceRWDCObj = $null
					If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
						$targetedADdomainSourceRWDCObj = Get-ADDomainController $targetedADdomainSourceRWDCFQDN -Server $targetedADdomainNearestRWDC
					}
					If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
						$targetedADdomainSourceRWDCObj = Get-ADDomainController $targetedADdomainSourceRWDCFQDN -Server $targetedADdomainNearestRWDC -Credential $adminCreds
					}

					$targetedADdomainSourceRWDCIsPDC = $null
					If ($targetedADdomainSourceRWDCFQDN -eq $targetedADdomainRWDCWithPDCFSMOFQDN) {
						$targetedADdomainSourceRWDCIsPDC = $True
					} Else {
						$targetedADdomainSourceRWDCIsPDC = $False
					}

					$targetedADdomainSourceRWDCSiteName = $null
					$targetedADdomainSourceRWDCSiteName = $targetedADdomainSourceRWDCObj.Site

					$targetedADdomainSourceRWDCDSType = "Read/Write"

					$targetedADdomainSourceRWDCIPAddress = $null
					$targetedADdomainSourceRWDCIPAddress = $targetedADdomainSourceRWDCObj.IPv4Address

					$targetedADdomainSourceRWDCReachability = $null
					$targetedADdomainSourceRWDCReachability = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}).Reachable

					$targetedADdomainSourceRWDCTime = 0.00

					$listOfDCsToCheckObjectOnStart = @()

					$listOfDCsToCheckObjectOnStart += $rodcToProcess

					$listOfDCsToCheckObjectOnStartObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN","Source RWDC DSA"

					$listOfDCsToCheckObjectOnStartObj."Host Name" = $null
					$listOfDCsToCheckObjectOnStartObj."Host Name" = $targetedADdomainSourceRWDCFQDN

					$listOfDCsToCheckObjectOnStartObj.PDC = $null
					$listOfDCsToCheckObjectOnStartObj.PDC = $targetedADdomainSourceRWDCIsPDC

					$listOfDCsToCheckObjectOnStartObj."Site Name" = $null
					$listOfDCsToCheckObjectOnStartObj."Site Name" = $targetedADdomainSourceRWDCSiteName

					$listOfDCsToCheckObjectOnStartObj."DS Type" = $null
					$listOfDCsToCheckObjectOnStartObj."DS Type" = $targetedADdomainSourceRWDCDSType

					$listOfDCsToCheckObjectOnStartObj."IP Address" = $null
					$listOfDCsToCheckObjectOnStartObj."IP Address" = $targetedADdomainSourceRWDCIPAddress

					$listOfDCsToCheckObjectOnStartObj.Reachable = $null
					$listOfDCsToCheckObjectOnStartObj.Reachable = $targetedADdomainSourceRWDCReachability

					$listOfDCsToCheckObjectOnStartObj."Source RWDC FQDN" = "N.A."
					$listOfDCsToCheckObjectOnStartObj."Source RWDC DSA" = "N.A."

					$listOfDCsToCheckObjectOnStart += $listOfDCsToCheckObjectOnStartObj

					$listOfDCsToCheckObjectOnStart = $listOfDCsToCheckObjectOnStart | Sort-Object -Property @{Expression = "DS Type"; Descending = $False}

					If ($targetedADdomainSourceRWDCReachability) {

						If ($modeOfOperationNr -eq 2) {

							$targetObjectToCheckDN = $null
							$targetObjectToCheckDN = createTempCanaryObject $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $execDateTimeCustom1 $localADforest $remoteCredsUsed $adminCreds
							If (!$targetObjectToCheckDN) {
								EXIT
							}
						}

						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {

							$targetObjectToCheck = $null
							If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
								$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainSourceRWDCFQDN
							}
							If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
								$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCreds
							}
							If ($targetObjectToCheck) {

								$targetObjectToCheckDN = $null
								$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName

								$targetObjectToCheckPwdLastSet = $null
								$targetObjectToCheckPwdLastSet = Get-Date $([datetime]::fromfiletime($targetObjectToCheck.pwdLastSet))

								$expirationTimeForNMinusOneKerbTickets = $null
								$expirationTimeForNMinusOneKerbTickets = (($targetObjectToCheckPwdLastSet.AddHours($targetedADdomainMaxTgtLifetimeHrs)).AddMinutes($targetedADdomainMaxClockSkewMins)).AddMinutes($targetedADdomainMaxClockSkewMins)

								$metadataObject = $null
								If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
									$metadataObject = Get-ADReplicationAttributeMetadata $targetObjectToCheckDN -Server $targetedADdomainSourceRWDCFQDN
								}
								If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
									$metadataObject = Get-ADReplicationAttributeMetadata $targetObjectToCheckDN -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCreds
								}
								$metadataObjectAttribPwdLastSet = $null
								$metadataObjectAttribPwdLastSet = $metadataObject | Where-Object{$_.AttributeName -eq "pwdLastSet"}
								$orgRWDCNTDSSettingsObjectDN = $null
								$orgRWDCNTDSSettingsObjectDN = $metadataObjectAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
								$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $null
								If ($orgRWDCNTDSSettingsObjectDN) {			

									$orgRWDCServerObjectDN = $null
									$orgRWDCServerObjectDN = $orgRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)

									$orgRWDCServerObjectObj = $null
									If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
										$orgRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainNearestRWDC/$orgRWDCServerObjectDN")
									}
									If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
										$orgRWDCServerObjectObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainNearestRWDC/$orgRWDCServerObjectDN"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
									}
									$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObj.dnshostname[0]
								} Else {
									$metadataObjectAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
								}
								$metadataObjectAttribPwdLastSetOrgTime = $null
								$metadataObjectAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
								$metadataObjectAttribPwdLastSetVersion = $null
								$metadataObjectAttribPwdLastSetVersion = $metadataObjectAttribPwdLastSet.Version

								$okToReset = $null
								If ($expirationTimeForNMinusOneKerbTickets -lt [DateTime]::Now) {

									$okToReset = $True
								} Else {

									Logging "  --> According To RWDC.....................: '$targetedADdomainSourceRWDCFQDN'"
									Logging "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
									Logging "  --> Date/Time N-1 Kerberos Tickets........: '$(Get-Date $expirationTimeForNMinusOneKerbTickets -f 'yyyy-MM-dd HH:mm:ss')'"
									Logging "  --> Date/Time Now.........................: '$(Get-Date $([DateTime]::Now) -f 'yyyy-MM-dd HH:mm:ss')'"
									Logging "  --> Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
									Logging "  --> Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
									Logging "  --> Originating RWDC Previous Change......: '$metadataObjectAttribPwdLastSetOrgRWDCFQDN'"
									Logging "  --> Originating Time Previous Change......: '$metadataObjectAttribPwdLastSetOrgTime'"
									Logging "  --> Current Version Of Attribute Value....: '$metadataObjectAttribPwdLastSetVersion'"
									Logging ""
									Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR IMPACT FOR RESOURCES SERVICED BY $rodcFQDNTarget' (Site: $rodcSiteTarget)" "WARNING"
									Logging "" "WARNING"
									Logging "What do you want to do? [CONTINUE | SKIP | STOP]: " "ACTION-NO-NEW-LINE"
									$continueOrStop = $null

									$continueOrStop = "continue"

									If ($continueOrStop.ToUpper() -ne "CONTINUE" -And $continueOrStop.ToUpper() -ne "SKIP" -And $continueOrStop.ToUpper() -ne "STOP") {
										$continueOrStop = "STOP"
									}
									Logging ""
									If ($continueOrStop.ToUpper() -eq "CONTINUE") {

										$okToReset = $True
									} Else {

										$okToReset = $False
									}
									Logging "  --> Chosen: $continueOrStop" "REMARK"
									Logging ""
								}
								If ($okToReset) {

									setPasswordOfADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $remoteCredsUsed $adminCreds
								} Else {

									If ($continueOrStop.ToUpper() -eq "SKIP") {

									} ElseIf ($continueOrStop.ToUpper() -eq "STOP") {
										EXIT
									} Else {
										EXIT
									}
								}
							} Else {

								Logging "  --> KrbTgt Account With sAMAccountName '$krbTgtSamAccountName' Does NOT Exist! Skipping..." "ERROR"
								Logging "" "ERROR"
							}
						}
					} Else {

						Logging ""
						Logging "The RWDC '$targetedADdomainSourceRWDCFQDN' to make the change on is not reachable/available..." "ERROR"
						Logging ""
					}

					If ($targetObjectToCheckDN) {

						If ($continueOrStop.ToUpper() -eq "CONTINUE") {

							$listOfDCsToCheckObjectOnEnd = @()

							$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time

							$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
							$listOfDCsToCheckObjectOnEndObj."Host Name" = $targetedADdomainSourceRWDCFQDN

							$listOfDCsToCheckObjectOnEndObj.PDC = $null
							$listOfDCsToCheckObjectOnEndObj.PDC = $targetedADdomainSourceRWDCIsPDC

							$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
							$listOfDCsToCheckObjectOnEndObj."Site Name" = $targetedADdomainSourceRWDCSiteName

							$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
							$listOfDCsToCheckObjectOnEndObj."DS Type" = $targetedADdomainSourceRWDCDSType

							$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
							$listOfDCsToCheckObjectOnEndObj."IP Address" = $targetedADdomainSourceRWDCIPAddress

							$listOfDCsToCheckObjectOnEndObj.Reachable = $null
							$listOfDCsToCheckObjectOnEndObj.Reachable = $targetedADdomainSourceRWDCReachability

							$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = "N.A."

							$listOfDCsToCheckObjectOnEndObj.Time = $null
							$listOfDCsToCheckObjectOnEndObj.Time = $targetedADdomainSourceRWDCTime

							$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj			

							checkADReplicationConvergence $targetedADdomainFQDN $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $listOfDCsToCheckObjectOnStart $listOfDCsToCheckObjectOnEnd $modeOfOperationNr $localADforest $remoteCredsUsed $adminCreds
						}
					}
				}
			} Else {

			}

			If ($collectionOfUnReachableRODCsToProcess) {
				$collectionOfUnReachableRODCsToProcess | ForEach-Object{

					$rodcToProcess = $null
					$rodcToProcess = $_

					$krbTgtSamAccountName = $null
					$krbTgtSamAccountName = $rodcToProcess."Krb Tgt"

					$rodcFQDNTarget = $null
					$rodcFQDNTarget = $rodcToProcess."Host Name"

					$rodcSiteTarget = $null
					$rodcSiteTarget = $rodcToProcess."Site Name"

					$targetedADdomainSourceRWDCFQDN = $null
					$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"

					$krbTgtDN = $null
					If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
						$krbTgtDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainSourceRWDCFQDN).DistinguishedName
					}
					If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
						$krbTgtDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCreds).DistinguishedName
					}
					Logging "+++++" "REMARK"
					Logging "+++ Processing KrbTgt Account....: '$krbTgtSamAccountName' | '$krbTgtDN' +++" "REMARK"
					Logging "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" "REMARK"
					Logging "+++++" "REMARK"
					Logging "" "REMARK"

					$targetedADdomainSourceRWDCIsPDC = $null
					$targetedADdomainSourceRWDCIsPDC = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True}).PDC

					$targetedADdomainSourceRWDCSiteName = $null
					$targetedADdomainSourceRWDCSiteName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Site Name"

					$targetedADdomainSourceRWDCDSType = $null
					$targetedADdomainSourceRWDCDSType = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."DS Type"

					$targetedADdomainSourceRWDCIPAddress = $null
					$targetedADdomainSourceRWDCIPAddress = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."IP Address"

					$targetedADdomainRWDCReachability = $null
					$targetedADdomainRWDCReachability = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True}).Reachable

					$targetedADdomainRWDCSourceRWDCFQDN = "N.A."

					$targetedADdomainRWDCTime = 0.00
					
					If ($targetedADdomainRWDCReachability) {

						If ($modeOfOperationNr -eq 2) {

							$targetObjectToCheckDN = $null
							$targetObjectToCheckDN = createTempCanaryObject $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $execDateTimeCustom1 $localADforest $remoteCredsUsed $adminCreds
							If (!$targetObjectToCheckDN) {
								EXIT
							}
						}

						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4) {

							$targetObjectToCheck = $null
							If ($localADforest -eq $true -Or ($remoteADforest -eq $true -And $remoteCredsUsed -eq $false)) {
								$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainSourceRWDCFQDN
							}
							If ($remoteADforest -eq $true -And $remoteCredsUsed -eq $true) {
								$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCreds
							}
							If ($targetObjectToCheck) {

								$targetObjectToCheckDN = $null
								$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName			

								$targetObjectToCheckPwdLastSet = $null
								$targetObjectToCheckPwdLastSet = Get-Date $([datetime]::fromfiletime($targetObjectToCheck.pwdLastSet))

								$expirationTimeForNMinusOneKerbTickets = $null
								$expirationTimeForNMinusOneKerbTickets = (($targetObjectToCheckPwdLastSet.AddHours($targetedADdomainMaxTgtLifetimeHrs)).AddMinutes($targetedADdomainMaxClockSkewMins)).AddMinutes($targetedADdomainMaxClockSkewMins)
								$okToReset = $null
								If ($expirationTimeForNMinusOneKerbTickets -lt [DateTime]::Now) {

									$okToReset = $True
								} Else {

									Logging "  --> According To RWDC.....................: '$targetedADdomainSourceRWDCFQDN'"
									Logging "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
									Logging "  --> Date/Time N-1 Kerberos Tickets........: '$(Get-Date $expirationTimeForNMinusOneKerbTickets -f 'yyyy-MM-dd HH:mm:ss')'"
									Logging "  --> Date/Time Now.........................: '$(Get-Date $([DateTime]::Now) -f 'yyyy-MM-dd HH:mm:ss')'"
									Logging "  --> Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
									Logging "  --> Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
									Logging ""
									Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR IMPACT FOR RESOURCES SERVICED BY $rodcFQDNTarget' (Site: $rodcSiteTarget)" "WARNING"
									Logging "" "WARNING"
									Logging "What do you want to do? [CONTINUE | SKIP | STOP]: " "ACTION-NO-NEW-LINE"
									$continueOrStop = $null

									$continueOrStop = "continue"

									If ($continueOrStop.ToUpper() -ne "CONTINUE" -And $continueOrStop.ToUpper() -ne "SKIP" -And $continueOrStop.ToUpper() -ne "STOP") {
										$continueOrStop = "STOP"
									}
									Logging ""
									If ($continueOrStop.ToUpper() -eq "CONTINUE") {

										$okToReset = $True
									} Else {

										$okToReset = $False
									}
									Logging "  --> Chosen: $continueOrStop" "REMARK"
									Logging ""
								}
								If ($okToReset) {

									setPasswordOfADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $remoteCredsUsed $adminCreds
								} Else {

									If ($continueOrStop.ToUpper() -eq "SKIP") {

									} ElseIf ($continueOrStop.ToUpper() -eq "STOP") {
										EXIT
									} Else {
										EXIT
									}
								}
							} Else {

								Logging "  --> KrbTgt Account With sAMAccountName '$krbTgtSamAccountName' Does NOT Exist! Skipping..." "ERROR"
								Logging "" "ERROR"
							}
						}
					} Else {

						Logging ""
						Logging "The RWDC '$targetedADdomainSourceRWDCFQDN' to make the change on is not reachable/available..." "ERROR"
						Logging ""
					}

					If ($continueOrStop.ToUpper() -eq "CONTINUE") {
						$listOfDCsToCheckObjectOnStart = ($tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read/Write"})

						$listOfDCsToCheckObjectOnEnd = @()

						$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time

						$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
						$listOfDCsToCheckObjectOnEndObj."Host Name" = $targetedADdomainSourceRWDCFQDN

						$listOfDCsToCheckObjectOnEndObj.PDC = $null
						$listOfDCsToCheckObjectOnEndObj.PDC = $targetedADdomainSourceRWDCIsPDC

						$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
						$listOfDCsToCheckObjectOnEndObj."Site Name" = $targetedADdomainSourceRWDCSiteName

						$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
						$listOfDCsToCheckObjectOnEndObj."DS Type" = $targetedADdomainSourceRWDCDSType

						$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
						$listOfDCsToCheckObjectOnEndObj."IP Address" = $targetedADdomainSourceRWDCIPAddress

						$listOfDCsToCheckObjectOnEndObj.Reachable = $null
						$listOfDCsToCheckObjectOnEndObj.Reachable = $targetedADdomainRWDCReachability

						$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
						$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainRWDCSourceRWDCFQDN

						$listOfDCsToCheckObjectOnEndObj.Time = $targetedADdomainRWDCTime

						$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj

						checkADReplicationConvergence $targetedADdomainFQDN $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $listOfDCsToCheckObjectOnStart $listOfDCsToCheckObjectOnEnd $modeOfOperationNr $localADforest $remoteCredsUsed $adminCreds
					}
				}		
			} Else {

			}

			If ($collectionOfUnknownRODCsToProcess) {
				Logging "+++++" "REMARK"
				Logging "+++ The Following Look Like RODCs, But May Not Be Real RODCs..." "REMARK"
				Logging "+++++" "REMARK"
				Logging "" "REMARK"

				$collectionOfUnknownRODCsToProcess | ForEach-Object{
					$rodcToProcess = $null
					$rodcToProcess = $_
					Logging "$($rodcToProcess | Format-Table * | Out-String)"
					Logging ""
				}
				Logging ""
			} Else {

			}
		}
	}

	If ($modeOfOperationNr -eq 8) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "CREATE TEST KRBTGT ACCOUNTS (MODE 8)..." "HEADER"
		Logging ""

		Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
		$continueOrStop = $null

		$continueOrStop = "continue"

		If ($continueOrStop.ToUpper() -ne "CONTINUE") {
			$continueOrStop = "STOP"
		}
		Logging ""
		Logging "  --> Chosen: $continueOrStop" "REMARK"
		Logging ""

		If ($continueOrStop.ToUpper() -ne "CONTINUE") {
			EXIT
		}	

		$targetedADdomainSourceRWDCFQDN = $null
		$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"

		$krbTgtSamAccountName = $null
		$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Krb Tgt"
		Logging "+++++" "REMARK"
		Logging "+++ Create Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
		Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
		Logging "+++++" "REMARK"
		Logging "" "REMARK"

		createTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName "RWDC" $targetedADdomainDomainSID $localADforest $remoteCredsUsed $adminCreds

		$tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown"} | ForEach-Object{

			$rodcToProcess = $null
			$rodcToProcess = $_

			$krbTgtSamAccountName = $null
			$krbTgtSamAccountName = $rodcToProcess."Krb Tgt"

			$rodcFQDNTarget = $null
			$rodcFQDNTarget = $rodcToProcess."Host Name"

			$rodcSiteTarget = $null
			$rodcSiteTarget = $rodcToProcess."Site Name"
			Logging "+++++" "REMARK"
			Logging "+++ Create Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
			Logging "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" "REMARK"
			Logging "+++++" "REMARK"
			Logging "" "REMARK"

			createTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName "RODC" $targetedADdomainDomainSID $localADforest $remoteCredsUsed $adminCreds
		}
	}

	If ($modeOfOperationNr -eq 9) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "CLEANUP TEST KRBTGT ACCOUNTS (MODE 9)..." "HEADER"
		Logging ""

		Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
		$continueOrStop = $null

		$continueOrStop = "continue"

		If ($continueOrStop.ToUpper() -ne "CONTINUE") {
			$continueOrStop = "STOP"
		}
		Logging ""
		Logging "  --> Chosen: $continueOrStop" "REMARK"
		Logging ""

		If ($continueOrStop.ToUpper() -ne "CONTINUE") {
			EXIT
		}	

		$targetedADdomainSourceRWDCFQDN = $null
		$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"

		$krbTgtSamAccountName = $null
		$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Krb Tgt"
		Logging "+++++" "REMARK"
		Logging "+++ Delete Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
		Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
		Logging "+++++" "REMARK"
		Logging "" "REMARK"

		deleteTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $remoteCredsUsed $adminCreds

		$tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown"} | ForEach-Object{

			$rodcToProcess = $null
			$rodcToProcess = $_

			$krbTgtSamAccountName = $null
			$krbTgtSamAccountName = $rodcToProcess."Krb Tgt"

			$rodcFQDNTarget = $null
			$rodcFQDNTarget = $rodcToProcess."Host Name"

			$rodcSiteTarget = $null
			$rodcSiteTarget = $rodcToProcess."Site Name"
			Logging "+++++" "REMARK"
			Logging "+++ Delete Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
			Logging "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" "REMARK"
			Logging "+++++" "REMARK"
			Logging "" "REMARK"

			deleteTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $remoteCredsUsed $adminCreds
		}
	}

	Logging ""
	Logging ""
	Logging "Log File Path...: $logFilePath" "REMARK"

}

#Getting Paramaters from Input (Hack)
function verifyAndAssign([ref]$param, [string]$value){
	if (![string]::IsNullOrEmpty($value) -and $argNames -notcontains $value.ToLower()) {
        if($value -ne "`$[1]`$USERNAME" -and $value -ne "`$[1]`$PASSWORD"){
		    $param.Value = $value
        }
	}
}

#Setting Defaults 
[string]$AccountScope = 1 #"Scope of KrbTgt in use by all RWDCs in the AD Domain"
[string]$RunOption = 4 #"Real KRBTGT Password Change"

[string]$InvokeMachine = $null
[string]$TargetAdForest = $null
[string]$TargetAdDomain = $null
[string]$DCAccountList = $null
[string]$Username = $null
[string]$Password = $null
[string]$LogPath = $null

$argNames = '-invokemachine', '-targetAdforest', '-targetaddomain', '-accountscope', '-dcaccountlist', '-username', '-password', '-runoption', '-logpath'

for ($i = 0; $i -lt $args.Count - 1; $i++) 
{
	if($args[$i] -is [string] -and $args.Count -ne ($i + 1)){
		switch ($args[$i].ToLower())
		{
			'-invokemachine' {
				verifyAndAssign -param ([ref]$InvokeMachine) -value ([string]$args[$i + 1])
			}
			'-targetadforest' {   
				verifyAndAssign -param ([ref]$TargetAdForest) -value ([string]$args[$i + 1])
			}
			'-targetaddomain' {
				verifyAndAssign -param ([ref]$TargetAdDomain) -value ([string]$args[$i + 1])
			}
			'-accountscope' {
				verifyAndAssign -param ([ref]$AccountScope) -value ([string]$args[$i + 1])
			}
			'-dcaccountlist' {
				verifyAndAssign -param ([ref]$DCAccountList) -value ([string]$args[$i + 1])
			}
			'-username' {
				verifyAndAssign -param ([ref]$Username) -value ([string]$args[$i + 1])
			}
			'-password' {
				verifyAndAssign -param ([ref]$Password) -value ([string]$args[$i + 1])
			}
			'-runoption' {
				verifyAndAssign -param ([ref]$RunOption) -value ([string]$args[$i + 1])
			}
			'-logpath' {
				verifyAndAssign -param ([ref]$LogPath) -value ([string]$args[$i + 1])
			}
		}
	}
}

#Checking if Script is being ran with accociated secret to use as credentials to invoke command into domain controller. 
if([string]::IsNullOrEmpty($Username) -or [string]::IsNullOrEmpty($Password))
{
    $creds = $null
}
else{
	$securePassword = ConvertTo-SecureString $Password -AsPlainText -Force	
	$creds = New-Object System.Management.Automation.PSCredential ($Username, $securePassword)
}

$hasCreds = $null -ne $creds
$hasInvokeMachine =  $null -ne $InvokeMachine

if(!$hasCreds -and !$hasInvokeMachine)
{
	Invoke-Command -ScriptBlock ${function:RunGoldenTicketScript} -argumentlist  ($TargetAdForest, $TargetAdDomain, $AccountScope, $DCAccountList, $RunOption, $LogPath)
}
elseif($hasCreds -and !$hasInvokeMachine)
{
	Invoke-Command -Credential $creds -ScriptBlock ${function:RunGoldenTicketScript} -argumentlist  ($TargetAdForest, $TargetAdDomain, $AccountScope, $DCAccountList, $RunOption, $LogPath)
}
elseif(!$hasCreds -and $hasInvokeMachine){
	Invoke-Command -ComputerName $InvokeMachine -ScriptBlock ${function:RunGoldenTicketScript} -argumentlist ($TargetAdForest, $TargetAdDomain, $AccountScope, $DCAccountList, $RunOption, $LogPath)
}
else{
    Invoke-Command -Credential $creds -ComputerName $InvokeMachine -ScriptBlock ${function:RunGoldenTicketScript} -argumentlist ($TargetAdForest, $TargetAdDomain, $AccountScope, $DCAccountList, $RunOption, $LogPath)
}