#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\MSOnline\1.1.183.8\MSOnline.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureADPreview\2.0.1.18\AzureADPreview.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.Profile\4.6.0\AzureRM.Profile.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.KeyVault\4.3.0\AzureRM.KeyVault.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.Resources\5.5.2\AzureRM.Resources.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureAD\2.0.1.16\AzureAD.psd1" -Global;

#. "D:\home\site\wwwroot\registerApp-PS\createKey.ps1"
#. ..\config.ps1


if ($ENV:environment -like "local") {
    Import-Module AzureADPreview
    . .\registerApp-PS\createKey.ps1
    $requestbody = Get-Content -Raw .\registerApp-PS\input.example.json | ConvertFrom-Json

} else {
    . "D:\home\site\wwwroot\registerApp-PS\createKey.ps1"
    Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureADPreview\2.0.1.18\AzureADPreview.psd1" -Global;
    Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.Profile\4.6.0\AzureRM.Profile.psd1" -Global;
    Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.KeyVault\4.3.0\AzureRM.KeyVault.psd1" -Global;
    Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.Resources\5.5.2\AzureRM.Resources.psd1" -Global;

    # POST method: $req
    $requestBody = Get-Content $req -Raw | ConvertFrom-Json

}

$tenantid = $ENV:APPSETTING_tenantid
$applicationId = $ENV:APPSETTING_applicationId
$appSecret = $ENV:APPSETTING_appSecret
$appSecretToken = $ENV:APPSETTING_appSecretToken
$tokenAuthURI = $ENV:APPSETTING_tokenAuthURI
$certThumbprint = $ENV:APPSETTING_certThumbprint
$secretWebhook = $ENV:APPSETTING_secretWebhook
$claimswebhook =  $ENV:APPSETTING_runbookUrl
$domainname = $ENV:APPSETTING_domainname
$subscriptionId = $ENV:APPSETTING_subscriptionId

$vaultname = "azureSelfServiceKeys"
$securePassword = $appSecret | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $applicationId, $securePassword
$applicationName = $requestbody.applicationName
$ApplicationURI = $("https://$DomainName/$($applicationName -Replace('[\W]',''))")
#$logoutURI = "https://login.microsoftonline.com/common/oauth2/logout"

$replyurls = $($requestbody.replyURLs).replace(" ",",")
$owners = $($requestbody.owners).replace(" ",",")

if ($ENV:APPSETTING_domainname -like "trygdeetaten.no") {
    $keyvaultname = $($applicationName -Replace('[\W]','')) + "Q"
    $ClaimsPolicy = "53eccc94-e7d4-4c1b-9d25-62baefaab0df" #53eccc94-e7d4-4c1b-9d25-62baefaab0df = preprod. c7880a6d-ab30-4fba-be66-4c41d7e6f22f = prod
}else {
    $keyvaultname = $($applicationName -Replace('[\W]','')) + "Prod"
    $ClaimsPolicy = "c7880a6d-ab30-4fba-be66-4c41d7e6f22f" #53eccc94-e7d4-4c1b-9d25-62baefaab0df = preprod. c7880a6d-ab30-4fba-be66-4c41d7e6f22f = prod
}




# kobler til azure ad med sertifikat som credentials
try {
    write-output "Connecting to Azure AD"
    Connect-AzureAD -TenantId  $tenantid -ApplicationId $applicationId -CertificateThumbprint $certThumbprint -ErrorAction Stop
} catch {
    write-error "Connect to Azure AD failed: $($_.Exeption.Message)"
    exit 1
}

# sjekker om applikasjon med samme navn finnes fra før.
try {
    write-output "check if application already exist"
    $appExist = Get-AzureADApplication -filter "DisplayName eq '$applicationname'" -ErrorAction stop
} catch {
    write-error "Could not find application with name: $applicationname  error:  $($_.Exception.Message)"
    exit 2
 }


# om appen ikke finnes, registrer med alle parametere
if (!($appExist)) {
    $GroupMembershipClaims = "SecurityGroup"
   
    # kobler til azure resource manager
    try {
        write-output "Connecting to Azure RM"
        Connect-AzureRmAccount -ServicePrincipal -Credential $credential -TenantId $tenantid -Subscription $subscriptionId -ErrorAction stop #preprod = "2f230ac3-94ea-48b6-93b9-8b1fc97add0a", prod="e9589aaa-5d01-4d93-a252-9cc27f620f44" 
    } catch {
        write-error "Could not connect to AzureRM: $($_.Exception.Message)"
        exit 4
    }

    try {
        $requestBodyAD = "grant_type=client_credentials" +
            "&client_id=$applicationId" +
            "&client_secret=$appSecretToken" +
            "&resource=https://graph.windows.net"

        $tokenResponseAD = Invoke-RestMethod -Method Post -Uri $tokenAuthURI -body $requestBodyAD -ContentType "application/x-www-form-urlencoded" # Kontakt Microsoft Graph via Rest for å hente token
        $accessTokenAD = $tokenResponseAD.access_token
    } catch {
        write-error "Unable to get token for grap.windows.net: $($_.Exception.Message)"
        exit 4
    }

    # create app secret
    $key = Create-AesKey
    $startdate = Get-Date
    $aadSecret = @{
        'startDate'=$startdate
        'endDate'=$startdate.AddYears(2)
        'keyId'=$(New-Guid);
        'value'=$Key
    }
    $secret = ConvertTo-SecureString -string $key -AsPlainText -Force

    ## setter riktige tilganger for appen
    $reqGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $reqGraph.ResourceAppId = "00000002-0000-0000-c000-000000000000"  # = windows azure active directory
    $appPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "311a71cc-e848-46a1-bdf8-97ff7156d8e6","Scope"  # = User.read, delegated permission
    $reqGraph.ResourceAccess = $appPermission1
    
    #regsiter application
    try {
        Write-Output "Registering the application"
        $app = New-AzureADApplication -IdentifierUris $ApplicationURI -DisplayName $ApplicationName -GroupMembershipClaims $GroupMembershipClaims -homepage $ApplicationURI -PasswordCredentials $aadSecret -ReplyUrls $replyurls -RequiredResourceAccess $reqGraph -ErrorAction stop
        $resServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $app.appID
    } catch {
        write-error "could not register application with name: $applicationname  error: $($_.Exception.Message)"
        exit 5
    }



    # oppretter ny keyvault
    try {
        Write-Output "createing new keyvault for the application"
        $keyvault = New-AzureRmKeyVault -name $keyvaultname -ResourceGroupName AzureSelfServiceKeyVault -Location "North Europe"
        Set-AzureRmKeyVaultAccessPolicy -VaultName $keyvaultname -PermissionsToSecrets set -ServicePrincipalName $ApplicationId -ErrorAction stop

        # skriver app secret til Azure keyvault
        $vaultSecret = Set-AzureKeyVaultSecret -VaultName $keyvaultname -name $keyvaultname -SecretValue $secret -ErrorAction stop
    } catch {
        write-error "Unable to create or write to keyvault: $($_.Exception.Message)"
        exit 6
    }
  
    
    # add owners + andre parametere
    foreach ($owner in $owners)
    {
        $AddOwnerError = $null
        DO 
        {   
            Write-Output "adding $owner as owner to the application. errorcount: $($addownererror.count)"
            if (!([string]::IsNullOrEmpty($AddOwnerError))) {start-sleep 5}
            $aduser = Get-AzureADUser -objectId $owner
            Add-AzureADApplicationOwner -objectid $app.ObjectId -RefObjectId $aduser.ObjectId -ErrorVariable +AddOwnerError
            # Set keyvault read permission
            Set-AzureRmKeyVaultAccessPolicy -VaultName $keyvaultname -PermissionsToSecrets get,list -UserPrincipalName $owner -ErrorVariable +AddOwnerError
            
        } Until ([string]::IsNullOrEmpty($AddOwnerError) -or $AddOwnerError.count -eq "5" )
        if ($AddOwnerError -eq "5") {
            write-warning "could not add owner to application after 5 retries: "
        }
    }
    
 
    
# oppdaterer app med acceptmappedclaims = true
$requestbodyAD =
@"
{
    "acceptMappedClaims": true
}
"@
try {
    $updateApp = Invoke-RestMethod -Method Patch -Uri "https://graph.windows.net/$tenantid/applications/$($app.objectid)?api-version=1.6" -Headers @{"Authorization"="Bearer $accessTokenAD"} -body $requestBodyAD -ContentType "application/json" -ErrorAction stop
} catch {
    write-warning "could not update group to SecurityEnabled group: $($_.Exception.Message)"
    exit 7
}

# Knytter til NAVident Claims Policy
$claimsbody = @{
    'applicationname' = $applicationName
    'claimspolicy' = $ClaimsPolicy
    'env' = $domainname
   }

$claimsbodyJSON = ConvertTo-Json $claimsbody
Write-Output "adding NAVident ClaimsPolicy to the new application"
$addcustomclaims = Invoke-RestMethod -uri $claimswebhook -Method POST -body $claimsbodyJSON -ContentType "application/json"



# setter respons
$output = ConvertTo-Json @{
    applicationName = $ApplicationName
    applicationObjectID = $app.ObjectId
    applicationAppID = $app.appID
    clientSecret = $vaultSecret.id
}

# accesstoken for å sende epost
$requestBodyGraph = "grant_type=client_credentials" +
"&client_id=$applicationId" +
"&client_secret=$appSecretToken" +
"&resource=https://graph.microsoft.com"

$tokenResponseGraph = Invoke-RestMethod -Method Post -Uri $tokenAuthURI -body $requestBodyGraph -ContentType "application/x-www-form-urlencoded" # Kontakt Microsoft Graph via Rest for å hente token
$accessTokenGraph = $tokenResponseGraph.access_token

# Sender mail til bruker med info om applikasjonen

$content="<html>\r\n<head>\r\n<meta http-equiv=\'Content-Type\' content=\'text/html; charset=utf-8\'>\r\n<meta content=\'text/html; charset=us-ascii\'>\r\n</head>\r\n<body>\r\n<b>Opprettelsen av Azure AD applikasjonen $applicationName er ferdig</b></br></br>appID/ClientID: $($app.appID)</br>ClientSecret: https://portal.azure.com/#@$domainname/asset/Microsoft_Azure_KeyVault/Secret/$($vaultSecret.id)</br>objectID: $($app.ObjectId)</br></br> Mvh</br>NAIS\r\n</body>\r\n</html>\r\n"

foreach ($owner in $owners) {
    $failedmail = $null
    $emailbody = @"
        {
        "message" : {
            "subject": "ny Azure AD applikasjon er ferdig opprettet",
            "body" : {
                "contentType": "HTML",
                "content": "$content"
                },
            "toRecipients": [
            {
            "emailAddress" : {
                "address" : "$owner"
                }
                }
            ]
        }
        }
"@

   
    write-output "sending info mail to $owner"
    $mailURI = "https://graph.microsoft.com/v1.0/users/$owner/sendMail"
    Invoke-RestMethod -Method Post -Uri $mailURI -Headers @{"Authorization"="Bearer $accessTokenGraph"} -ContentType application/json -Body $emailbody -ErrorVariable failedmail
    
    if ($failedmail) {
        Write-warning "sending mail to $owner failed"
    }
}


$output
#Out-File -Encoding Ascii -FilePath $res -inputObject $output
}


# Om appen finnes fra før, kun oppdater owners og replyurls
else {
    $error = $null
    $appreplyurls = (Get-AzureADApplication -ObjectId $appExist.objectid).replyurls

    $compReplyurls = Compare-Object -ReferenceObject $appreplyurls -DifferenceObject $replyurls

    if ($compReplyurls) {
        $addReplyurl = Set-AzureADApplication -ObjectId $appExist.ObjectId -ReplyUrls $replyurls
    }


    
    # henter eksisterende eiere på app og sammenligner med eiere angitt i konfigfil
    $appowners = Get-AzureADApplicationOwner -ObjectId $appExist.ObjectId
    $appownerComp = @()
    foreach ($appowner in $appowners)
    {
        $appownerComp += $appowner.UserPrincipalName
    }
    Write-output $appownerComp

    $ownerComp = @()
    foreach ($owner in $owners)
    {
        $ownerComp += $owner
    }
    write-output $ownerComp

    $addowner = Compare-Object -ReferenceObject $appownerComp -DifferenceObject $ownerComp | where sideindicator -eq "=>"
    $removeOwner = Compare-Object -ReferenceObject $appownerComp -DifferenceObject $ownerComp | where sideindicator -eq "<="

    # Legger til nye eiere i konfigfila
    foreach ($owner in $addowner)
    {
        $aduser = Get-AzureADUser -filter "UserPrincipalName eq '$($owner.inputObject)'"
        Add-AzureADApplicationOwner -objectid $appExist.ObjectId -RefObjectId $aduser.ObjectId
    }

    # fjerner eiere som er tatt vekk i konfigfila
    foreach ($owner in $removeOwner) {
        Write-Output $owner.inputObject
        $aduser = Get-AzureADUser -filter "UserPrincipalName eq '$($owner.inputObject)'"
        Remove-AzureADApplicationOwner -objectid $appExist.ObjectId -OwnerId $aduser.ObjectId
    }
    Write-Output $addowner
    Write-Output $removeOwner

    # leser ut nye eiere fra app
    $newowners = Get-AzureADApplicationOwner -ObjectId $appExist.ObjectId

    # skriver respons
    $output = ConvertTo-Json @{
        applicationName = $appExist.DisplayName
        appExist = $true
        ReplyURLupdate = $replyurls
        ownersUpdate = $newowners.UserPrincipalName
        error = $Error
    }
    
    $output
 #   Out-File -Encoding Ascii -FilePath $res -inputObject $output
}
