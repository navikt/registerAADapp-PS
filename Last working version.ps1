#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\MSOnline\1.1.183.8\MSOnline.psd1" -Global;
Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureADPreview\2.0.1.18\AzureADPreview.psd1" -Global;
Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.Profile\4.6.0\AzureRM.Profile.psd1" -Global;
Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.KeyVault\4.3.0\AzureRM.KeyVault.psd1" -Global;
Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.Resources\5.5.2\AzureRM.Resources.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureAD\2.0.1.16\AzureAD.psd1" -Global;
#Import-Module AzureADPreview
#. .\createKey.ps1
. "D:\home\site\wwwroot\registerApp-PS\createKey.ps1"
#. ..\config.ps1

$tenantid = $ENV:APPSETTING_tenantid
$applicationId = $ENV:APPSETTING_applicationId
$appSecret = $ENV:APPSETTING_appSecret
$appSecretToken = $ENV:APPSETTING_appSecretToken
$tokenAuthURI = $ENV:APPSETTING_tokenAuthURI
$certThumbprint = $ENV:APPSETTING_certThumbprint
$secretWebhook = $ENV:APPSETTING_secretWebhook

# POST method: $req
$requestBody = Get-Content $req -Raw | ConvertFrom-Json

$securePassword = $appSecret | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $applicationId, $securePassword
$applicationName = $requestbody.applicationName
$vaultname = "azureSelfServiceKeys"
$domainname = "nav.no"
$ApplicationURI = $("https://$DomainName/$($applicationName -Replace('[\W]',''))")
$logoutURI = "https://login.microsoftonline.com/common/oauth2/logout"



$replyurls = $($requestbody.replyURLs).replace(" ",",")
$owners = $($requestbody.owners).replace(" ",",")


# kobler til azure ad med sertifikat som credentials
Connect-AzureAD -ApplicationId $applicationId -CertificateThumbprint $certThumbprint -TenantId $tenantid

# sjekker om applikasjon med samme navn finnes fra før.
$appExist = Get-AzureADApplication -filter "DisplayName eq '$applicationname'"

# om appen ikke finnes, registrer med alle parametere
if (!($appExist)) {
    $GroupMembershipClaims = "SecurityGroup"
    $ClaimsPolicy = "c7880a6d-ab30-4fba-be66-4c41d7e6f22f" #53eccc94-e7d4-4c1b-9d25-62baefaab0df = preprod. c7880a6d-ab30-4fba-be66-4c41d7e6f22f = prod

    # kobler til azure resource manager
    Connect-AzureRmAccount -ServicePrincipal -Credential $credential -TenantId $tenantid -Subscription "e9589aaa-5d01-4d93-a252-9cc27f620f44"

    $requestBodyAD = "grant_type=client_credentials" +
        "&client_id=$applicationId" +
        "&client_secret=$appSecretToken" +
        "&resource=https://graph.windows.net"

    $tokenResponseAD = Invoke-RestMethod -Method Post -Uri $tokenAuthURI -body $requestBodyAD -ContentType "application/x-www-form-urlencoded" # Kontakt Microsoft Graph via Rest for å hente token
    $accessTokenAD = $tokenResponseAD.access_token


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
    $app = New-AzureADApplication -IdentifierUris $ApplicationURI -DisplayName $ApplicationName -GroupMembershipClaims $GroupMembershipClaims -homepage $ApplicationURI -logoutUrl $logoutURI -PasswordCredentials $aadSecret -ReplyUrls $replyurls -RequiredResourceAccess $reqGraph
    $resServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $app.appID
    

    # oppretter ny keyvault
    $keyvaultname = $($applicationName -Replace('[\W]',''))+ "Prod"
    $keyvault = New-AzureRmKeyVault -name $keyvaultname -ResourceGroupName AzureSelfServiceKeyVault -Location "North Europe"
    Set-AzureRmKeyVaultAccessPolicy -VaultName $keyvaultname -PermissionsToSecrets set -ServicePrincipalName $ApplicationId

    # skriver app secret til Azure keyvault
    $vaultSecret = Set-AzureKeyVaultSecret -VaultName $keyvaultname -name $keyvaultname -SecretValue $secret
    
    
  
    
    # add owners + andre parametere
    foreach ($owner in $owners)
    {
        $aduser = Get-AzureADUser -objectId $owner
        Add-AzureADApplicationOwner -objectid $app.ObjectId -RefObjectId $aduser.ObjectId
        # Set keyvault read permission
        Set-AzureRmKeyVaultAccessPolicy -VaultName $keyvaultname -PermissionsToSecrets get,list -UserPrincipalName $owner
    }
    
    
    
    
    
    $teamsbody = ConvertTo-Json -Depth 4 @{
        title = "Ny applikasjon er registrert i Q"
        text = "ny Applikasjon er registrert i AzureAD Q, for å assigne riktig policy må følgende powershell kommando kjøres som GlobalAdmin: "
        sections = @(
            @{
                activityTitle = 'Powershell kommando'
                activityText = "Add-AzureADServicePrincipalPolicy -Id $($resServicePrincipal.Id) -RefObjectId $ClaimsPolicy"
            }
            @{
                title = 'Detaljer'
                facts = @{
                    name = 'Applikasjonsnavn'
                    value = $applicationname
                },
                @{
                    name = "Eiere"
                    value = $owners
                },
                @{
                    name = "Applikasjons URI"
                    value = $ApplicationURI
                }
    
            }
        )
    }
    
    
    Invoke-RestMethod -uri $secretWebhook -Method Post -Body $teamsbody -ContentType 'application/json'
    
    
# oppdaterer app med acceptmappedclaims = true
$requestbodyAD =
@"
{
    "acceptMappedClaims": true
}
"@

$updateApp = Invoke-RestMethod -Method Patch -Uri "https://graph.windows.net/$tenantid/applications/$($app.objectid)?api-version=1.6" -Headers @{"Authorization"="Bearer $accessTokenAD"} -body $requestBodyAD -ContentType "application/json"

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

$content="<html>\r\n<head>\r\n<meta http-equiv=\'Content-Type\' content=\'text/html; charset=utf-8\'>\r\n<meta content=\'text/html; charset=us-ascii\'>\r\n</head>\r\n<body>\r\n<b>Opprettelsen av Azure AD applikasjonen $applicationName er ferdig</b></br></br>appID/ClientID: $($app.appID)</br>ClientSecret: https://portal.azure.com/#@nav.no/asset/Microsoft_Azure_KeyVault/Secret/$($vaultSecret.id)</br>objectID: $($app.ObjectId)</br></br> Mvh</br>NAIS\r\n</body>\r\n</html>\r\n"

foreach ($owner in $owners) {
#Write-Output $owner
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
    #Send-MailMessage -from no-reply@nav.no -to $owner -subject "Applikasjonsbestillingen er ferdig utført" -SmtpServer smtp.office365.com -port 587 -usessl -Credential $credential
    $mailURI = "https://graph.microsoft.com/v1.0/users/kn@navno.onmicrosoft.com/sendMail"
    Invoke-RestMethod -Method Post -Uri $mailURI -Headers @{"Authorization"="Bearer $accessTokenGraph"} -ContentType application/json -Body $emailbody

}


$output
Out-File -Encoding Ascii -FilePath $res -inputObject $output
}


# Om appen finnes fra før, kun oppdater owners og replyurls
else {

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
    #Write-output $appownerComp

    $ownerComp = @()
    foreach ($owner in $owners)
    {
        $ownerComp += $owner
    }
    #write-output $ownerComp

    $addowner = Compare-Object -ReferenceObject $appownerComp -DifferenceObject $ownerComp | where sideindicator -eq "=>"
    $removeOwner = Compare-Object -ReferenceObject $appownerComp -DifferenceObject $ownerComp | where sideindicator -eq "<="

    # Legger til nye eiere i konfigfil
    foreach ($owner in $addowner)
    {
        $aduser = Get-AzureADUser -filter "UserPrincipalName eq '$($owner.inputObject)'"
        Add-AzureADApplicationOwner -objectid $appExist.ObjectId -RefObjectId $aduser.ObjectId
    }

    # fjerner eiere som er tatt vekk i konfigfil
    foreach ($owner in $removeOwner) {
        Write-Output $owner.inputObject
        $aduser = Get-AzureADUser -filter "UserPrincipalName eq '$($owner.inputObject)'"
        Remove-AzureADApplicationOwner -objectid $appExist.ObjectId -OwnerId $aduser.ObjectId
    }
    #Write-Output $addowner
    #Write-Output $removeOwner

    # leser ut nye eiere fra app
    $newowners = Get-AzureADApplicationOwner -ObjectId $appExist.ObjectId

    # skriver respons
    $output = ConvertTo-Json @{
        applicationName = $appExist.DisplayName
        appExist = $true
        ReplyURLupdate = $replyurls
        ownersUpdate = $newowners.UserPrincipalName
    }
    
    $output
    Out-File -Encoding Ascii -FilePath $res -inputObject $output
}
