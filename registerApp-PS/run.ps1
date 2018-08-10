#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\MSOnline\1.1.183.8\MSOnline.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureADPreview\2.0.1.18\AzureADPreview.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.Profile\4.6.0\AzureRM.Profile.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.KeyVault\4.3.0\AzureRM.KeyVault.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\registerApp-PS\additionalmodules\AzureRM.Resources\5.5.2\AzureRM.Resources.psd1" -Global;
Import-Module AzureADPreview
. .\createKey.ps1
#. "D:\home\site\wwwroot\registerApp-PS\createKey.ps1"
. ..\config.ps1

#$tenantid = $ENV:APPSETTING_tenantid
#$applicationId = $ENV:APPSETTING_applicationId
#$appSecret = $ENV:APPSETTING_appSecret
#$appSecretToken = $ENV:APPSETTING_appSecretToken
#$tokenAuthURI = $ENV:APPSETTING_tokenAuthURI
#$certThumbprint = $ENV:APPSETTING_certThumbprint
#$secretWebhook = $ENV:APPSETTING_secretWebhook


$securePassword = $appSecret | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $applicationId, $securePassword
$applicationName = $requestbody.applicationName
$vaultname = "azureSelfServiceKeys"
$domainname = "trygdeetaten.no"
$ApplicationURI = $("https://$DomainName/$($applicationName -Replace('[\W]',''))")
$logoutURI = "https://login.microsoftonline.com/common/oauth2/logout"

# POST method: $req
#$requestBody = Get-Content $req -Raw | ConvertFrom-Json

$replyurls = $($requestbody.replyURLs).replace(" ",",")
$owners = $($requestbody.owners).replace(" ",",")



Connect-AzureAD -TenantId  $tenantid -ApplicationId $applicationId -CertificateThumbprint $certThumbprint

$appExist = Get-AzureADApplication -filter "DisplayName eq '$applicationname'"

# om appen ikke finnes, registrer med alle parametere
if (!($appExist)) {
    $GroupMembershipClaims = "SecurityGroup"
    $ClaimsPolicy = "53eccc94-e7d4-4c1b-9d25-62baefaab0df" #53eccc94-e7d4-4c1b-9d25-62baefaab0df = preprod. c7880a6d-ab30-4fba-be66-4c41d7e6f22f = prod

    Connect-AzureRmAccount -ServicePrincipal -Credential $credential -TenantId $tenantid

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
    
    $vaultSecret = Set-AzureKeyVaultSecret -VaultName $vaultname -name $($applicationName -Replace('[\W]','')) -SecretValue $secret
    
    
    #regsiter application
    $app = New-AzureADApplication -IdentifierUris $ApplicationURI -DisplayName $ApplicationName -GroupMembershipClaims $GroupMembershipClaims -homepage $ApplicationURI -logoutUrl $logoutURI -PasswordCredentials $aadSecret -ReplyUrls $replyurls
    
    
    # add owners + andre parametere
    foreach ($owner in $owners)
    {
        $aduser = Get-AzureADUser -objectId $owner
        Add-AzureADApplicationOwner -objectid $app.ObjectId -RefObjectId $aduser.ObjectId
    }
    
    
    $resServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $app.appID
    
    
    
    $teamsbody = ConvertTo-Json -Depth 4 @{
        title = "Ny applikasjon er registrert"
        text = "ny Applikasjon er registrert i AzureAD, for å assigne riktig policy må følgende powershell kommando kjøres som GlobalAdmin: "
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
    
    
    #Invoke-RestMethod -uri $secretWebhook -Method Post -Body $teamsbody -ContentType 'application/json'
    
    

$requestbodyAD =
@"
{
    "acceptMappedClaims": true
}
"@

$updateApp = Invoke-RestMethod -Method Patch -Uri "https://graph.windows.net/$tenantid/applications/$($app.objectid)?api-version=1.6" -Headers @{"Authorization"="Bearer $accessTokenAD"} -body $requestBodyAD -ContentType "application/json"

$output = ConvertTo-Json @{
    applicationName = $ApplicationName
    applicationObjectID = $app.ObjectId
    applicationAppID = $app.appID
    clientSecret = $key
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

    foreach ($owner in $addowner)
    {
        $aduser = Get-AzureADUser -SearchString $owner.inputObject
        Add-AzureADApplicationOwner -objectid $appExist.ObjectId -RefObjectId $aduser.ObjectId
    }
    foreach ($owner in $removeOwner) {
        Write-Output $owner.inputObject
        $aduser = Get-AzureADUser -SearchString $owner.inputObject
        Remove-AzureADApplicationOwner -objectid $appExist.ObjectId -OwnerId $aduser.ObjectId
    }
    Write-Output $addowner
    Write-Output $removeOwner

    $newowners = Get-AzureADApplicationOwner -ObjectId $appExist.ObjectId

    $output = ConvertTo-Json @{
        applicationName = $appExist.DisplayName
        appExist = $true
        ReplyURLupdate = $replyurls
        ownersUpdate = $newowners.UserPrincipalName
    }
    
    $output
 #   Out-File -Encoding Ascii -FilePath $res -inputObject $output
}
