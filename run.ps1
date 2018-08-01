#Import-Module "D:\home\site\wwwroot\User_MFA\additionalmodules\MSOnline\1.1.183.8\MSOnline.psd1" -Global;
#Import-Module "D:\home\site\wwwroot\User_MFA\additionalmodules\AzureADPreview\2.0.1.18\AzureADPreview.psd1" -Global;
#Import-Module AzureADPreview
. .\createKey.ps1
. .\config.ps1


# POST method: $req
$requestBody = Get-Content $req -Raw | ConvertFrom-Json
#$name = $requestBody.name


Connect-AzureRmAccount -ServicePrincipal -Credential $credential -TenantId $tenantid
Connect-AzureAD -TenantId  $tenantid -ApplicationId $applicationId -CertificateThumbprint $certThumbprint

$requestBodyAD = "grant_type=client_credentials" +
    "&client_id=$applicationId" +
    "&client_secret=$appSecretToken" +
    "&resource=https://graph.windows.net"

$tokenResponseAD = Invoke-RestMethod -Method Post -Uri $tokenAuthURI -body $requestBodyAD -ContentType "application/x-www-form-urlencoded" # Kontakt Microsoft Graph via Rest for å hente token
$accessTokenAD = $tokenResponseAD.access_token

$vaultname = "azureSelfServiceKeys"
$applicationName = $requestbody.applicationName
$domainname = "trygdeetaten.no"
$ApplicationURI = $("https://$DomainName/$($applicationName -Replace('[\W]',''))")
$logoutURI = "https://login.microsoftonline.com/common/oauth2/logout"
#$replyurls = (
#    "https://localhost/callback",
#    "https://app.trygdeetaten.no/callback"
#)
$replyurls = $requestbody.replyURLs
#$owners = (
#    "kn@navq.onmicrosoft.com",
#    "kjetil.nordlund@trygdeetaten.no"
#)
$owners = $requestbody.owners

$GroupMembershipClaims = "SecurityGroup"
$ClaimsPolicy = "53eccc94-e7d4-4c1b-9d25-62baefaab0df" #53eccc94-e7d4-4c1b-9d25-62baefaab0df = preprod. c7880a6d-ab30-4fba-be66-4c41d7e6f22f = prod



$key = Create-AesKey



$startdate = Get-Date



$aadSecret = @{
    'startDate'=$startdate
    'endDate'=$startdate.AddYears(2)
    'keyId'=$(New-Guid);
    'value'=$Key
}

$secret = ConvertTo-SecureString -string $key -AsPlainText -Force

#$vaultkey = Add-AzureKeyVaultKey -inputObject $key -VaultName azureSelfServiceKeys -name testkey -Destination Software
$vaultSecret = Set-AzureKeyVaultSecret -VaultName $vaultname -name $($applicationName -Replace('[\W]','')) -SecretValue $secret
#$key = Get-AzureKeyVaultSecret -VaultName azureSelfServiceKeys -name testkey

$app = New-AzureADApplication -IdentifierUris $ApplicationURI -DisplayName $ApplicationName -GroupMembershipClaims $GroupMembershipClaims -homepage $ApplicationURI -logoutUrl $logoutURI -PasswordCredentials $aadSecret -ReplyUrls $replyurls
#New-AzureADApplication -IdentifierUris $ApplicationURI -DisplayName $ApplicationName -PasswordCredentials $aadSecret


foreach ($owner in $owners)
{
    $aduser = Get-AzureADUser -objectId $owner
    Add-AzureADApplicationOwner -objectid $app.ObjectId -RefObjectId $aduser.ObjectId
}


$resServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $app.appID

#$resAddSPP = Add-AzureADServicePrincipalPolicy -Id $resServicePrincipal.Id -RefObjectId $ClaimsPolicy

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