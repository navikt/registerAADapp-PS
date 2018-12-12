Regsiter new application API
=======================================================

## API for registrering av ny APP / servicePrincipal i Azure AD

Azure AD app / servicePrincipal er nødvendig for å kunne logge inn i applikasjoner/tjenester med AzureAD credentials

## JSON Input format:
```
{

    "applicationName": "kn test app14",
  
    "replyURLs": [
    
        "https://localhost/callback",
        
        "https://app.trygdeetaten.no/callback"
        
    ],
    
    "owners": [
    
        "kn@navq.onmicrosoft.com",
        
        "kjetil.nordlund@trygdeetaten.no"
        
    ]

}
```

## Azure functions:

### Preprod:

navInfraQapi - registerApp-PS

### Prod:

navInfraApi - registerApp-PS

## Nødvendige variabler:

Variablene legges inn som "application settings" i Azure funksjonen

```
applicationId = appId til autentiserings app i AAD

appSecret = Key for autentiseringsappen i AAD

appSecretToken = key for autentiseringsappen i AAD

certThumbprint = thumprint på sertifikat som er lastet opp til functionen for autentisering mot AAD

secretWebhook = URI til Microsoft Teams kannal for posting av info

teanantid = Azure AD tenant ID

tokenAuthURI = AAD standard token URI

WEWSITE_LOAD_CERTIFICATES = samme thumbprint som certThumbprint
```


## Deployment:

Commit til "master" trigger autodeployment til Azure Functions i både preprod og prod tenanten.

Bruk "staging" barnchen for commit som ikke skal autodeployes.


## Contact:

For spørsmål knyttet til denne funksjonen, Azure AD applications, Azure AD integrasjon:

Nav it slack'en: #bruk-av-tokens
