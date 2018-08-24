Regsiter new application API
=======================================================

> API for registrering av ny APP / servicePrincipal i Azure AD

Azure AD app / servicePrincipal er nødvendig for å kunne logge inn i applikasjoner/tjenester med AzureAD credentials

> JSON Input format:
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
