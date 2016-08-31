# Owin.Security.CogniStreamer

[![Build status](https://ci.appveyor.com/api/projects/status/90egsdh2x1gfeojk/branch/master?svg=true)](https://ci.appveyor.com/project/huysentruitw/owin-security-cognistreamer/branch/master)

OWIN middleware for authenticating users using a CogniStreamer portal.

## Get it on NuGet

    Install-Package Owin.Security.CogniStreamer

## Usage

```C#
app.UseCogniStreamerAuthentication(new CogniStreamerAuthenticationOptions
{
    ClientId = "OAuth2ClientId",
    ClientSecret = "OAuth2ClientSecret",
    PortalBaseUrl = new Uri("https://portalurl/"),
    AuthenticationMode = AuthenticationMode.Active,
    SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
});
```
