# MH-GenerateToken

Azure Function (`GenerateToken`) that signs a JWT with a certificate found by thumbprint in the current user's personal certificate store
(on Azure App Service, make the certificate available with the `WEBSITE_LOAD_CERTIFICATES` app setting).

## API

`POST /api/GenerateToken?appID=...&endpoint=...&thumbprint=...` (function key required)

| Parameter | Notes |
| --- | --- |
| `appID` | Used as `iss` and `sub` |
| `endpoint` | Used as `aud` |
| `thumbprint` | Certificate thumbprint; spaces and hidden characters are stripped |

| Status | Meaning |
| --- | --- |
| `200` | `application/json` body `{"token":"..."}` |
| `400` | Missing parameter, certificate not found / no private key, or the generated token failed validation |
| `500` | Unexpected failure (details are in the function log, not in the response) |

Previously every failure returned `200` with an error message as the body; callers must now check the status code.

## Known limitations

- Targets `netcoreapp3.1` / Azure Functions v3 (in-process), which is out of support. Migrating to the isolated worker model on a current .NET is the recommended next step and was not attempted here.
- `Microsoft.IdentityModel.*` 6.6.0 is old; update it as part of that migration.
