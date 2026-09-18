**UNOFFICIAL FORK (mTLS)**: this integration is a fork of the official *Tanium v2* integration (Tanium pack 1.0.44), patched to present a client certificate (mutual TLS), e.g. to a reverse proxy in front of the Tanium API. It is temporary: switch back to the official integration once it supports client certificates.

### Client certificate (mutual TLS)

1. Create a credential in **Settings > Integrations > Credentials**:
   - **Username** / **Password**: the Tanium credentials, as for the official integration. When using an API token instead, put the certificate in the credential selected for the *API Token* parameter.
   - **Certificate**: the client certificate followed by its private key (e.g. an `RSA PRIVATE KEY` block), in PEM format:

     ```
     -----BEGIN CERTIFICATE-----
     (client certificate)
     -----END CERTIFICATE-----
     (private key block)
     ```

2. In the instance, select this credential from the credentials store. The certificate is not available to the integration when the username and password are typed in the instance.
3. Click **Test**. TLS errors are reported with their cause (e.g. certificate required, unknown CA).

Notes:
- Line breaks lost when pasting (spaces, Windows line breaks) are repaired, and the blocks can be in any order. Intermediate CA certificates can be added after the client certificate.
- An encrypted private key requires the passphrase of the credential. Otherwise, store the key decrypted: `openssl rsa -in encrypted_key.pem -out key.pem`.
- The server certificate is verified as in the official integration (see *Trust any certificate*).
- Without a certificate in the credential, the integration behaves like the official one.

---

Integration with Tanium REST API. Available from Tanium version 7.3.0. You can manage questions, actions, saved questions, packages and sensor information.

## Configuration Parameters

**Hostname**  
The network address of the Tanium server host.

**Domain**  
The Tanium user domain. Relevant when there is more than one domain inside Tanium.

**Credentials**  
The credentials should be the same as the Tanium client.

**API Token**  
The API token that should be used, if using OAuth 2.0 authentication.


## Authentication Process
This integration supports both basic authentication and OAuth 2.0 authentication.

### Basic Authentication
To authenticate using basic authentication fill in the username and password into the corresponding fields and leave
 the API Token field empty. The username and password should be the same as the Tanium client.
 
### OAuth 2.0 Authentication
To use OAuth 2.0 follow the next steps:

1. Follow the instructions [**here**](https://docs.tanium.com/platform_user/platform_user/console_api_tokens.html#add_API_tokens)  to create an API token.

2. Paste the generated API Token into the *API Token* parameter in the instance configuration, and leave the username
 and password fields empty.
3. Click the **Test** button to validate the instance configuration.

**Notes:**
1. **Trusted IP Addresses**: by default, the Tanium Server blocks API tokens from all addresses except registered Tanium
 Module Servers. To add additional allowed IP addresses for any API token, add the IP addresses to the api_token_trusted_ip_address_list global setting. To add allowed IP addresses for an individual API token, specify the IP addresses in the trusted_ip_addresses field of the api_token object.
2. **Expiration Time**: by default, an api_token is valid for seven days. To change the expiration timeframe, edit the
 api_token_expiration_in_days global setting (minimum value is 1), or include a value with the expire_in_days field when you create the token.
3. To edit a global setting in the Tanium platform, go to *Administration* -> *Global Settings* and search for the
 setting you would like to edit.
  
4. For more information see the [**Tanium documentation**](https://docs.tanium.com/platform_user/platform_user/console_api_tokens.html).


---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/tanium-v2)