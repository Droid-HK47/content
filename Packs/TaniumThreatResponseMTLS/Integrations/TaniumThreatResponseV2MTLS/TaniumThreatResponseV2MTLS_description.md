**UNOFFICIAL FORK (mTLS)**: this integration is a fork of the official *Tanium Threat Response v2* integration (Tanium Threat Response pack 2.2.32), patched to present a client certificate (mutual TLS), e.g. to a reverse proxy in front of the Tanium API. It is temporary: switch back to the official integration once it supports client certificates.

### Client certificate (mutual TLS)

1. Create a credential in **Settings > Integrations > Credentials**:
   - **Username** / **Password**: the Tanium credentials, as for the official integration (`_token` and the API token, or a username and password).
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

You can use an API Token or Username and Password to authenticate. In order to use an API Token, enter `_token` in the Username field and insert the API token in the Password field. 

In order to retrieve API Token:
1. Connect Tanium UI. 
2. Navigate to `Administration` at the top bar.
3. In `Configuration` tab choose `API Tokens`.
4. Press on `New API Token` in order to create new API Token.