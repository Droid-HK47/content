# Tanium mTLS Fork

**Unofficial fork** of the *Tanium v2* integration, adding mutual TLS: the integration presents the client certificate stored in the **Certificate** field of the credential, e.g. to a reverse proxy in front of the Tanium API.

This pack is temporary. Remove it once the official integration supports client certificates (feature request to Palo Alto Networks), and switch the playbooks back to the official integration.

## Content

| Integration | Forked from |
| --- | --- |
| Tanium v2 mTLS | Tanium v2, pack `Tanium` 1.0.44 |

## Differences with the official integration

- The client certificate and its private key are read from the **Certificate** field of the credential selected from the credentials store, and presented on every request.
- TLS handshake failures are reported with their cause, instead of as a server certificate issue.
- With a client certificate and *Trust any certificate* selected, the TLS settings are the urllib3 defaults: the legacy ciphers that the official integration enables in that mode are not enabled.
- The integration ID, name and display name are changed, so that the fork can be installed next to the official pack. The commands and outputs are unchanged.

Every change in the code is marked with `[mTLS fork]`. The mutual TLS section of the code is identical in the Tanium v2 mTLS and Tanium Threat Response v2 mTLS integrations.

## Updating the fork to a new official version

1. Compare the official versions to see what changed: `git diff <old commit> <new commit> -- Packs/Tanium/Integrations/Tanium_v2/`
2. Apply these changes to `Integrations/TaniumV2MTLS/`, keeping the `[mTLS fork]` changes.
3. Update the official pack version in the descriptions, and add release notes to this pack.
