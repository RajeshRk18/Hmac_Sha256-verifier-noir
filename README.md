### HMAC_SHA256 Verifier
This is a HMAC SHA256 verifier circuit library.

### How to use this with TLS Notary?

Following steps happen in the rust binary:

- The client requests the data from TLS server.
- Client decrypts the encrypted response and extract **Message Authentication Code** from it.
- Then, we can create a rust script that generates a Noir boilerplate with message and key lengths set as in the client context.
- Then, we can generate the proof and verify it with;

```shell
nargo prove --prover-name <PROVER>
nargo verify -- verifier-name <VERIFIER>
```

respectively.

