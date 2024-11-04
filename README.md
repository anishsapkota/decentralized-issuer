# decentralized-issuer
Decentralising credentials issuance authority by using multi party computation based threshold signatures

# Running locally
**Issuer**
1. Replace .env url with [https://ngrok.com](ngrok) url for localhost:7001
2. ```cargo run```

This will start your issuer

**Signing Nodes**
1. `docker compose up -d` : This will start apache kafka in a docker container
2. `cargo run -- -n 5 -t 3`: This will start 5 nodes with threshold 3.

For inital run, there are no partial keys, so this will initiate distirbuted key generation.

**Testing**
1. send a post request with following json body to `http://localhost:7001/offer`
```
{
    "credentialSubject": {
        "given_name": "John",
        "family_name":"Doe",
        "birth_date": "2000/1/1",
        "gpa": 1.0,
        "issuance_date": "2023/10/30",
        "expiry_date": "2030/10/30"
    },
    "type": ["UniversityDegreeCredential"]
}
```
- Copy the response URL (`open-credential-offer://...`) to a QR code generator (e.g., [QRCode Generator](https://www.qrcode-generator.de)).

- Scan the QR code with your wallet app, such as [iGrant.io DataWallet](https://igrant.io/datawallet.html).
- PIN: 1234
  
The purpose of the wallet is to initiate the issuance workflow based on OID4VCI.
The wallet cannot verify schnorr signatures, so it will throw jwt is invalid at the end

2. Copy the generated jwt from the issuer's console and verify it by sending a post request with following body to `http://localhost:3030/verify`
   ```
  {
  "jwt": "eyJhbGciOiJTQ0hOT1JSIiwidHlwIjoiSldUIiwiaGFzaF9hbGciOiJTSEEyNTYifQ.eyJleHAiOjE3MzA2OTA0NTMsImlhdCI6MTczMDY4Njg1MywiaXNzIjoiaHR0cHM6Ly9kYmNlLTE0OS0yMzMtNTEtODgubmdyb2stZnJlZS5hcHAiLCJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYm5uRUgzNGl6Q2trUWdDMkJLc2dTV3FOaEFVM0I2a3dNeG5FaXB4d1VZS0c2dEEzYjRqWjZINlB6NWFHeGk3alpIWVFOcTRKeGdDYjI0ZEI2S2czYVBwdGpXWGZxUEd4ZnJjVkE5NTJ1RDY2NTNBOGtqZDI2b29tSEhIR0s0TDZ5ZmkiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vZXVyb3BhLmV1LzIwMTgvY3JlZGVudGlhbHMvZXVkaS9waWQvdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYmlydGhfZGF0ZSI6IjIwMDAvMS8xIiwiZXhwaXJ5X2RhdGUiOiIyMDMwLzEwLzMwIiwiZmFtaWx5X25hbWUiOiJEb2UiLCJnaXZlbl9uYW1lIjoiSm9obiIsImdwYSI6MS4wLCJpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtibm5FSDM0aXpDa2tRZ0MyQktzZ1NXcU5oQVUzQjZrd014bkVpcHh3VVlLRzZ0QTNiNGpaNkg2UHo1YUd4aTdqWkhZUU5xNEp4Z0NiMjRkQjZLZzNhUHB0aldYZnFQR3hmcmNWQTk1MnVENjY1M0E4a2pkMjZvb21ISEhHSzRMNnlmaSIsImlzc3VhbmNlX2RhdGUiOiIyMDI0LTExLTA0VDAyOjIwOjUzWiJ9LCJpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtibm5FSDM0aXpDa2tRZ0MyQktzZ1NXcU5oQVUzQjZrd014bkVpcHh3VVlLRzZ0QTNiNGpaNkg2UHo1YUd4aTdqWkhZUU5xNEp4Z0NiMjRkQjZLZzNhUHB0aldYZnFQR3hmcmNWQTk1MnVENjY1M0E4a2pkMjZvb21ISEhHSzRMNnlmaSIsImlzc3VhbmNlRGF0ZSI6IjIwMjQtMTEtMDRUMDI6MjA6NTNaIiwiaXNzdWVyIjoiZGlkOmVic2k6enJaWnlvUVZyZ3dwVjFRWm1SVUhOUHoiLCJ0eXBlIjpbIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ.eIUcabHhVArSWx71x9_p8R6JJQHWjp9xgfhr9ARrKBAxVW9v-5-lFAE8rqE36yKnM_I-bO2TF3adTjCIeJKJCQ",
  "public_pem":"-----BEGIN PUBLIC KEY-----\ndDj+9L4SoGaOWGnX+sCM50LDGrviBvzfQlIfI70wZuDs=\n-----END PUBLIC KEY-----"
  }
   ```
- Replace jwt with yours and public_pem with group_public.pem, generated during keygen. It can be found under `signing_nodes/keys` folder





