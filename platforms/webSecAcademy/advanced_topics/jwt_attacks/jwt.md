In Burp, load the JWT Editor extension from the BApp store.

## JWT header parameter injections
According to the JWS specification, only the `alg` header parameter is mandatory. In practice, JWT headers often contain other parameters:
- jwk (JSON Web Key) - Provides an embedded JSON object representing the key.
- jku (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.
- kid (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching kid parameter.

### Injecting self-signed JWTs via the jwk parameter
The JSON Web Signature (JWS) specification describes an optional jwk header parameter, which servers can use to embed their public key directly within the token itself in JWK format
Example:
```
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```
Ideally, servers should only use a limited whitelist of public keys to verify JWT signatures. However, misconfigured servers sometimes use any key that's embedded in the `jwk` parameter.

You can exploit this behavior by signing a modified JWT using your own RSA private key, then embedding the matching public key in the `jwk` header. 

Although you can manually add or modify the `jwk` parameter in Burp, the `JWT Editor extension` provides a useful feature to help you test for this vulnerability:
- With the extension loaded, in Burp's main tab bar, go to the `JWT Editor Keys` tab.
- Generate a new RSA key (see `new_rsa_key_burp.md`)
- Send a request containing a JWT to Burp Repeater.
- In the message editor, switch to the extension-generated JSON Web Token tab and modify the token's payload however you like.
- Click Attack, then select Embedded JWK. When prompted, select your newly generated RSA key.
- Send the request to test how the server responds.

You can also perform this attack manually by adding the jwk header yourself. However, you may also need to update the JWT's kid header parameter to match the kid of the embedded key. The extension's built-in attack takes care of this step for you. 

### Injecting self-signed JWTs via the jku parameter
Some servers let you use the jku (JWK Set URL) header parameter to reference a JWK Set containing the key. When verifying the signature, the server fetches the relevant key from this URL.

An example of API response with keys:
```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```
#### Lab:
1. Go to the `JWT Editor Keys` tab in Burp's main tab bar.
2. Click `New RSA Key`.
3. In the dialog, click Generate to automatically generate a new key pair, then click OK to save the key. Note that you don't need to select a key size as this will automatically be updated later. 
4. In the JWT Editor Keys tab, right-click on the entry for the key that you just generated, then select `Copy Public Key as JWK`. 
5. Go to the server that you control and create an api endpoint that returns:
    ```
    {
        "keys": [

        ]
    }
    ```
    And paste the copied RSA key into `keys` array
6. Go back to the GET /admin request in Burp Repeater and switch to the extension-generated JSON Web Token message editor tab. 
7. In the header of the JWT, replace the current value of the kid parameter with the kid of the JWK that you uploaded to the exploit server. 
8. Add a new jku parameter to the header of the JWT. Set its value to the URL of your JWK Set on the exploit server. 
9. In the payload, change the value of the sub claim to administrator. 
10. At the bottom of the tab, click Sign, then select the RSA key that you generated in the previous section.
11. Make sure that the Don't modify header option is selected, then click OK

### Injecting self-signed JWTs via the kid parameter
the header of a JWT may contain a kid (Key ID) parameter, which helps the server identify which key to use when verifying the signature. 

the JWS specification doesn't define a concrete structure for this ID - it's just an arbitrary string of the developer's choosing. For example, they might use the kid parameter to point to a particular entry in a database, or even the name of a file. 

If this parameter is also vulnerable to directory traversal, an attacker could potentially force the server to use an arbitrary file from its filesystem as the verification key. 

This is especially dangerous if the server also supports JWTs signed using a symmetric algorithm. In this case, an attacker could potentially point the kid parameter to a predictable, static file, then sign the JWT using a secret that matches the contents of this file. 

You could theoretically do this with any file, but one of the simplest methods is to use /dev/null, which is present on most Linux systems. As this is an empty file, reading it returns an empty string. Therefore, signing the token with a empty string will result in a valid signature. 

> Note: If you're using the JWT Editor extension, note that this doesn't let you sign tokens using an empty string. However, due to a bug in the extension, you can get around this by using a Base64-encoded null byte.     

> Note: If the server stores its verification keys in a database, the kid header parameter is also a potential vector for SQL injection attacks. 

#### Lab:
- Create a new symmetricly signed key:
  - Go to the JWT Editor Keys tab in Burp's main tab bar.
  - Click New Symmetric Key.
  - In the dialog, click Generate to generate a new key in JWK format. Note that you don't need to select a key size as this will automatically be updated later.
  - Replace the generated value for the k property with a Base64-encoded null byte (`AA==`). Note that this is just a workaround because the JWT Editor extension won't allow you to sign tokens using an empty string.
  - Click OK to save the key.
- change the value of the kid parameter to a path traversal sequence pointing to the /dev/null file: `../../../../../../../dev/null`
- In the JWT payload, change the value of the sub claim to administrator. 
- At the bottom of the tab, click Sign, then select the symmetric key that you generated in the previous section.
- Make sure that the Don't modify header option is selected, then click OK. The modified token is now signed using a null byte as the secret key.

### Other interesting JWT header parameters
The following header parameters may also be interesting for attackers:
- cty (Content Type) - Sometimes used to declare a media type for the content in the JWT payload. This is usually omitted from the header, but the underlying parsing library may support it anyway. If you have found a way to bypass signature verification, you can try injecting a cty header to change the content type to text/xml or application/x-java-serialized-object, which can potentially enable new vectors for XXE and deserialization attacks.
- x5c (X.509 Certificate Chain) - Sometimes used to pass the X.509 public key certificate or certificate chain of the key used to digitally sign the JWT. This header parameter can be used to inject self-signed certificates, similar to the jwk header injection attacks discussed above. Due to the complexity of the X.509 format and its extensions, parsing these certificates can also introduce vulnerabilities. Details of these attacks are beyond the scope of these materials, but for more details, check out CVE-2017-2800 and CVE-2018-2633.

## Algorithm confusion attacks
HS256 (HMAC + SHA-256) is a "symmetric" key
RS256 (RSA + SHA-256) is an "asymmetric" key pair

Algorithm confusion vulnerabilities typically arise due to flawed implementation of JWT libraries. Although the actual verification process differs depending on the algorithm used, many libraries provide a single, algorithm-agnostic method for verifying signatures. These methods rely on the alg parameter in the token's header to determine the type of verification they should perform.

The following pseudo-code shows a simplified example of what the declaration for this generic verify() method might look like in a JWT library:
```bash
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```
Problems arise when website developers who subsequently use this method assume that it will exclusively handle JWTs signed using an asymmetric algorithm like RS256. Due to this flawed assumption, they may always pass a fixed public key to the method as follows:
```bash
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```

In this case, if the server receives a token signed using a symmetric algorithm like HS256, the library's generic verify() method will treat the public key as an HMAC secret (AKA private key). This means that an attacker could sign the token using HS256 and the public key, and the server will use the same public key to verify the signature.


### Lab: JWT authentication bypass via algorithm confusion
#### General info
After `/login` endpoint we get a JWT inside of a `session` cookie
```
{
  "kid": "a2c34873-a3d5-4495-b646-54a627313481",
  "alg": "RS256"
}
{
  "iss": "portswigger",
  "exp": 1725882534,
  "sub": "wiener"
}
```
Note: The signature of the JWT above is created with RSA private key

The server exposes its public keys via endpoint:
```
/jwks.json
```
So we copy the public key that the endpoint above reveals:
```
{
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "a2c34873-a3d5-4495-b646-54a627313481",
    "alg": "RS256",
    "n": "7nECfaqKu-0JzArtqRaoft3nfQcebgTEH_Iu9r6OLz-z30_ewp6R1E-r-WJJRXHRrKvpVYMUd5zBf3jN6O2VCTddlSo9-h4sdc9Aetr0IpkBBvdE1rXZRdRABNfNkhHBUnSx5mx8hBPR1WOIQBLGWIVo6GkTGKBNpPzpaGX5xNqm0cQe7dCic1la6xFeJJHB5sRdTLegXQ71E1WR4QkQ0Eu23jrle8LUgCc_sy1oxRiNkvgDBF3AByDbRzUcOR0YcG5m6JbUcGb78PvBRL1rbNH7SE7OLbFEmq2DNxMnW66MipQmhV_tceAamtsmNjUW5QBuhDhg7SARG10eBGSdoQ"
}
```

On the server we have code:
```bash
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```
And that `verify` function does the following:
```bash
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```

#### Exploit explanation:
- Extract server's public key from `/jwks.keys` endpoint
- Modify JWT token (which is inside of the `session` cookie), by changing its `alg` to `HS256` (used to be `RS256`) and change the payload of the JWT token.
- Since we modified JWT inside of `session` cookie we now need to sign it.
- We sign this modified JWT with symmetric encryption (`HMAC`) and as a secret key of symmetric encryption we actually use RSA public key that we extracted from that public endpoint.
- Look at the vulnerable code above to understand that since `alg` was changed to `HS256`, the `verify` function will actually use that RSA public key as a secret in order to decrypt the token signature

#### Exploitation steps:
- In the browser, go to the standard endpoint /jwks.json and observe that the server exposes a JWK Set containing a single public key.
- Copy the JWK object from inside the keys array

Generate a malicious private signing HMAC key (public RSA key is used as a private secret in HMAC):
- In Burp, load the JWT Editor extension from the BApp store.
- Go to the JWT Editor Keys tab in Burp's main tab bar.
- Click New RSA Key.
- In the dialog, make sure that the JWK option is selected, then paste the JWK that you just copied. Click OK to save the key.
- Right-click on the entry for the key that you just created, then select Copy Public Key as PEM.
- Use the Decoder tab to Base64 encode this PEM key, then copy the resulting string.
- Go back to the JWT Editor Keys tab in Burp's main tab bar.
- Click New Symmetric Key. In the dialog, click Generate to generate a new key in JWK format. Note that you don't need to select a key size as this will automatically be updated later.
- Replace the generated value for the `k` property with a Base64-encoded PEM that you just created.
- Save the key.

Then Modify and sign the token:
- Go back to the GET /admin request in Burp Repeater and switch to the extension-generated JSON Web Token tab.
- In the header of the JWT, change the value of the alg parameter to HS256.
- In the payload, change the value of the sub claim to `administrator`.
- At the bottom of the tab, click Sign, then select the symmetric key that you generated in the previous section.
- Make sure that the Don't modify header option is selected, then click OK. The modified token is now signed using the server's public key as the secret key.
- Send the request and observe that you have successfully accessed the admin panel.

### Lab: JWT authentication bypass via algorithm confusion with no exposed key
This lab is very similar to the previous one (Lab: JWT authentication bypass via algorithm confusion)
Except in the current lab we don't have `/jwks.json` endpoint which reveals server's public keys.
That's why we'll get public keys from 2 different JWT tokens with the tool called `portswigger/sig2n`

#### Exploitation steps (copied from the lab solution section):
Obtain two JWTs generated by the server
- In Burp, load the JWT Editor extension from the BApp store.
- In the lab, log in to your own account and send the post-login GET /my-account request to Burp Repeater.
- In Burp Repeater, change the path to /admin and send the request. Observe that the admin panel is only accessible when logged in as the administrator user.
- Copy your JWT session cookie and save it somewhere for later.
- Log out and log in again.
- Copy the new JWT session cookie and save this as well. You now have two valid JWTs generated by the server.

Brute-force the server's public key
- In a terminal, run the following command, passing in the two JWTs as arguments.
  ```bash
  docker run --rm -it portswigger/sig2n <token1> <token2>
  ```
  Note that the first time you run this, it may take several minutes while the image is pulled from Docker Hub.
- Notice that the output contains one or more calculated values of n. Each of these is mathematically possible, but only one of them matches the value used by the server. In each case, the output also provides the following:
  - A Base64-encoded public key in both X.509 and PKCS1 format.
  - A tampered JWT signed with each of these keys.
- Copy the tampered JWT from the first X.509 entry (you may only have one).
- Go back to your request in Burp Repeater and change the path back to /my-account.
- Replace the session cookie with this new JWT and then send the request.
  - If you receive a 200 response and successfully access your account page, then this is the correct X.509 key.
  - If you receive a 302 response that redirects you to /login and strips your session cookie, then this was the wrong X.509 key. In this case, repeat this step using the tampered JWT for each X.509 key that was output by the script.

Generate a malicious signing key
- From your terminal window, copy the Base64-encoded X.509 key that you identified as being correct in the previous section. Note that you need to select the key, not the tampered JWT that you used in the previous section.
- In Burp, go to the JWT Editor Keys tab and click New Symmetric Key.
- In the dialog, click Generate to generate a new key in JWK format.
- Replace the generated value for the k property with a Base64-encoded key that you just copied. Note that this should be the actual key, not the tampered JWT that you used in the previous section.
- Save the key.

Modify and sign the token
- Go back to your request in Burp Repeater and change the path to /admin.
- Switch to the extension-generated JSON Web Token tab.
- In the header of the JWT, make sure that the alg parameter is set to HS256.
- In the JWT payload, change the value of the sub claim to administrator.
- At the bottom of the tab, click Sign, then select the symmetric key that you generated in the previous section.
- Make sure that the Don't modify header option is selected, then click OK. The modified token is now signed using the server's public key as the secret key.
- Send the request and observe that you have successfully accessed the admin panel.
- In the response, find the URL for deleting carlos (/admin/delete?username=carlos). Send the request to this endpoint to solve the lab.
