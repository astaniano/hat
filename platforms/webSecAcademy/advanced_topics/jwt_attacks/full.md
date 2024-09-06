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

