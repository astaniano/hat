### JWT token is not verified (only decoded)
- rarely happens but it may happen anyway

### Tokens with no signature
- change "alg":"none" in JWT header and remove the signature (the third part of JWT) but leave the trailing dot after the second part of JWT

### Brute force JWT secrets
`hashcat -a 0 -m 16500 <jwt> ./jwt.secrets.list`
To show the result run:
`hashcat -a 0 -m 16500 <jwt> ./jwt.secrets.list --show`
If success, the result looks like: `<jwt>:<identified-secret>`

## JWT header parameter injections
### Injecting self-signed JWTs via the jwk parameter
### Injecting self-signed JWTs via the jku parameter
### Injecting self-signed JWTs via the kid parameter

### Other interesting JWT header parameters
