const fs = require('fs')

function decodeB64(base64String) {
    const decodedBuffer = Buffer.from(base64String, 'base64');
    const decodedString = decodedBuffer.toString('utf-8');

    return decodedString
}

function decodeJWT(jwt) {
    const jwtParts = jwt.split('.')

    return {
        header: decodeB64(jwtParts[0]),
        payload: decodeB64(jwtParts[1])
    }
}

// const base64String = "eyJ...";
// const decodedStr = decodeB64(base64String)
// console.log(decodedStr);

const jwt = `

`
const {header, payload} = decodeJWT(jwt)
const indentedPayload = JSON.stringify(JSON.parse(payload), null, 4)
fs.writeFileSync(`./tokens/jwt_idp.txt`, `${header}\n\n${indentedPayload}\n`)

