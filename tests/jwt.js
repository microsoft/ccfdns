// Rough code for decoding and verifying JWT tokens such as those issued by aDNS

const jose = require('jose');

jwks = {
keys: [
    {
        crv: "P-384",
        kid: "O/PfthjndysD5C9OdX6YPvugWM2wP82Lg8bdkdHrjnk=",
        kty: "EC",
        x: "e6XiheW-nGKrPvkoqs_fFsUaXJ9ENWwpeRfKR15THAiGEPqwP4xnfxG7tXVXyvjO",
        y: "O-MWLrVRNkQw7h9n6Le4TSK-Wc6l5Psh1mqvhZ1RIR3scxwckVMwHwrhrgjLWNiV"
    },
    {
        crv: "P-384",
        kid: "TykmeLHfiQBRXUXZvW0qFMnX2pjMdjrd89vrG3mg5HU=",
        kty: "EC",
        x: "ehN8LObmGG14acgypdKQDwJpZgOOUg-rGBzNR5kNsBWdzEO8mST4q8RGgrJt-NOU",
        y: "zUW2EoWw_Z2KCiGCST4mGNfuKxrC-XztfLGB9sLEF81hIXuaUmldNhdOlxMGDymK"
    } 
]
}

keystore = jose.createLocalJWKSet(jwks);

jwt = 'ewogICAgImFsZyI6ICJFUzM4NCIsCiAgICAia2lkIjogIk8vUGZ0aGpuZHlzRDVDOU9kWDZZUHZ1Z1dNMndQODJMZzhiZGtkSHJqbms9IiwKICAgICJ0eXAiOiAiSldUIgp9.ewogICAgImV4cCI6IDE3MDg2MjI5MjEsCiAgICAiaWF0IjogMTcwODYxOTMyMSwKICAgICJpc3MiOiAiaHR0cHM6Ly9hZG5zLmNjZi5kZXYvdjIuMCIsCiAgICAibmJmIjogMTcwODYxOTMyMQp9.MGYCMQDe5rKdFZu_whva2Wivux4ZdjSUNF-zoO77dsiP47JAsVD3WXl2bBitOxODOeN7Y0UCMQCKMQBoYtZghgjwUw3kYjl3pLGpEIfN6BeJz7y5HuDgzQKsA_SpRY7A0bu_6jD3EbA'

jose.decodeJwt(jwt)
jose.jwtVerify(jwt, keystore, { algorithms: ['ES384'] }) 

key = keystore.get('5fk0SqdYszSIjzBYkLmsjxWK20fAbzVHXd');
kid = jose.decodeProtectedHeader(jwt).kid
