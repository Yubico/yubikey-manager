These OpenSSL 3.5 PKCS#8 private keys are public test fixtures, not production keys.
Each `-seed.pem` file was exported from the corresponding `-full.pem` key, so
the two files contain the same seed. The default OpenSSL output includes both
the seed and expanded key; the other output contains only the seed.

To regenerate a pair (substitute any of `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`,
`ml-kem-512`, `ml-kem-768`, or `ml-kem-1024`):

```sh
openssl genpkey -algorithm ml-dsa-44 -out ml-dsa-44-full.pem
openssl pkey -in ml-dsa-44-full.pem \
  -provparam ml-dsa.output_formats=seed-only -out ml-dsa-44-seed.pem
```

For ML-KEM, use `ml-kem.output_formats=seed-only` instead.
