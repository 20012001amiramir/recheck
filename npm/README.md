# exhibitb

Verify an EXHIBIT B receipt on your own machine, without contacting the issuer:

```
npx exhibitb verify receipt.json
```

This package is the `recheck` verifier compiled to WebAssembly and run under Node 18 or newer.
Everything — commands, exit codes, the offline guarantee, the receipt spec — is documented in the
repository: <https://github.com/20012001amiramir/recheck>.
