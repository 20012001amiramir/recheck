# Pinned keys

`exhibitb.json` is compiled into every `recheck` build (`receipt.Pinned()`). It has the shape of
the issuer's `GET /keys.json` and is refreshed from
<https://github.com/20012001amiramir/exhibitb-roots/blob/master/keys.json> on each release:

```json
{
  "keys": [
    {
      "key_id": "eb-receipt-2026-09",
      "alg": "ed25519",
      "purpose": "receipt",
      "public_key": "<base64 of the 32 raw public-key bytes>",
      "created_at": "2026-09-04T22:23:18Z",
      "retired_at": null
    }
  ]
}
```

Retired keys stay listed forever, so a receipt sealed under an old key still verifies. A receipt
signed under a key id this file does not know reports `key_pinned: warn` — refresh the build, or
pass a freshly fetched `keys.json` with `--keys`.

Never pin `eb-receipt-test` or `eb-root-test` (the vector fixture key, whose private half is
public by design). The tests pin it themselves; on the command line, pass
`--keys spec/vectors/test-key.json` when verifying a vector.
