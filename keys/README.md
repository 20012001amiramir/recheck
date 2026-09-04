# Pinned keys

`exhibitb.json` is compiled into every `recheck` build (`receipt.Pinned()`). It has the shape of
the issuer's `GET /keys.json`:

```json
{
  "keys": [
    {
      "key_id": "eb-receipt-2026-09",
      "alg": "ed25519",
      "purpose": "receipt",
      "public_key": "<base64 of the 32 raw public-key bytes>",
      "created_at": "2026-09-01T00:00:00Z",
      "retired_at": null
    }
  ]
}
```

TODO (deploy step): fetch the production `keys.json` from the issuer, review the key ids
(`eb-receipt-YYYY-MM`, `eb-root-YYYY-MM`), write it here, and cut a release. Until then the list
is empty and `key_pinned` reports `skip` — a build without pinned keys can say a receipt is
internally consistent, not who signed it.

Never pin `eb-receipt-test` or `eb-root-test` (the vector fixture key, whose private half is
public by design).
