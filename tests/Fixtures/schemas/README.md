# CycloneDX schemas

Official, unmodified copies from
[CycloneDX/specification](https://github.com/CycloneDX/specification/tree/master/schema).
The pinned tag and commit live in `tests/Build/schemas.php`.

Do not edit these files by hand. Use:

```bash
composer schemas:check    # fails if a local file differs from the pinned upstream file
composer schemas:update   # downloads the pinned files and overwrites the local copies
composer schemas:check-latest  # fails if a newer upstream release changes a file or adds a spec version
```

The `Schemas` workflow runs `schemas:check-latest` on the 1st and 15th of
each month and on demand. A failed run means upstream moved; its job
summary lists the changed files and the exact pin to set.

To move to a newer specification release, bump `SPECIFICATION_TAG` and
`SPECIFICATION_COMMIT` in `tests/Build/schemas.php` together, then run
`composer schemas:update`.

Do not replace these with the copies shipped in
`cyclonedx/cyclonedx-library` (`res/schema/*.SNAPSHOT.schema.json`). Those
are renamed and, for 1.4 and 1.5, loosened (for example `version` is no
longer required), so they are not the official schemas.
