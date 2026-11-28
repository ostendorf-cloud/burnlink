# Changelog

## v0.1.0 (2026-11-28)

### Features

- **web:** check a secret before the reveal and finish the keyboard flow ([#90](https://github.com/ostendorf-cloud/burnlink/pull/90))
- **cli:** send and open a secret from the terminal ([#91](https://github.com/ostendorf-cloud/burnlink/pull/91))
- **notify:** tell a sender when a secret was redeemed ([#84](https://github.com/ostendorf-cloud/burnlink/pull/84))
- **web:** share and reveal a secret end to end in the browser ([#55](https://github.com/ostendorf-cloud/burnlink/pull/55))
- **web:** give burnlink its own generated palette ([#50](https://github.com/ostendorf-cloud/burnlink/pull/50))
- **legal:** serve the imprint and privacy pages with the govue routes ([#48](https://github.com/ostendorf-cloud/burnlink/pull/48))
- **analytics:** count page views with govue and Umami ([#46](https://github.com/ostendorf-cloud/burnlink/pull/46))
- **webapp:** serve the five secret endpoints ([#44](https://github.com/ostendorf-cloud/burnlink/pull/44))
- **store:** add the Redis-compatible secret store client ([#41](https://github.com/ostendorf-cloud/burnlink/pull/41))
- **web:** add the security page that explains the encryption ([#27](https://github.com/ostendorf-cloud/burnlink/pull/27))
- **requestlink:** receive a secret through a request link ([#20](https://github.com/ostendorf-cloud/burnlink/pull/20))
- **crypto:** port the payload format from old_burnlink ([#12](https://github.com/ostendorf-cloud/burnlink/pull/12))

### Bug Fixes

- **deps:** update govue to v0.12.0 ([#93](https://github.com/ostendorf-cloud/burnlink/pull/93))
- **deps:** update module github.com/redis/go-redis/v9 to v9.24.1 ([#88](https://github.com/ostendorf-cloud/burnlink/pull/88))
- **requestlink:** address the deferred findings of the #20 review ([#80](https://github.com/ostendorf-cloud/burnlink/pull/80))
- **deps:** update module github.com/redis/go-redis/v9 to v9.24.0 ([#72](https://github.com/ostendorf-cloud/burnlink/pull/72))
- **web:** give the request link page a main landmark and serve /r/<id> ([#29](https://github.com/ostendorf-cloud/burnlink/pull/29))
