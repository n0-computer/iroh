# Release process


## Generating Changelog

Install dependencies

```sh
$ npm install -g conventional-changelog-cli
$ cd iroh
$ conventional-changelog -p angular
```

Add the output of that to `CHANGELOG.md`, and write a human-centric summary of changes.
Update the linked output to reference the new version, which conventional-changelog doesn't know about:

```md
# [](https://github.com/n0-computer/iroh/compare/v0.1.1...v) (2022-11-28)
```
becomes:
```md
# [v0.1.2](https://github.com/n0-computer/iroh/compare/v0.1.1...v0.1.2) (2022-11-28)
```

## Publishing

Publishing on crates.io, bumping version & generating tags is done using [`cargo-release`](https://github.com/crate-ci/cargo-release).

This requires the following permissions 

- on github.com/n0-computer/iroh
  - creating tags 
  - pushing to `main`
- on crates.io
  - publish access to all published crates

Dry run

```sh
$ cargo release <patch|minor|major>
```

Actual publishing

```sh
$ cargo release --execute <patch|minor|major>
```
