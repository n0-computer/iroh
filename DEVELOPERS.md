# Developing Iroh

- [Development Setup](#setup)
- [Coding Rules](#rules)
- [Pull Request Guidlines](#prs)
- [Commit Message Guidelines](#commits)
- [Troubleshooting](#troubleshooting)

## <a name="setup"></a> Development Setup

This document describes how to set up your development environment to build and test Iroh, and
explains the basic mechanics of using `cargo run` and `cargo test`.

### Installing Dependencies

Before you can build Iroh, you must install and configure the following dependencies on your
machine:

- [Git](http://git-scm.com/): The [Github Guide to
  Installing Git][git-setup] is a good source of information.

- [The Rust Programming Language](https://www.rust-lang.org/): see https://www.rust-lang.org/learn/get-started to get started

#### Protobuf compiler

[Protobuf compiler](https://github.com/protocolbuffers/protobuf#protocol-compiler-installation): Download it from the [Protobuf Releases page](https://github.com/protocolbuffers/protobuf/releases)

You need to get the `protoc-` release for your platform (they can be found at the very bottom of the list of release binaries). To install, make sure the `protoc` compiler is on your path. If you get errors during build about `experimental_allow_proto3_optional` or inability to import `/google/protobuf/empty.proto` you're likely using a version of the compiler that's too old.

It may be that Rust Analyzer does not find the protobuf compiler even after installation. You can point it in the right direction using a configuration like this:

```
   "rust-analyzer.cargo.extraEnv": {
     "PROTOC": "/path/to/protoc"
   }
```

This works in VSCode settings, for instance.

#### Clang

RocksDb requires `libclang` to be built successfully. On Linux you can make this available by installing the clang package.

### Forking Iroh on Github

To contribute code to Iroh, you must have a GitHub account so you can push code to your own
fork of Iroh and open Pull Requests in the [GitHub Repository][github].

### Building Iroh from source

Use `cargo` commands to build and run the various Iroh binaries.
For example:

```shell
# run each command in a different terminal to simulate running iroh as
# microservices on different boxes:
$ cargo run -p iroh-p2p
$ cargo run -p iroh-gateway
$ cargo run -p iroh-store
$ cargo run -p iroh -- status --watch
```

If you want to use the `iroh` binary to start and stop the services, you can
use `xtask` to move previously built binaries to the correct bin:

```shell
# build the binaries
$ cargo build

# or build the binaries for release:
$ cargo build --release

# move the binaries to the correct location
$ cargo xtask dev-install
```

## <a name="rules"></a> Coding Rules

When you push your branch to github and open up a pull request, it will automatically trigger [CircleCI](https://circleci.com/about/) to lint and test your code.

In order to catch linting and testing errors before pushing the code to github, be sure to run:

```shell
$ cargo clippy --workspace --all-features --all-targets
$ cargo test --workspace --all-features --all-targets
```

Setting up a [git hook][git-hook] to run these commands can save you many headaches:

```shell
#!/bin/sh
cargo clippy --workspace --all-features --all-targets && cargo test --workspace --all-features --all-targets
```

## <a name="dependecies"></a> Dependencies

Any crate added to iroh will need to use a license compatible with ours.  Any PR that introduces a new crate will require additional review time to audit the crate being introduced, including rationale on why you chose *this* crate, and what alternatives you considered willl speed up the review process.

Crate lists in `Cargo.toml` files must be kept alphabetically sorted.

## <a name="prs"></a> Pull Request Guidelines

The tests must pass and you must get an approval from someone on the Iroh team before you can merge your PR.

Depending on your permissions in the `iroh` repo, you may not have the the ability to "request a review". Instead, please tag your selected reviewers in the PR itself (using the `@`) and specify that you would like them to review. If you are a member of our discord community, you can and should ping your reviewer(s) there as well.

If you don't know who to tag for review, here are some good guidelines. For any markdown documentations changes, tag `ramfox` or `b5`. If your PR solves an issue that someone else created, tag that person in review. If it's an issue you have created, tag team members who have been discussing the issue. Otherwise, create the PR and note that you aren't sure who to tag! Someone will drop in to give you guidance. If you are apart of our discord community, ask who should be tagged in the `iroh` channel.

### A note about our current CI testing set up

The MacOS testing infrastructure currently does not work on forked branches of `iroh`. If you are working on a forked branch, you will notice that the MacOS tests on your PRs will always fail (because they will not run). This is the only case where you may have a "failing" test and still merge your PR.

### Merging

Please "squash and merge" your commits, combining the commit message into something that will properly summarize all the changes you have made, the bugs you have fixed, and/or the features you have implemented. Use the commit guidelines outlined in the following sections.

## <a name="commits"></a> Git Commit Guidelines

We have very precise rules over how our git commit messages can be formatted. This leads to **more
readable messages** that are easy to follow when looking through the **project history**. But also,
we use the git commit messages to **generate the Iroh change log**.

### Commit Message Format

Each commit message consists of a **header**, a **body** and a **footer**. The header has a special
format that includes a **type**, a **scope** and a **subject**:

```
<type>(<scope>): <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

The **header** is mandatory and the **scope** of the header is optional.

Any line of the commit message cannot be longer 100 characters! This allows the message to be easier
to read on GitHub as well as in various git tools.

### Revert

If the commit reverts a previous commit, it should begin with `revert: `, followed by the header
of the reverted commit.
In the body it should say: `This reverts commit <hash>.`, where the hash is the SHA of the commit
being reverted.
A commit with this format is automatically created by the [`git revert`][git-revert] command.

### Type

Must be one of the following:

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing
  semi-colons, etc)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing or correcting existing tests
- **chore**: Changes to the build process or auxiliary tools and libraries such as documentation
  generation

### Scope

The scope could be anything specifying place of the commit change. For example, if I am refactoring something in the `iroh` package, I may start my commit with "refactor(iroh)".

You can use `*` when the change affects more than a single scope.

### Subject

The subject contains succinct description of the change:

- use the imperative, present tense: "change" not "changed" nor "changes"
- don't capitalize first letter
- no dot (.) at the end

### Body

Just as in the **subject**, use the imperative, present tense: "change" not "changed" nor "changes".
The body should include the motivation for the change and contrast this with previous behavior.

### Footer

The footer should contain any information about **Breaking Changes** and is also the place to
[reference GitHub issues that this commit closes][closing-issues].

**Breaking Changes** should start with the word `BREAKING CHANGE:` with a space or two newlines.
The rest of the commit message is then used for this.

A detailed explanation can be found in this [document][commit-message-format].

[closing-issues]: https://help.github.com/articles/closing-issues-via-commit-messages/
[commit-message-format]: https://docs.google.com/document/d/1QrDFcIiPjSLDn3EL15IJygNPiHORgU1_OOAqWjiDU5Y/edit#
[github]: https://github.com/n0-computer/iroh
[git-revert]: https://git-scm.com/docs/git-revert
[git-setup]: https://help.github.com/articles/set-up-git
[git-hook]: https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks

## <a name="troubleshooting"> Troubleshooting

#### "Too Many Open Files" on MacOS

If, while running Iroh, you get errors concerning "too many open files", you will need to adjust the number of files your shell process is willing to open. This is particularly common with any `p2p` work.

Often this is caused by having too low a file limit for your shell. You can use the [`ulimit` command](https://ss64.com/osx/ulimit.html) to check out or change the limits. Try the following command to set the shell limit to unlimited open files:

```
ulimit -S -n unlimited
```

###### This documentation has been adapted from the [Qri](https://github.com/qri-io/qri), [Data Together](https://github.com/datatogether/datatogether), [Hyper](https://github.com/zeit/hyper), and [AngularJS](https://github.com/angular/angularJS) documentation, all of which are projects we :heart:
