# Developing Iroh

* [Development Setup](#setup)
* [Coding Rules](#rules)
* [Commit Message Guidelines](#commits)
* [Troubleshooting](#troubleshooting)

## <a name="setup"></a> Development Setup

This document describes how to set up your development environment to build and test Iroh, and
explains the basic mechanics of using `rustup` and `cargo test`.

### Installing Dependencies

Before you can build Iroh, you must install and configure the following dependencies on your
machine:

* [Git](http://git-scm.com/): The [Github Guide to
  Installing Git][git-setup] is a good source of information.

* [The Rust Programming Language](https://www.rust-lang.org/): see https://www.rust-lang.org/learn/get-started to get started


### Forking Iroh on Github

To contribute code to Iroh, you must have a GitHub account so you can push code to your own
fork of Iroh and open Pull Requests in the [GitHub Repository][github].


### Building Iroh


Check out this documentation on [how to build Iroh from source](https://github.com/n0-computer/iroh/README.md#building-from-source)


## <a name="rules"></a> Coding Rules

When you push your branch to github and open up a pull request, it will automatically trigger  [CircleCI](https://circleci.com/about/) to lint and test your code.

In order to catch linting and testing errors before pushing the code to github, be sure to run:

```
cargo clippy --workspace --examples --benches --tests
cargo test --workspace --examples --benches
```


## <a name="commits"></a> Git Commit Guidelines

We have very precise rules over how our git commit messages can be formatted.  This leads to **more
readable messages** that are easy to follow when looking through the **project history**.  But also,
we use the git commit messages to **generate the Iroh change log**.

### Commit Message Format
Each commit message consists of a **header**, a **body** and a **footer**.  The header has a special
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

* **feat**: A new feature
* **fix**: A bug fix
* **docs**: Documentation only changes
* **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing
  semi-colons, etc)
* **refactor**: A code change that neither fixes a bug nor adds a feature
* **perf**: A code change that improves performance
* **test**: Adding missing or correcting existing tests
* **chore**: Changes to the build process or auxiliary tools and libraries such as documentation
  generation

### Scope
The scope could be anything specifying place of the commit change. For example, if I am refactoring something in the `iroh-ctl` package, I may start my commit with "refactor(iroh-ctl)".

You can use `*` when the change affects more than a single scope.

### Subject
The subject contains succinct description of the change:

* use the imperative, present tense: "change" not "changed" nor "changes"
* don't capitalize first letter
* no dot (.) at the end

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
[git-revert]: https://git-scm.com/docs/git-revert
[git-setup]: https://help.github.com/articles/set-up-git
[github]: https://github.com/qri-io/frontend
[style]: https://standardjs.com
[yarn-install]: https://yarnpkg.com/en/docs/install


## <a name="troubleshooting"> Troubleshooting

#### "Too Many Open Files" on MacOS

If, while running the test suite, you get failing tests with "too many open files", you may need to adjust the number of files your shell process is willing to open. This is particularly common with the `p2p` and `cmd` pacakges. Both rely heavily on interacting temporary directories on the file system to run tests.

Often this is caused by having too low a file limit for your shell. You can use the [`ulimit` command](https://ss64.com/osx/ulimit.html) to check out or change the limits. Try the following command to set the shell limit to 1000 open files:

```
ulimit -S -n 1000
```

We recommend a ulimit value of at least 1000; feel free to go higher if you need. Some other software require values as high as 10000 to avoid the max open file issue.

###### This documentation has been adapted from the [Qri](https://github.com/qri-io/qri), [Data Together](https://github.com/datatogether/datatogether), [Hyper](https://github.com/zeit/hyper), and [AngularJS](https://github.com/angular/angularJS) documentation, all of which are projects we :heart:
