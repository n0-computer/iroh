# Contributing to Iroh

We'd love for you to contribute to our source code and to make Iroh even better.

Here are the guidelines we'd like you to follow:

* [Code of Conduct](#coc)
* [Questions and Problems](#question)
* [Issues and Bugs](#issue)
* [Feature Requests](#feature)
* [Improving Documentation](#docs)
* [Issue Submission Guidelines](#submit)
* [Pull Request Submission Guidelines](#submit-pr)

## <a name="coc"></a> Code of Conduct

Help us keep the Iroh project open and inclusive. Please read and follow our [Code of Conduct][coc].

## <a name="requests"></a> Questions, Bugs, Features

### <a name="issue"></a> Found an Issue or Bug?

If you find a bug or are having a problem using Iroh, help us by submitting an issue to our
[GitHub Repository][github]. Even better, you can submit a Pull Request with a fix.

**Please see the [Submission Guidelines](#submit) below.**

### <a name="feature"></a> Missing a Feature?

You can request a new feature by submitting an issue to our [GitHub Repository][github-issues].

If you would like to implement a new feature then consider what kind of change it is:

* **Major Changes** that you wish to contribute to the project should be discussed first in an
  [GitHub issue][github-issues] that outlines the changes and benefits of the feature. 
* **Small Changes** can directly be crafted and submitted to the [GitHub Repository][github]
  as a Pull Request. See the section about [Pull Request Submission Guidelines](#submit-pr), and
  for detailed information the [core development documentation][developers].

### <a name="docs"></a> Want a Doc Fix?

Should you have a suggestion for the documentation, you can open an issue and outline the problem
or improvement you have - however, creating the doc fix yourself is much better!

If you want to help improve the docs, it's a good idea to let others know what you're working on to
minimize duplication of effort. Create a new issue (or comment on a related existing one) to let
others know what you're working on.

If you're making a small change (typo, phrasing) don't worry about filing an issue first. Use the
friendly blue "Improve this doc" button at the top right of the doc page to fork the repository
in-place and make a quick change on the fly. The commit message is preformatted to the right type
and scope, so you only have to add the description.

For large fixes, please build and test the documentation before submitting the PR to be sure you
haven't accidentally introduced any layout or formatting issues. You should also make sure that your
commit message follows the **[Commit Message Guidelines][developers.commits]**.

## <a name="submit"></a> Issue Submission Guidelines
Before you submit your issue search the archive, maybe your question was already answered.

If your issue appears to be a bug, and hasn't been reported, open a new issue. Help us to maximize
the effort we can spend fixing issues and adding new features, by not reporting duplicate issues.

* **Overview of the Issue** - if an error is being thrown a non-minified stack trace helps
* **Motivation for or Use Case** - explain why this is a bug for you
* **Iroh Version(s)** - is it a regression?
* **Operating System** - is this a problem with all builds or only specific ones?
* **Reproduce the Error** - please provide an unambiguous set of steps we can use to reproduce the error.
* **Related Issues** - has a similar issue been reported before?
* **Suggest a Fix** - if you can't fix the bug yourself, perhaps you can point to what might be
  causing the problem (line of code or commit)

## <a name="submit-pr"></a> Pull Request Submission Guidelines
Before you submit your pull request consider the following guidelines:

* Search [GitHub](https://github.com/n0-computer/iroh/pulls) for an open or closed Pull Request
  that relates to your submission. You don't want to duplicate effort.
* Create the [development environment][developers.setup]
* Make your changes in a new git branch:

    ```shell
    git checkout -b my-fix-branch main 
    ```

* Create your patch commit.
* Follow our [Coding Rules][developers.rules].
* Commit your changes using a descriptive commit message that follows our
  [commit message conventions][developers.commits]. Adherence to the
  [commit message conventions][developers.commits] is required, because release notes are
  automatically generated from these messages.

    ```shell
    git commit -a
    ```
  Note: the optional commit `-a` command line option will automatically "add" and "rm" edited files.
* Push your branch to GitHub:

    ```shell
    git push origin my-fix-branch
    ```

* In GitHub, send a pull request to ` iroh:main`. 
* Follow our [Pull Request Guidelines](developers.prs) to understand who to tag for review and how best to merge your work.

* If we suggest changes, then:

  * Make the required updates.
  * Commit your changes to your branch (e.g. `my-fix-branch`).
  * Push the changes to your GitHub repository (this will update your Pull Request).

That's it! Thank you for your contribution!

#### After your pull request is merged

After your pull request is merged, you can safely delete your branch and pull the changes
from the main (upstream) repository:

* Delete the remote branch on GitHub either through the GitHub web UI or your local shell as follows:

    ```shell
    git push origin --delete my-fix-branch
    ```

* Check out the main branch:

    ```shell
    git checkout main -f
    ```

* Delete the local branch:

    ```shell
    git branch -D my-fix-branch
    ```

* Update your main with the latest upstream version:

    ```shell
    git pull --ff upstream main 
    ```

[coc]: https://github.com/n0-computer/iroh/blob/main/code_of_conduct.md
[developers]: DEVELOPERS.md
[developers.setup]: DEVELOPERS.md#setup
[developers.commits]: DEVELOPERS.md#commits
[developers.rules]: DEVELOPERS.md#rules
[github-issues]: https://github.com/n0-computer/iroh/issues
[github]: https://github.com/n0-computer/iroh
[jsfiddle]: http://jsfiddle.net/
[plunker]: http://plnkr.co/edit


###### This documentation has been adapted from the [Qri](https://github.com/qri-io/qri), [Data Together](https://github.com/datatogether/datatogether), [Hyper](https://github.com/zeit/hyper), and [AngularJS](https://github.com/angular/angularJS) documentation.
