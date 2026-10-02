# Contributing to Iroh

We'd love for you to contribute to our source code to make `iroh` even better!

When contributing to `iroh`, you are expected to follow our [Code of Conduct][coc].

Here are some of the ways in which you can contribute:

## Discussions

If you want to ask a question to understand a concept regarding `iroh`, or need help working with `iroh`, please check the [Discussions][discussions]. If you don't find a thread that fits your needs, feel free to create a new one.

Please refer to our [AI Policy][AIPolicy] before using AI to assist or generate any content in a discussion.

## Issues

If you found unexpected behavior while using `iroh`, please browse our existing [issues][issues]. If no issues fit your case, [create a new one][newissue].

If you would like to suggest a new feature in `iroh`, [create a new issue][newissue]. This helps have meaningful conversations about design, feasibility, and general expectations of how a feature would work. If you plan to work on this yourself, we ask you to state this as well, so that you receive the guidance you need.

Please refer to our [AI Policy][AIPolicy] before using AI to assist or generate any issues.

## Pull Requests

Code contributions to `iroh` are greatly appreciated.

In response to the influx of AI-assisted PRs, we have a new workflow for getting your PRs merged. The intention is to make it easier for developers who are making meaningful contributions to `iroh` to get the attention of maintainers.

Note: please join our [discord][discord] if you are looking to be mentored through a bug or feature!

Here is the general workflow you should follow to contribute to `iroh`:

1. **Open an issue and have a human-to-human discussion with the maintainers**

  **We will automatically close any PRs that do not reference issues labeled `ready-for-pr`.**

  Before opening a PR, open or find an issue and discuss the proposed change with a maintainer. When there is reasonable consensus on how to implement the feature or solve the bug, then a PR is welcome. The PR description must link to that issue (for example, `Fixes #123` or `Refs #123`).

  You will know that reasonable consensus was reached when the label `ready-for-pr` is added to the issue.

- A PR that does not link to an issue will be closed automatically.
- A linked issue only counts if the label `ready-for-pr` was added. Typically this means that a discussion took place between humans and reasonable consensus was reached.
- A PR may still be closed if the PR does not match the scope agreed on in the issue.

  We are a handful of folks trying to maintain high-quality open-source software as well as a welcoming community. Please note that if your PR is closed **it is not a judgment on you or the code**. It just reflects the changing software landscape that we are all currently living through and the different processes that need to exit to respond to those changes.

  Please refer to our [AI Policy][AIPolicy] before using AI to assist or generate any issues you open or comments you write.

  Sensible exceptions will be made for small changes that don't require issues, such as doc fixes or maintenance chores, at the discretion of the maintainers.

2. **Write some code!**

   If this is your first contribution to `iroh`, you will need to [fork][forkiroh] and clone it using git. If you need help with the code you are working on, don't hesitate to ask questions in the associated issue. We will be happy to help you.

3. **Open the pull request**

   In general, pull requests should be opened as [a draft][draftprs]. This way, the team and community can know what work is being done, and reviewers can give early pointers on the work you are doing. Additionally we ask you to follow these guidelines:

   - **General code guidelines**

     - When possible, please document relevant pieces of code following the [rust documentation conventions][docconventions]. For more information on how the rust documentation system works check the [rustdoc documentation][rustdoc].
     - Comment your code. It will be useful for your reviewer and future contributors.
     - Using AI when coding your PR is allowed, but please refer to our [AI Policy][AIPolicy]. We reserve the right to close any PRs where we feel that the author has abdicated their responsibility to write a coherent, focused PR to AI. 

   - **Pull request titles**

     - `iroh` pull requests titles look like this: `type(crate): description`

       | **`type`** | **When to use** |
       |--:         |-- |
       | `feat`     | A new feature |
       | `test`     | Changes that exclusively affect tests, either by adding new ones or correcting existing ones |
       | `fix`      | A bug fix |
       | `docs`     | Documentation only changes |
       | `refactor` | A code change that neither fixes a bug nor adds a feature |
       | `perf`     | A code change that improves performance |
       | `deps`     | Dependency only updates |
       | `chore`    | Changes to the build process or auxiliary tools and libraries |


       **`crate`** is the rust crate containing your changes.

       **`description`** is a short sentence that summarizes your changes.

       If there is a breaking change please use a `!` in the commit message to denote this, eg. `feat(iroh)!: break the world`.

   - **Pull request descriptions**

     Once you open a pull request, you will be prompted to follow a template with three simple parts:

     - **Description**

       A summary of what your pull request achieves and a rough list of changes.

     - **Breaking Changes**

       Optional, if there are any breaking changes document them, including how to migrate older code.

     - **Notes & open questions**

       Notes, open questions and remarks about your changes.

     - **Checklist**

       - **Self review**: We ask you to thoroughly review your changes until you are happy with them. This helps speed up the review process.
       - **Add documentation**: If your change requires documentation updates, make sure they are properly added.
       - **Tests**: If your code creates a new feature, when possible add tests for this. If they fix a bug, a regression test is recommended as well.
       - **Breaking Changes**: All breaking changes need to be documented.


4. **Review process**

    - Mark your pull request as ready for review.
    - If a team member in particular is guiding you, feel free to directly tag them in your pull request to get a review. Otherwise, wait for someone to pick it up.
    - Attend to constructive criticism and make changes when necessary.

5. **My code is ready to be merged!**

    Congratulations on becoming an official `iroh` contributor!

[coc]: https://github.com/n0-computer/iroh/blob/main/code_of_conduct.md
[discussions]: https://github.com/n0-computer/iroh/discussions
[issues]: https://github.com/n0-computer/iroh/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc
[newissue]: https://github.com/n0-computer/iroh/issues/new
[forkiroh]: https://github.com/n0-computer/iroh/fork
[draftprs]: https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests#draft-pull-requests
[rustdoc]: https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html
[docconventions]: https://rust-lang.github.io/rfcs/1574-more-api-documentation-conventions.html#appendix-a-full-conventions-text
[discord]: https://discord.gg/Vc3nv3uyaY
[AIPolicy]: https://github.com/n0-computer/iroh/blob/main/AI_POLICY.md
