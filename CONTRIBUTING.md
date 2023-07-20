# Contributing to Iroh

We'd love for you to contribute to our source code and to make Iroh even better.

When contributing to Iroh, you are expected to follow our [Code of conduct][coc].

Here are some of the ways in which you can contribute:

## Discussions

If you want to ask a question to understand a concept regarding Iroh, or need help working with Iroh, please check the [Discussions][discussions]. If you don't find a thread that fits your needs, feel free to create a new one. 

## Issues

If you found an unexpected behavior using Iroh, please browse our existing [issues][issues]. If none fits your case, [create a new one][newissue].

If you would like to have a new feature in Iroh, [create a new issue][newissue]. This helps have meaningful conversations about design, feasibility and general expectations of how a feature would work. If you plan to work on this yourself, we ask you to state this as well, so that you receive the guidance you need ahead.

## Pull requests

Code contributions to Iroh are greatly appreciated. Here is the general workflow you should follow:

1. **State in the associated issue your desire to work on it**

  If there is no issue for the work you would like to do, please open one. This helps reduce duplicated efforts and give contributors the help and guidance they might need.

2. **Write some code!**

  If this is your first contribution to Iroh, you will need to [fork][forkiroh] and clone it using git. If you need help with the code you are working on, don't hesitate to ask questions in the associated issue. You will be happy to help you.

3. **Open the pull request**

  In general, pull requests should be opened as [a draft][draftprs]. This way, the team and community can know what work is being done, and reviewers can give early pointers on the work you are doing. Additionally we ask you to follow these guidelines:

  - **General code guidelines**

    - When possible, please documment relevant pieces of code. If docummentation refers to other object (module, function, struct, etc) use ``[`path::to::ReferencedObject`]`` to link it. For more information check the [rustdoc docummentation][rustdoc]
    - Comment your code. It will be useful for your reviewer and future contributors.

  - **Pull request titles**

    - Iroh pull requests titles look like this: `type(crate): description`

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

  
      **`crate`** is the rust crate containing your changes

      **`description`** is a short sentence that summarizes your changes.

  - **Pull request descriptions**

    Once you open a pull request, you will be prompted to follow a template with three simple parts

    - **Description**

      A summary of what your pull request achieves and a rough list of changes.

    - **Notes & open questions**

      Notes, open questions and remarks about your changes.

    - **Checklist**

      - **Self review**: We ask you to thoroughly review your changes until you are happy with them. This helps speed up the review process.
      - **Add docummentation**: If your change requires docummentation updates, make sure they are properly added.
      - **Tests**: If you code creates a new feature, when possible add tests for this. If they fix a bug, a regression test is recommended as well.

  4. **Review process**

    - Mark your pull request as ready for review.
    - If a team member in particular is guiding you, feel free to directly tag them in your pull request to get a review. Otherwise, wait for someone to pick it up.
    - Attend to constructive criticism and make changes when necessary.

  5. **My code is ready to be merged!**

    Congratulations on becoming an official Iroh contributor!

[coc]: https://github.com/n0-computer/iroh/blob/main/code_of_conduct.md
[discussions]: https://github.com/n0-computer/iroh/discussions
[issues]: https://github.com/n0-computer/iroh/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc
[newissue]: https://github.com/n0-computer/iroh/issues/new
[forkiroh]: https://github.com/n0-computer/iroh/fork
[draftprs]: https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests#draft-pull-requests
[rustdoc]: https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html
