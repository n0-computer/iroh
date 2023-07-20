# Contributing to Iroh

We'd love for you to contribute to our source code and to make Iroh even better.

When contributing to Iroh, you are expected to follow our [Code of conduct][coc].

Here are some of the ways in which you can contribute:

## Discussions

If you want to ask a question to understand a concept regarding Iroh, or need help working with Iroh, plese check the [Discussions][discussions]. If you don't find a thread that fits your needs, feel free to create a new one. 

## Issues

If you found an unexpected beheaviour using Iroh, please browse our existing [issues][issues]. If none fits your case, [create a new one][newissue].

If you would like to have a new feature in Iroh, [create a new issue][newissue]. This helps have meaningful conversations about design, feasability and general expectations of how a feature would work. If you plan to work on this yourself, we ask you to state this as well, so that you receive the guidence you need ahead.

## Pull requests

Code conitrbutions to Iroh are greatly appreciated. Here is the general workflow you should follow:
- **State in the associated issue your desire to work on it**
  If there is no issue for the work you would like to do, please open one. This helps reduce duplicated efforts and give contributors the help and guideance they might need.
- **Write some code!**
  If this is your first contribution to Iroh, you will need to [fork][forkiroh] and clone it using git. If you need help with the code you are working on, don't hesitate to ask questions in the associated issue or in our [Discord][discord]. You will be happy to help you.
- **Open the pull request**
  In general, pull requests should be opened as [a draft][draftprs]. This way, the team and community can know what work is being done, and reviewers can give early pointers on the work you are doing. Aditionally we ask you to follow these guidelines:
  - **General code guideles**
    - When possible, please documment relevant pieces of code. If docummentation refers to other object (module, function, struct, etc) use ``[`path::to::ReferencedObject`]`` to link it. For more information check the [rustdoc docummentation][rustdoc]
    - Comment your code. It will be useful for your reviewer and future contributors.
  - **Pull request titles**
    - Iroh pull requests titles look like this: `type(crate): description`
      **`type`** is one of:
      - `feat`: A new feature.
      - `test`: Changes that exclusively affect tests, either by adding new ones or correcting existing ones.
      - `fix`: A bug fix.
      - `docs`: Documentation only changes.
      - `refactor`: A code change that neither fixes a bug nor adds a feature
      - `perf`: A code change that improves performance
      - `deps`: Dependency only updates
      - `chore`: Changes to the build process or auxiliary tools and libraries
      **`crate`** is the rust crate containing your changes
      **`description`** is a short sentence that summarizes your changes.
  - **Pull request descriptions**
    Once you open a pull request, you will be prompted to follow a template with three simple parts
    - **Description**
      A summary of what your pull request achieves and a rough list of changes.
    - **Notes & open questions**
      Notes, open questions and remarks about your changes.
    - Checklist
      - Self review: We ask you to thoroughly review your changes until you are happy with them. This helps speed up the review process.
      - Add docummentation: If your change requires docummentation updates, make sure they are properly added.
      - Tests: If you code creates a new feature, when possible add tests for this. If they fix a bug, a regression test is recommended as well.
  - **Review process**
    - If a team member in particular is guiding you, feel free to directly tag them in your pull request to get a review. Otherwise, wait for someone to pick it up.
    - Attend to constructive criticism and make changes when necessary.
  - **My code is ready to be merged!**
    Congratulations on becoming an official Iroh contributor!

