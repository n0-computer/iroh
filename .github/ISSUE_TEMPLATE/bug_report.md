---
name: Bug report
about: Create a report to help us improve
title: 'bug: [description]'
labels: bug
assignees: ''

---

**Describe the bug**
<!-- A clear and concise description of what the bug is. -->

**Relevant Logs**
<!-- Setup `tracing_subscriber` in your application and use the `RUST_LOG = debug` env variable to turn on debug logs. Please see: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/fn.init.html -->

**Expected behavior**
<!-- A clear and concise description of what you expected to happen. -->

**Iroh**

Version:

<!-- If possible use cargo tree: -->

```
[paste output from `cargo tree -i -e features -p iroh` here]
```

<!-- Otherwise, please list the iroh version and/or commit hash. -->

Endpoint configuration:<!-- (please complete the following information) -->

[e.g. are you using `.n0_discovery()`, a custom relay map, etc]

**Platform(s)**
Desktop<!-- (please complete the following information) -->:
 - OS: [e.g. iOS]
 - Version [e.g. 22]

Smartphone<!-- (please complete the following information) -->:
 - Device: [e.g. iPhone6]
 - OS: [e.g. iOS8.1]
 - Version [e.g. 22]

**Additional Context / Screenshots / GIFs**
<!-- Add any other context about the problem here. -->
