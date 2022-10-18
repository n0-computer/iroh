# localOps

Think "devops on localhost". This crate contains iroh-specific tools for starting & stopping processes in a cross platform way. 

This crate targets three operating systems via [conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html):
* `macos`
* `linux`
* `windows`