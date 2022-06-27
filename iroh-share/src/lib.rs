pub mod sender {
    use std::path::Path;

    pub struct Sender {}

    impl Sender {
        pub async fn new() -> Self {
            todo!()
        }

        pub async fn new_transfer(&self, path: &Path) -> Transfer {
            todo!()
        }
    }

    pub struct Transfer {}

    impl Transfer {}
}

pub mod receiver {}
