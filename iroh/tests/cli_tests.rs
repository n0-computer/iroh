// using globs for trycmd unfortunately leads to some issues
// when `.in` and `.out` directories are in use. So we avoid that

#[test]
fn add_directory_without_r_fails_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "add_directory")
        .case("tests/cmd/add_directory_without_r_fails.trycmd")
        .run();
}

#[test]
fn add_directory_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "add_directory")
        .case("tests/cmd/add_directory.trycmd")
        .run();
}

#[test]
fn add_file_missing_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "add_file")
        .case("tests/cmd/add_file_missing.trycmd")
        .run();
}

#[test]
fn add_file_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "add_file")
        .case("tests/cmd/add_file.trycmd")
        .run();
}

#[test]
fn get_cid_directory_overwrite_explicit_failure_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_directory_overwrite_explicit_failure.trycmd")
        .run();
}

#[test]
fn get_cid_directory_overwrite_failure_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_directory_overwrite_failure.trycmd")
        .run();
}

#[test]
fn get_cid_explicit_output_path_success_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_explicit_output_path_success.trycmd")
        .run();
}

#[test]
fn get_cid_success_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_success.trycmd")
        .run();
}

#[tokio::test]
async fn get_unwrapped_file_overwrite_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get_unwrapped_file")
        .case("tests/cmd/get_unwrapped_file_overwrite.trycmd")
        .run();
}

#[tokio::test]
async fn get_failure_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_failure.trycmd")
        .run();
}

#[test]
fn get_ipfs_path_success_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_ipfs_path_success.trycmd")
        .run();
}

#[test]
fn get_tail_success_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get_unwrapped_file")
        .case("tests/cmd/get_tail_success.trycmd")
        .run();
}

#[test]
fn get_unwrapped_file_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get_unwrapped_file")
        .case("tests/cmd/get_unwrapped_file.trycmd")
        .run();
}

#[test]
fn get_wrapped_file_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get_wrapped_file")
        .case("tests/cmd/get_wrapped_file.trycmd")
        .run();
}

#[tokio::test]
async fn get_unwrapped_symlink_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get_unwrapped_symlink")
        .case("tests/cmd/get_unwrapped_symlink.trycmd")
        .run();
}

#[tokio::test]
async fn get_wrapped_symlink_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "get_wrapped_symlink")
        .case("tests/cmd/get_wrapped_symlink.trycmd")
        .run();
}

#[test]
fn lookup_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "lookup")
        .case("tests/cmd/lookup.trycmd")
        .run();
}

#[test]
fn version_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .case("tests/cmd/version.trycmd")
        .insert_var("[VERSION]", std::env::var("CARGO_PKG_VERSION").unwrap())
        .unwrap();
}

#[test]
fn start_status_stop_test() {
    trycmd::TestCases::new()
        .env("RUST_BACKTRACE", "0")
        .env("IROH_CTL_FIXTURE", "start_status_stop")
        .case("tests/cmd/start_status_stop.trycmd")
        .run();
}
