// using globs for trycmd unfortunately leads to some issues
// when `.in` and `.out` directories are in use. So we avoid that

#[tokio::test]
async fn lookup_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "lookup")
        .case("tests/cmd/lookup.trycmd")
        .run();
}

#[tokio::test]
async fn get_success_cid_explicit_output_path_success_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_explicit_output_path_success.trycmd")
        .run();
}

#[tokio::test]
async fn get_cid_success_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_success.trycmd")
        .run();
}

#[tokio::test]
async fn get_ipfs_path_success_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_ipfs_path_success.trycmd")
        .run();
}

#[tokio::test]
async fn get_tail_success_test() {
    // we use the get_unwrapped_file fixture because it delivers a file
    // which is what the test simulates
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get_unwrapped_file")
        .case("tests/cmd/get_tail_success.trycmd")
        .run();
}

#[tokio::test]
async fn get_cid_directory_overwrite_expicit_failure_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_directory_overwrite_explicit_failure.trycmd")
        .run();
}

#[tokio::test]
async fn get_cid_directory_overwrite_failure_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_directory_overwrite_failure.trycmd")
        .run();
}

#[tokio::test]
async fn get_wrapped_file_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get_wrapped_file")
        .case("tests/cmd/get_wrapped_file.trycmd")
        .run();
}

#[tokio::test]
async fn get_unwrapped_file_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get_unwrapped_file")
        .case("tests/cmd/get_unwrapped_file.trycmd")
        .run();
}

#[tokio::test]
async fn get_unwrapped_file_overwrite_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get_unwrapped_file")
        .case("tests/cmd/get_unwrapped_file_overwrite.trycmd")
        .run();
}

#[tokio::test]
async fn get_failure_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_failure.trycmd")
        .run();
}

#[tokio::test]
async fn version_cli_test() {
    trycmd::TestCases::new()
        .case("tests/cmd/version.trycmd")
        .run();
}
