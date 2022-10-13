// using globs for trycmd unfortunately leads to some issues
// when `.in` and `.out` directories are in use. So we avoid that

#[test]
fn lookup_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "lookup")
        .case("tests/cmd/lookup.trycmd")
        .run();
}

#[test]
fn get_success_cid_explicit_output_path_success_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_explicit_output_path_success.trycmd")
        .run();
}

#[test]
fn get_cid_success_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_cid_success.trycmd")
        .run();
}

#[test]
fn get_wrapped_file_cli_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get_wrapped_file")
        .case("tests/cmd/get_wrapped_file.trycmd")
        .run();
}

#[test]
fn get_unwrapped_file_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get_unwrapped_file")
        .case("tests/cmd/get_unwrapped_file.trycmd")
        .run();
}

#[test]
fn get_unwrapped_file_overwrite_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get_unwrapped_file")
        .case("tests/cmd/get_unwrapped_file_overwrite.trycmd")
        .run();
}

#[test]
fn get_failure_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get_failure.trycmd")
        .run();
}

#[test]
fn version_cli_test() {
    trycmd::TestCases::new()
        .case("tests/cmd/version.trycmd")
        .run();
}

#[test]
fn add_file() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "add_file")
        .case("tests/cmd/add_file.trycmd")
        .run();
}

#[test]
fn add_missing() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "add_file")
        .case("tests/cmd/add_missing.trycmd")
        .run();
}

#[test]
fn add_directory() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "add_directory")
        .case("tests/cmd/add_directory.trycmd")
        .run();
}
