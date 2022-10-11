#[tokio::test]
async fn lookup_cli_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "lookup")
        .case("tests/cmd/lookup.trycmd")
        .run();
}

#[tokio::test]
async fn get_cli_test() {
    trycmd::TestCases::new()
        .env("IROH_CTL_FIXTURE", "get")
        .case("tests/cmd/get.trycmd")
        .run();
}
