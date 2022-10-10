#[tokio::test]
async fn lookup_cli_test() {
    std::env::set_var("IROH_CTL_FIXTURE", "lookup");
    trycmd::TestCases::new().case("tests/cmd/lookup.trycmd");
}
