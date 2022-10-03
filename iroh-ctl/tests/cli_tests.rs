#[tokio::test]
async fn cli_tests() {
    std::env::set_var("IROH_CTL_FIXTURE", "peer_ids");
    trycmd::TestCases::new().case("tests/cmd/*.trycmd");
}
