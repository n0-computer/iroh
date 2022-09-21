use std::env;

#[test]
fn cli_tests() {
    env::set_var("IROH_CTL_TESTING", "1");
    trycmd::TestCases::new().case("tests/cmd/*.trycmd");
}
