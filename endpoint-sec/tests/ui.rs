//! Dummy libary used to separate trybuild since it is causing spurious recompilations because we change
//! the binaries by signing them.

#[cfg(test)]
mod tests {
    #[test]
    fn test_trybuild_client_ui() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/*.rs");
    }
}
