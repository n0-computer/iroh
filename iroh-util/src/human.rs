use humansize::{format_size, DECIMAL};

/// Format byte count as a human-readable size string eg: 1_000_000u64 -> "1 MB"
/// this func isolates a library + configuration choice
pub fn format_bytes(size: u64) -> String {
    format_size(size, DECIMAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1_000_000u64), "1 MB");
    }
}
