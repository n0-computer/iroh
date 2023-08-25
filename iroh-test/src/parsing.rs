use anyhow::{ensure, Context, Result};

/// Parses a commented multi line hexdump into a vector of bytes.
///
/// This is useful to write wire level protocol tests.
pub fn parse_hexdump(s: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    for (line_number, line) in s.lines().enumerate() {
        let data_part = line.splitn(2, '#').next().unwrap_or("");
        let cleaned: String = data_part.chars().filter(|c| !c.is_whitespace()).collect();

        ensure!(
            cleaned.len() % 2 == 0,
            "Non-even number of hex chars detected on line {}.",
            line_number + 1
        );

        for i in (0..cleaned.len()).step_by(2) {
            let byte_str = &cleaned[i..i + 2];
            let byte = u8::from_str_radix(byte_str, 16)
                .with_context(|| format!("Invalid hex data on line {}.", line_number + 1))?;

            result.push(byte);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::parse_hexdump;

    #[test]
    fn test_basic() {
        let input = r"
            a1b2 # comment
            3c4d
        ";
        let result = parse_hexdump(input).unwrap();
        assert_eq!(result, vec![0xa1, 0xb2, 0x3c, 0x4d]);
    }

    #[test]
    fn test_upper_case() {
        let input = r"
            A1B2 # comment
            3C4D
        ";
        let result = parse_hexdump(input).unwrap();
        assert_eq!(result, vec![0xa1, 0xb2, 0x3c, 0x4d]);
    }

    #[test]
    fn test_mixed_case() {
        let input = r"
            a1B2 # comment
            3C4d
        ";
        let result = parse_hexdump(input).unwrap();
        assert_eq!(result, vec![0xa1, 0xb2, 0x3c, 0x4d]);
    }

    #[test]
    fn test_odd_characters() {
        let input = r"
            a1b
        ";
        let result = parse_hexdump(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_characters() {
        let input = r"
            a1g2 # 'g' is not valid in hex
        ";
        let result = parse_hexdump(input);
        assert!(result.is_err());
    }
}
