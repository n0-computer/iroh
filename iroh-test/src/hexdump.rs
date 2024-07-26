use anyhow::{ensure, Context, Result};

/// Parses a commented multi line hexdump into a vector of bytes.
///
/// This is useful to write wire level protocol tests.
pub fn parse_hexdump(s: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    for (line_number, line) in s.lines().enumerate() {
        let data_part = line.split('#').next().unwrap_or("");
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

/// Returns a hexdump of the given bytes in multiple lines as a String.
pub fn print_hexdump(bytes: impl AsRef<[u8]>, line_lengths: impl AsRef<[usize]>) -> String {
    let line_lengths = line_lengths.as_ref();
    let mut bytes_iter = bytes.as_ref().iter();
    let default_line_length = line_lengths
        .last()
        .filter(|x| **x != 0)
        .copied()
        .unwrap_or(16);
    let mut line_lengths_iter = line_lengths.iter();
    let mut output = String::new();

    loop {
        let line_length = line_lengths_iter
            .next()
            .copied()
            .unwrap_or(default_line_length);
        if line_length == 0 {
            output.push('\n');
        } else {
            let line: Vec<_> = bytes_iter.by_ref().take(line_length).collect();

            if line.is_empty() {
                break;
            }

            for byte in &line {
                output.push_str(&format!("{:02x} ", byte));
            }
            output.pop(); // Remove the trailing space
            output.push('\n');
        }
    }

    output
}

/// This is a macro to assert that two byte slices are equal.
///
/// It is like assert_eq!, but it will print a nicely formatted hexdump of the
/// two slices if they are not equal. This makes it much easier to track down
/// a difference in a large byte slice.
#[macro_export]
macro_rules! assert_eq_hex {
    ($a:expr, $b:expr) => {
        assert_eq_hex!($a, $b, [])
    };
    ($a:expr, $b:expr, $hint:expr) => {
        let a = $a;
        let b = $b;
        let hint = $hint;
        let ar: &[u8] = a.as_ref();
        let br: &[u8] = b.as_ref();
        let hintr: &[usize] = hint.as_ref();
        if ar != br {
            panic!(
                "assertion failed: `(left == right)`\nleft:\n{}\nright:\n{}\n",
                ::iroh_test::hexdump::print_hexdump(ar, hintr),
                ::iroh_test::hexdump::print_hexdump(br, hintr),
            )
        }
    };
}

#[cfg(test)]
mod tests {
    use super::{parse_hexdump, print_hexdump};

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
    #[test]
    fn test_basic_hexdump() {
        let data: &[u8] = &[0x1, 0x2, 0x3, 0x4, 0x5];
        let output = print_hexdump(data, [1, 2]);
        assert_eq!(output, "01\n02 03\n04 05\n");
    }

    #[test]
    fn test_newline_insertion() {
        let data: &[u8] = &[0x1, 0x2, 0x3, 0x4];
        let output = print_hexdump(data, [1, 0, 2]);
        assert_eq!(output, "01\n\n02 03\n04\n");
    }

    #[test]
    fn test_indefinite_line_length() {
        let data: &[u8] = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
        let output = print_hexdump(data, [2, 4]);
        assert_eq!(output, "01 02\n03 04 05 06\n07 08\n");
    }

    #[test]
    fn test_empty_data() {
        let data: &[u8] = &[];
        let output = print_hexdump(data, [1, 2]);
        assert_eq!(output, "");
    }

    #[test]
    fn test_zeros_then_default() {
        let data: &[u8] = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
        let output = print_hexdump(data, [1, 0, 0, 2]);
        assert_eq!(output, "01\n\n\n02 03\n04 05\n06 07\n08\n");
    }
}
