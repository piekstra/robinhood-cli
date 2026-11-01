//! Decimal amounts without floats: the provider's fixed-point money strings
//! trimmed for display ([`normalize_amount`]), and integer fixed-point
//! arithmetic at 8 fraction digits — the API's own quantity precision — for
//! anything that multiplies, divides, or sums them. No float ever touches a
//! balance, a quantity, or a price.

use pk_cli_core::Money;

/// Trim a provider amount string for display: two decimals minimum, further
/// digits only when significant (`"1234.5600"` → `"1234.56"`,
/// `"0.676086"` stays). Sub-cent precision is real for option and crypto
/// prices, so it is never rounded away here.
pub(crate) fn normalize_amount(raw: &str) -> String {
    match raw.split_once('.') {
        Some((int, frac)) => {
            let trimmed = frac.trim_end_matches('0');
            if trimmed.len() <= 2 {
                format!("{int}.{trimmed:0<2}")
            } else {
                format!("{int}.{trimmed}")
            }
        }
        None => format!("{raw}.00"),
    }
}

/// Fraction digits the money math carries. Eight — the API's own quantity
/// precision (`"10.00000000"`), and enough that a real equity exceeding the
/// 4-decimal money convention (seen live 2026-08-21) sums exactly. i64 at
/// this scale still holds ~$92B.
pub(crate) const FRAC_DIGITS: usize = 8;
pub(crate) const SCALE: i64 = 100_000_000;

/// quantity × price, both in 1/10⁸ units, exact in `i128`, rounded half
/// away from zero back to 1/10⁸ units.
pub(crate) fn mul_fixed(quantity: i64, price: i64) -> Option<i64> {
    let product = (quantity as i128) * (price as i128);
    let scale = SCALE as i128;
    let half = scale / 2;
    let rounded = if product >= 0 {
        (product + half) / scale
    } else {
        (product - half) / scale
    };
    i64::try_from(rounded).ok()
}

/// Parse a decimal amount into 1/10^[`FRAC_DIGITS`] units. `None` for
/// anything that is not a plain signed decimal within that precision — the
/// caller treats that as an upstream surprise rather than guessing.
pub(crate) fn to_fixed(amount: &str) -> Option<i64> {
    let (negative, digits) = match amount.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, amount),
    };
    let (int, frac) = digits.split_once('.').unwrap_or((digits, ""));
    if int.is_empty() || frac.len() > FRAC_DIGITS {
        return None;
    }
    if !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let int: i64 = int.parse().ok()?;
    let frac: i64 = format!("{frac:0<FRAC_DIGITS$}").parse().ok()?;
    let v = int.checked_mul(SCALE)?.checked_add(frac)?;
    Some(if negative { -v } else { v })
}

/// 1/10^[`FRAC_DIGITS`] units back to a [`Money`], trimmed the way every
/// other amount in this CLI is (two decimals minimum, further digits only
/// when significant). Takes `i128` so a caller summing in `i128` (which a
/// sum of `i64` values cannot overflow) renders directly; per-value
/// producers pass `i64` via `into`.
pub(crate) fn from_fixed(v: i128) -> Money {
    let sign = if v < 0 { "-" } else { "" };
    let scale = i128::from(SCALE);
    let (units, frac) = ((v / scale).abs(), (v % scale).abs());
    Money::usd(normalize_amount(&format!(
        "{sign}{units}.{frac:0FRAC_DIGITS$}"
    )))
}

/// a ÷ b, both in 1/10⁸ units, exact in `i128` up to the final rounding
/// (half away from zero, back to 1/10⁸ units). `None` for a zero divisor or
/// an out-of-range quotient.
pub(crate) fn div_fixed(a: i64, b: i64) -> Option<i64> {
    if b == 0 {
        return None;
    }
    let num = i128::from(a) * i128::from(SCALE);
    let den = i128::from(b);
    let (q, r) = (num / den, num % den);
    let rounded = if 2 * r.abs() >= den.abs() {
        if (num < 0) != (den < 0) {
            q - 1
        } else {
            q + 1
        }
    } else {
        q
    };
    i64::try_from(rounded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_is_exact_and_rounds_half_away_from_zero() {
        // 10 × 155.00
        assert_eq!(mul_fixed(10 * SCALE, 155 * SCALE), Some(1550 * SCALE));
        // 2.5 × 1.5 = 3.75
        assert_eq!(
            mul_fixed(5 * SCALE / 2, 3 * SCALE / 2),
            Some(375 * SCALE / 100)
        );
        // 0.00000001 shares × $0.50 = 5e-9 → rounds up to 1e-8.
        assert_eq!(mul_fixed(1, SCALE / 2), Some(1));
        // Fractional share × sub-cent price stays exact within 8 digits:
        // 0.33333333 × 0.1 = 0.033333333 → rounds to 0.03333333.
        assert_eq!(mul_fixed(33_333_333, SCALE / 10), Some(3_333_333));
        assert_eq!(mul_fixed(0, 155 * SCALE), Some(0));
    }

    #[test]
    fn to_fixed_parses_signed_decimals_and_rejects_the_rest() {
        assert_eq!(to_fixed("2000.00"), Some(2000 * SCALE));
        assert_eq!(to_fixed("0.0001"), Some(10_000));
        assert_eq!(to_fixed("-0.05"), Some(-5_000_000), "sign survives |v| < 1");
        assert_eq!(to_fixed("15"), Some(15 * SCALE));
        // Eight digits — the API's own quantity precision — parse exactly;
        // beyond that is an upstream surprise.
        assert_eq!(to_fixed("10.00000000"), Some(10 * SCALE));
        assert_eq!(to_fixed("1234.567856"), Some(123_456_785_600));
        assert_eq!(to_fixed("0.123456789"), None, "more than 8 digits");
        assert_eq!(to_fixed("n/a"), None);
        assert_eq!(to_fixed(""), None);
        assert_eq!(to_fixed(".5"), None);
    }

    #[test]
    fn from_fixed_round_trips_and_keeps_the_sign() {
        assert_eq!(from_fixed(i128::from(2000 * SCALE)).amount, "2000.00");
        assert_eq!(from_fixed(-5_000_000).amount, "-0.05");
        assert_eq!(from_fixed(30_000).amount, "0.0003");
        assert_eq!(from_fixed(0).amount, "0.00");
    }

    #[test]
    fn division_rounds_half_away_from_zero() {
        // 67.6086 / 100 = 0.676086 — a per-contract figure to per-share.
        assert_eq!(
            div_fixed(to_fixed("67.6086").unwrap(), 100 * SCALE),
            to_fixed("0.676086")
        );
        // 1 / 3 = 0.33333333 (rounds down), 2 / 3 = 0.66666667 (rounds up).
        assert_eq!(div_fixed(SCALE, 3 * SCALE), Some(33_333_333));
        assert_eq!(div_fixed(2 * SCALE, 3 * SCALE), Some(66_666_667));
        assert_eq!(div_fixed(-2 * SCALE, 3 * SCALE), Some(-66_666_667));
        assert_eq!(div_fixed(SCALE, 0), None);
        // Remainder zero leaves the quotient alone, whatever the sign.
        assert_eq!(div_fixed(0, 3 * SCALE), Some(0));
    }
}
