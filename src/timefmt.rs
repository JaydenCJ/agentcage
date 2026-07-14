//! Minimal UTC timestamp formatting (RFC 3339), dependency-free.
//!
//! Audit entries only need a sortable UTC timestamp; pulling in a full
//! date-time crate for that would be wasteful for a single-binary tool.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339_from_unix(secs)
}

/// Formats Unix seconds (UTC) as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Converts days since 1970-01-01 to a (year, month, day) civil date.
///
/// This is Howard Hinnant's `civil_from_days` algorithm, exact for all
/// dates in the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamp() {
        // 2026-07-08 12:34:56 UTC.
        assert_eq!(rfc3339_from_unix(1_783_514_096), "2026-07-08T12:34:56Z");
    }

    #[test]
    fn leap_day() {
        // 2024-02-29 00:00:00 UTC.
        assert_eq!(rfc3339_from_unix(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn year_boundary() {
        // 2025-12-31 23:59:59 UTC.
        assert_eq!(rfc3339_from_unix(1_767_225_599), "2025-12-31T23:59:59Z");
    }

    #[test]
    fn before_epoch() {
        // 1969-12-31 23:59:59 UTC.
        assert_eq!(rfc3339_from_unix(-1), "1969-12-31T23:59:59Z");
    }
}
