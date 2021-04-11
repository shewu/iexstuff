extern crate chrono;

use chrono::prelude::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_dst() {
        assert_eq!(
            crate::utc_ns_for_naive_datetime(
                &chrono::NaiveDate::from_ymd(2018, 3, 12).and_hms(6, 30, 0)),
            1520861400000000000);
        assert_eq!(
            crate::utc_ns_for_naive_datetime(
                &chrono::NaiveDate::from_ymd(2018, 11, 2).and_hms(6, 30, 0)),
            1541165400000000000);
    }

    #[test]
    fn test_no_dst() {
        assert_eq!(
            crate::utc_ns_for_naive_datetime(
                &chrono::NaiveDate::from_ymd(2018, 3, 9).and_hms(6, 30, 0)),
            1520605800000000000);
        assert_eq!(
            crate::utc_ns_for_naive_datetime(
                &chrono::NaiveDate::from_ymd(2018, 11, 5).and_hms(6, 30, 0)),
            1541428200000000000);
    }
}

pub const NS_PER_SEC: u64 = 1_000_000_000;
pub const SEC_PER_MIN: u64 = 60;

pub type UtcNs = u64;

// XXX(sherry): careful that local time zone is what you expect!
// XXX(sherry): what happens when the system time zone changes during the program's execution?
pub fn utc_ns_for_naive_datetime(ndt: &chrono::prelude::NaiveDateTime) -> Option<UtcNs> {
    match Local.from_local_datetime(ndt) {
        chrono::LocalResult::Single(t) => Some(t.timestamp_nanos() as UtcNs),
        _ => None,
    }
}
