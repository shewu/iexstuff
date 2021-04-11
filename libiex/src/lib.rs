extern crate chrono;
extern crate libfs;

use std::ffi;
use std::path;

#[cfg(test)]
mod tests {
    #[test]
    fn test_trade_date_from_deep_pcap() {
        assert_eq!(crate::trade_date_from_deep_pcap("20190703_IEXTP1_DEEP1.0.pcap"),
                   Ok(chrono::NaiveDate::from_ymd(2019, 7, 3)));
        assert_eq!(crate::trade_date_from_deep_pcap("../../data/iex/20190703_IEXTP1_DEEP1.0.pcap"),
                   Ok(chrono::NaiveDate::from_ymd(2019, 7, 3)));
    }
}

pub fn trade_date_from_deep_pcap(deep_pcap: &str)
    -> Result<chrono::NaiveDate, libfs::TradeDateFromFileErr> {
    let path = path::Path::new(deep_pcap);
    if let Some(extension) = path.extension() {
        if !extension.eq(ffi::OsStr::new("pcap")) && !extension.eq(ffi::OsStr::new("gz")) {
            return Err(libfs::TradeDateFromFileErr::WrongFileExtension);
        }
    } else {
        return Err(libfs::TradeDateFromFileErr::WrongFileExtension);
    }

    // TODO(sherry): check format YYYYmmdd_IEXTP1_DEEP1.0.pcap?
    path.file_stem()
        .ok_or_else(|| libfs::TradeDateFromFileErr::NoStem)
        .and_then(|stem| stem.to_str().ok_or_else(|| libfs::TradeDateFromFileErr::InvalidUnicode))
        .and_then(|stem| libfs::yyyymmdd_prefix_from_stem(&stem[0..8]))
}
