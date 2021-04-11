extern crate chrono;

use std::ffi;
use std::path;

#[cfg(test)]
mod tests {
    #[test]
    fn test_trade_date_from_h5() {
        assert_eq!(crate::trade_date_from_h5("asdf"),
                   Err(crate::TradeDateFromFileErr::WrongFileExtension));
        assert_eq!(crate::trade_date_from_h5("asdf.txt"),
                   Err(crate::TradeDateFromFileErr::WrongFileExtension));
        // XXX(sherry): this returns ::WrongFileExtension?!
        // assert_eq!(crate::trade_date_from_h5(".h5"),
        //            Err(crate::TradeDateFromFileErr::NoStem));
        assert_eq!(crate::trade_date_from_h5("asdf.h5"),
                   Err(crate::TradeDateFromFileErr::InvalidDate));
        assert_eq!(crate::trade_date_from_h5("20180229.h5"),
                   Err(crate::TradeDateFromFileErr::InvalidDate));
        assert_eq!(crate::trade_date_from_h5("20180228.h5"),
                   Ok(chrono::NaiveDate::from_ymd(2018, 2, 28)));
    }

    #[test]
    fn test_yyyymmdd_prefix_from_stem() {
        assert_eq!(crate::yyyymmdd_prefix_from_stem("asdf"),
                   Err(crate::TradeDateFromFileErr::InvalidDate));
        assert_eq!(crate::yyyymmdd_prefix_from_stem("20181329"),
                   Err(crate::TradeDateFromFileErr::InvalidDate));
        assert_eq!(crate::yyyymmdd_prefix_from_stem("20180229"),
                   Err(crate::TradeDateFromFileErr::InvalidDate));
        assert_eq!(crate::yyyymmdd_prefix_from_stem("20180228"),
                   Ok(chrono::NaiveDate::from_ymd(2018, 2, 28)));
    }
}

pub type H5RawPath = str;

// TODO(sherry): format with {} instead of {:?}
#[derive(Debug, PartialEq)]
pub enum TradeDateFromFileErr {
    WrongFileExtension,
    NoStem,
    InvalidUnicode,
    // TODO(sherry): make reason more precise, year | month | date
    InvalidDate,
}

pub fn yyyymmdd_prefix_from_stem(stem: &str)
    -> Result<chrono::NaiveDate, TradeDateFromFileErr> {
    chrono::NaiveDate::parse_from_str(stem, "%Y%m%d")
        .or(Err(TradeDateFromFileErr::InvalidDate))
}

pub fn trade_date_from_h5(h5_path: &H5RawPath)
    -> Result<chrono::NaiveDate, TradeDateFromFileErr> {
    let path = path::Path::new(h5_path);
    if let Some(extension) = path.extension() {
        if !extension.eq(ffi::OsStr::new("h5")) {
            return Err(TradeDateFromFileErr::WrongFileExtension);
        }
    } else {
        return Err(TradeDateFromFileErr::WrongFileExtension);
    }

    path.file_stem()
        .ok_or_else(|| TradeDateFromFileErr::NoStem)
        .and_then(|stem| stem.to_str().ok_or_else(|| TradeDateFromFileErr::InvalidUnicode))
        .and_then(yyyymmdd_prefix_from_stem)
}
