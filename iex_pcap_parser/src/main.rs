extern crate etherparse;
extern crate flate2;
extern crate hdf5;
extern crate libdt;
extern crate libh5;
extern crate libiex;
extern crate pcap;
extern crate pretty_env_logger;

use std::collections::HashMap;
use std::env;
use std::ffi;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path;

use flate2::read::GzDecoder;
use log::{trace, info, warn};
use pcap::Capture;

/// 40 bytes
struct IexTpHeader {
    version: u8,
    reserved: u8,
    message_protocol_id: u16,
    channel_id: u32,
    session_id: u32,
    payload_length: u16,
    message_count: u16,
    stream_offset: u64,
    first_message_sequence_number: u64,
    send_time: libdt::UtcNs,
}

macro_rules! _index_offset {
    ( $arr:expr, $offset:expr, $type:ty, $index:expr ) => {
        {
            (($arr[$offset + $index] as $type) << (8*($index)))
        }
    };
}

macro_rules! bytes_u16 {
    ( $arr:expr, $offset:expr ) => {
        {
            _index_offset!($arr, $offset, u16, 0) +
            _index_offset!($arr, $offset, u16, 1)
        }
    };
}

macro_rules! bytes_u32 {
    ( $arr:expr, $offset:expr ) => {
        {
            _index_offset!($arr, $offset, u32, 0) +
            _index_offset!($arr, $offset, u32, 1) +
            _index_offset!($arr, $offset, u32, 2) +
            _index_offset!($arr, $offset, u32, 3)
        }
    };
}

macro_rules! bytes_u64 {
    ( $arr:expr, $offset:expr ) => {
        {
            _index_offset!($arr, $offset, u64, 0) +
            _index_offset!($arr, $offset, u64, 1) +
            _index_offset!($arr, $offset, u64, 2) +
            _index_offset!($arr, $offset, u64, 3) +
            _index_offset!($arr, $offset, u64, 4) +
            _index_offset!($arr, $offset, u64, 5) +
            _index_offset!($arr, $offset, u64, 6) +
            _index_offset!($arr, $offset, u64, 7)
        }
    };
}

type MessageSymbol = [char; 8];

fn get_price_multiplier_for_timestamp(_timestamp: u64) -> u64 {
    10000
}

struct IexDeepMessage {
    message_type: u8,
    message_subtype: u8,
    timestamp: u64,
    body: IexDeepMessageImpl,
    packet_number: u64,
    message_sequence_number: u64,
}

impl IexDeepMessage {
    fn to_serialized_tick(&self) -> Option<libh5::Tick> {
        match &self.body {
            IexDeepMessageImpl::TradeReport(m) => {
                Some(libh5::Tick {
                    message_type: self.message_type,
                    message_subtype: self.message_subtype,
                    timestamp: self.timestamp,
                    size: m.size,
                    price: m.price,
                    price_multiplier: get_price_multiplier_for_timestamp(self.timestamp),
                    packet_number: self.packet_number,
                    message_sequence_number: self.message_sequence_number,
                })
            },
            IexDeepMessageImpl::PriceLevelUpdate(m) => {
                Some(libh5::Tick {
                    message_type: self.message_type,
                    message_subtype: self.message_subtype,
                    timestamp: self.timestamp,
                    size: m.size,
                    price: m.price,
                    price_multiplier: get_price_multiplier_for_timestamp(self.timestamp),
                    packet_number: self.packet_number,
                    message_sequence_number: self.message_sequence_number,
                })
            },
            _ => None,
        }
    }

    fn symbol(&self) -> Option<String> {
        match &self.body {
            IexDeepMessageImpl::TradeReport(m) => Some(m.symbol.into_iter().collect()),
            IexDeepMessageImpl::PriceLevelUpdate(m) => Some(m.symbol.into_iter().collect()),
            _ => None,
        }
    }
}

// TODO(sherry): codegen the impls

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum SystemEvent {
    StartOfMessages             = 'O' as u8,
    StartOfSystemHours          = 'S' as u8,
    StartOfRegularMarketHours   = 'R' as u8,
    EndOfRegularMarketHours     = 'M' as u8,
    EndOfSystemHours            = 'E' as u8,
    EndOfMessages               = 'C' as u8,
}

impl SystemEvent {
    fn from_u8(byte: u8) -> Option<SystemEvent> {
        match byte as char {
            'O' => Some(SystemEvent::StartOfMessages),
            'S' => Some(SystemEvent::StartOfSystemHours),
            'R' => Some(SystemEvent::StartOfRegularMarketHours),
            'M' => Some(SystemEvent::EndOfRegularMarketHours),
            'E' => Some(SystemEvent::EndOfSystemHours),
            'C' => Some(SystemEvent::EndOfMessages),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum LimitUpLimitDownTier {
    NotApplicable = 0x0,
    Tier1NmsStock = 0x1,
    Tier2NmsStock = 0x2,
}

impl LimitUpLimitDownTier {
    fn from_u8(byte: u8) -> Option<LimitUpLimitDownTier> {
        match byte {
            0x0 => Some(LimitUpLimitDownTier::NotApplicable),
            0x1 => Some(LimitUpLimitDownTier::Tier1NmsStock),
            0x2 => Some(LimitUpLimitDownTier::Tier2NmsStock),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum TradingStatus {
    Halted                                  = 'H' as u8,
    HaltReleasedIntoOrderAcceptancePeriod   = 'O' as u8,
    PausedAndOrderAcceptancePeriod          = 'P' as u8,
    Trading                                 = 'T' as u8,
}

impl TradingStatus {
    fn from_u8(byte: u8) -> Option<TradingStatus> {
        match byte as char {
            'H' => Some(TradingStatus::Halted),
            'O' => Some(TradingStatus::HaltReleasedIntoOrderAcceptancePeriod),
            'P' => Some(TradingStatus::PausedAndOrderAcceptancePeriod),
            'T' => Some(TradingStatus::Trading),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum OperationalHaltStatus {
    Halted      = 'O' as u8,
    NotHalted   = 'N' as u8,
}

impl OperationalHaltStatus {
    fn from_u8(byte: u8) -> Option<OperationalHaltStatus> {
        match byte as char {
            'O' => Some(OperationalHaltStatus::Halted),
            'N' => Some(OperationalHaltStatus::NotHalted),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum ShortSalePriceTestStatus {
    NotInEffect = 0x0,
    InEffect    = 0x1,
}

impl ShortSalePriceTestStatus {
    fn from_u8(byte: u8) -> Option<ShortSalePriceTestStatus> {
        match byte {
            0x0 => Some(ShortSalePriceTestStatus::NotInEffect),
            0x1 => Some(ShortSalePriceTestStatus::InEffect),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum Detail {
    NoPriceTestInPlace  = ' ' as u8,
    Activated           = 'A' as u8,
    Continued           = 'C' as u8,
    Deactivated         = 'D' as u8,
    NotAvailable        = 'N' as u8,
}

impl Detail {
    fn from_u8(byte: u8) -> Option<Detail> {
        match byte as char {
            ' ' => Some(Detail::NoPriceTestInPlace),
            'A' => Some(Detail::Activated),
            'C' => Some(Detail::Continued),
            'D' => Some(Detail::Deactivated),
            'N' => Some(Detail::NotAvailable),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum SecurityEvent {
    OpeningProcessComplete = 'O' as u8,
    ClosingProcessComplete = 'C' as u8,
}

impl SecurityEvent {
    fn from_u8(byte: u8) -> Option<SecurityEvent> {
        match byte as char {
            'O' => Some(SecurityEvent::OpeningProcessComplete),
            'C' => Some(SecurityEvent::ClosingProcessComplete),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum PriceLevelUpdateEventFlags {
    OrderBookIsProcessingAnEvent = 0x0,
    EventProcessingComplete = 0x1,
}

impl PriceLevelUpdateEventFlags {
    fn from_u8(byte: u8) -> Option<PriceLevelUpdateEventFlags> {
        match byte {
            0x0 => Some(PriceLevelUpdateEventFlags::OrderBookIsProcessingAnEvent),
            0x1 => Some(PriceLevelUpdateEventFlags::EventProcessingComplete),
            _ => None,
        }
    }
}

// TODO(sherry): these are not mutually exclusive
// #[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
// #[repr(u8)]
// enum SaleConditionFlags {
//     IntermarketSweep        = 'F' as u8,
//     ExtendedHours           = 'T' as u8,
//     OddLot                  = 'I' as u8,
//     TradeThroughExempt      = '8' as u8,
//     SinglePriceCrossTrade   = 'X' as u8,
// }
// 
// impl SaleConditionFlags {
//     fn from_u8(byte: u8) -> Option<SaleConditionFlags> {
//         match byte as char {
//             'F' => Some(SaleConditionFlags::IntermarketSweep),
//             'T' => Some(SaleConditionFlags::ExtendedHours),
//             'I' => Some(SaleConditionFlags::OddLot),
//             '8' => Some(SaleConditionFlags::TradeThroughExempt),
//             'X' => Some(SaleConditionFlags::SinglePriceCrossTrade),
//             _ => None,
//         }
//     }
// }

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum PriceType {
    OfficialOpeningPrice = 'Q' as u8,
    OfficialClosingPrice = 'M' as u8,
}

impl PriceType {
    fn from_u8(byte: u8) -> Option<PriceType> {
        match byte as char {
            'Q' => Some(PriceType::OfficialOpeningPrice),
            'M' => Some(PriceType::OfficialClosingPrice),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum AuctionType {
    Opening     = 'O' as u8,
    Closing     = 'C' as u8,
    Ipo         = 'I' as u8,
    Halt        = 'H' as u8,
    Volatility  = 'V' as u8,
}

impl AuctionType {
    fn from_u8(byte: u8) -> Option<AuctionType> {
        match byte as char {
            'O' => Some(AuctionType::Opening),
            'C' => Some(AuctionType::Closing),
            'I' => Some(AuctionType::Ipo),
            'H' => Some(AuctionType::Halt),
            'V' => Some(AuctionType::Volatility),
            _ => None,
        }
    }
}

#[derive(hdf5::H5Type, Clone, PartialEq, Debug)]
#[repr(u8)]
enum ImbalanceSide {
    BuySideImbalance    = 'B' as u8,
    SellSideImbalance   = 'S' as u8,
    NoImbalance         = 'N' as u8,
}

impl ImbalanceSide {
    fn from_u8(byte: u8) -> Option<ImbalanceSide> {
        match byte as char {
            'B' => Some(ImbalanceSide::BuySideImbalance),
            'S' => Some(ImbalanceSide::SellSideImbalance),
            'N' => Some(ImbalanceSide::NoImbalance),
            _ => None,
        }
    }
}

struct SystemEventMessage {
    system_event: SystemEvent,
}

struct SecurityDirectoryMessage {
    symbol: MessageSymbol,
    round_lot_size: u32,
    adjusted_poc_price: u64,
    luld_tier: LimitUpLimitDownTier,
    flags: u8,
}

struct TradingStatusMessage {
    symbol: MessageSymbol,
    reason: [char; 4],
    trading_status: TradingStatus,
}

struct OperationalHaltStatusMessage {
    symbol: MessageSymbol,
    operational_halt_status: OperationalHaltStatus,
}

struct ShortSalePriceTestStatusMessage {
    symbol: MessageSymbol,
    detail: Detail,
    short_sale_price_test_status: ShortSalePriceTestStatus,
}

struct SecurityEventMessage {
    symbol: MessageSymbol,
    security_event: SecurityEvent,
}

struct PriceLevelUpdateMessage {
    symbol: MessageSymbol,
    size: u32,
    price: u64,
    event_flags: PriceLevelUpdateEventFlags,
}

struct TradeReportMessage {
    symbol: MessageSymbol,
    size: u32,
    price: u64,
    trade_id: u64,
    sale_condition_flags: u8,
}

struct OfficialPriceMessage {
    symbol: MessageSymbol,
    official_price: u64,
    price_type: PriceType,
}

struct TradeBreakMessage {
    symbol: MessageSymbol,
    size: u32,
    price: u64,
    trade_id: u64,
    sale_condition_flags: u8,
}

struct AuctionInformationMessage {
    symbol: MessageSymbol,
    paired_shares: u32,
    reference_price: u64,
    indicative_clearing_price: u64,
    imbalance_shares: u32,
    imbalance_side: ImbalanceSide,
    extension_number: u8,
    scheduled_auction_time: u32,
    auction_book_clearing_price: u64,
    collar_reference_price: u64,
    lower_auction_collar: u64,
    upper_auction_collar: u64,
    auction_type: AuctionType,
}

enum IexDeepMessageImpl {
    SystemEvent(SystemEventMessage),
    SecurityDirectory(SecurityDirectoryMessage),
    TradingStatus(TradingStatusMessage),
    OperationalHaltStatus(OperationalHaltStatusMessage),
    ShortSalePriceTestStatus(ShortSalePriceTestStatusMessage),
    SecurityEvent(SecurityEventMessage),

    /// Trading message formats
    PriceLevelUpdate(PriceLevelUpdateMessage),
    TradeReport(TradeReportMessage),
    OfficialPrice(OfficialPriceMessage),
    TradeBreak(TradeBreakMessage),

    /// Auction message formats
    AuctionInformation(AuctionInformationMessage),
}

struct ParseMessageResponse {
    parsed_message: IexDeepMessage,
    consumed_bytes: usize,
}

fn parse_message(bytes: &[u8], packet_num: u64, message_seq_num: u64) -> Option<ParseMessageResponse> {
    let message_type = bytes[0];
    let message_subtype = bytes[1];
    let timestamp = bytes_u64!(bytes, 2);
    match message_type as char {
        'S' => {
            SystemEvent::from_u8(message_subtype).map(|system_event| {
                let message = SystemEventMessage {
                    system_event,
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::SystemEvent(message);
                ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                }
            })
        },
        'D' => {
            LimitUpLimitDownTier::from_u8(bytes[30]).map(|luld_tier| {
                let message = SecurityDirectoryMessage {
                    flags: message_subtype,
                    symbol: [
                        bytes[10] as char, bytes[11] as char,
                        bytes[12] as char, bytes[13] as char,
                        bytes[14] as char, bytes[15] as char,
                        bytes[16] as char, bytes[17] as char,
                    ],
                    round_lot_size: bytes_u32!(bytes, 18),
                    adjusted_poc_price: bytes_u64!(bytes, 22),
                    luld_tier,
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::SecurityDirectory(message);
                ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                }
            })
        },
        'H' => {
            TradingStatus::from_u8(message_subtype).map(|trading_status| {
                let message = TradingStatusMessage {
                    trading_status,
                    symbol: [
                        bytes[10] as char, bytes[11] as char,
                        bytes[12] as char, bytes[13] as char,
                        bytes[14] as char, bytes[15] as char,
                        bytes[16] as char, bytes[17] as char,
                    ],
                    reason: [
                        bytes[18] as char, bytes[19] as char,
                        bytes[20] as char, bytes[21] as char,
                    ],
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::TradingStatus(message);
                ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                }
            })
        },
        'O' => {
            OperationalHaltStatus::from_u8(message_subtype).map(|operational_halt_status| {
                let message = OperationalHaltStatusMessage {
                    operational_halt_status,
                    symbol: [
                        bytes[10] as char, bytes[11] as char,
                        bytes[12] as char, bytes[13] as char,
                        bytes[14] as char, bytes[15] as char,
                        bytes[16] as char, bytes[17] as char,
                    ],
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::OperationalHaltStatus(message);
                ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                }
            })
        },
        'P' => {
            ShortSalePriceTestStatus::from_u8(message_subtype).and_then(|short_sale_price_test_status| {
                Detail::from_u8(bytes[18]).map(|detail| {
                    let message = ShortSalePriceTestStatusMessage {
                        short_sale_price_test_status,
                        symbol: [
                            bytes[10] as char, bytes[11] as char,
                            bytes[12] as char, bytes[13] as char,
                            bytes[14] as char, bytes[15] as char,
                            bytes[16] as char, bytes[17] as char,
                        ],
                        detail,
                    };
                    let consumed_bytes = std::mem::size_of_val(&message);
                    let body = IexDeepMessageImpl::ShortSalePriceTestStatus(message);
                    ParseMessageResponse {
                        parsed_message: IexDeepMessage {
                            message_type,
                            message_subtype,
                            timestamp,
                            body,
                            packet_number: packet_num,
                            message_sequence_number: message_seq_num,
                        },
                        consumed_bytes,
                    }
                })
            })
        },
        'E' => {
            SecurityEvent::from_u8(message_subtype).map(|security_event| {
                let message = SecurityEventMessage {
                    security_event,
                    symbol: [
                        bytes[10] as char, bytes[11] as char,
                        bytes[12] as char, bytes[13] as char,
                        bytes[14] as char, bytes[15] as char,
                        bytes[16] as char, bytes[17] as char,
                    ],
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::SecurityEvent(message);
                ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                }
            })
        },
        '8' | '5' => {
            PriceLevelUpdateEventFlags::from_u8(message_subtype).map(|event_flags| {
                let message = PriceLevelUpdateMessage {
                    event_flags,
                    symbol: [
                        bytes[10] as char, bytes[11] as char,
                        bytes[12] as char, bytes[13] as char,
                        bytes[14] as char, bytes[15] as char,
                        bytes[16] as char, bytes[17] as char,
                    ],
                    size: bytes_u32!(bytes, 18),
                    price: bytes_u64!(bytes, 22),
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::PriceLevelUpdate(message);
                ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                }
            })
        },
        'T' => {
            // SaleConditionFlags::from_u8(message_subtype).map(|sale_condition_flags| {
            if bytes.len() >= 38 {
                let message = TradeReportMessage {
                    symbol: [
                        bytes[10] as char, bytes[11] as char,
                        bytes[12] as char, bytes[13] as char,
                        bytes[14] as char, bytes[15] as char,
                        bytes[16] as char, bytes[17] as char,
                    ],
                    size: bytes_u32!(bytes, 18),
                    price: bytes_u64!(bytes, 22),
                    trade_id: bytes_u64!(bytes, 30),
                    sale_condition_flags: message_subtype,
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::TradeReport(message);
                Some(ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                })
            } else {
                println!("Not enough bytes to parse trade message: have {}, expected {}",
                      bytes.len(), 38);
                None
            }
            // })
        },
        'X' => {
            PriceType::from_u8(message_subtype).map(|price_type| {
                let message = OfficialPriceMessage {
                    price_type,
                    symbol: [
                        bytes[10] as char, bytes[11] as char,
                        bytes[12] as char, bytes[13] as char,
                        bytes[14] as char, bytes[15] as char,
                        bytes[16] as char, bytes[17] as char,
                    ],
                    official_price: bytes_u64!(bytes, 18),
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::OfficialPrice(message);
                ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                }
            })
        },
        'B' => {
            // SaleConditionFlags::from_u8(message_subtype).map(|sale_condition_flags| {
            if bytes.len() >= 38 {
                let message = TradeBreakMessage {
                    symbol: [
                        bytes[10] as char, bytes[11] as char,
                        bytes[12] as char, bytes[13] as char,
                        bytes[14] as char, bytes[15] as char,
                        bytes[16] as char, bytes[17] as char,
                    ],
                    size: bytes_u32!(bytes, 18),
                    price: bytes_u64!(bytes, 22),
                    trade_id: bytes_u64!(bytes, 30),
                    sale_condition_flags: message_subtype,
                };
                let consumed_bytes = std::mem::size_of_val(&message);
                let body = IexDeepMessageImpl::TradeBreak(message);
                Some(ParseMessageResponse {
                    parsed_message: IexDeepMessage {
                        message_type,
                        message_subtype,
                        timestamp,
                        body,
                        packet_number: packet_num,
                        message_sequence_number: message_seq_num,
                    },
                    consumed_bytes,
                })
            } else {
                println!("Not enough bytes to parse message! Have {}, expected {}",
                      bytes.len(), 38);
                None
            }
            // })
        },
        'A' => {
            // TODO(sherry): implement
            None
        },
        _ => {
            warn!("unknown message type '{}' in packet {} message {}",
                  message_type, packet_num, message_seq_num);
            None
        },
    }
}

fn parse_body(bytes: &[u8], packet_num: u64, message_seq_num_start: u64) -> Vec<IexDeepMessage> {
    let mut messages = Vec::new();
    let mut offset = 0;
    let mut message_seq_num = message_seq_num_start;
    while 2 + offset < bytes.len() {
        let message_length = bytes_u16!(bytes, offset);
        offset += 2;
        if message_length == 0 {
            warn!("encountered 0-length message at offset {}. breaking", offset);
            break;
        }
        if let Some(response) = parse_message(&bytes[offset..], packet_num, message_seq_num) {
            messages.push(response.parsed_message);
            trace!("consumed bytes: {}", response.consumed_bytes);
        } else {
            warn!("Failed to parse message {} in packet {} at offset {}",
                  message_seq_num, packet_num, offset);
        }
        offset += message_length as usize;
        message_seq_num += 1;
    }
    messages
}

fn parse_header(bytes: &[u8]) -> Option<IexTpHeader> {
    let iex_header_length = std::mem::size_of::<IexTpHeader>();
    assert!(iex_header_length == 40);
    if bytes.len() < iex_header_length {
        return None;
    }

    Some(IexTpHeader {
        version: bytes[0],
        reserved: bytes[1],
        message_protocol_id: bytes_u16!(bytes, 2),
        channel_id: bytes_u32!(bytes, 4),
        session_id: bytes_u32!(bytes, 8),
        payload_length: bytes_u16!(bytes, 12),
        message_count: bytes_u16!(bytes, 14),
        stream_offset: bytes_u64!(bytes, 16),
        first_message_sequence_number: bytes_u64!(bytes, 24),
        send_time: bytes_u64!(bytes, 32),
    })
}

fn debug_header(iex_header: &IexTpHeader) {
    info!("Version: {}", iex_header.version);
    info!("Message Protocol ID: {}", iex_header.message_protocol_id);
    info!("Channel ID: {}", iex_header.channel_id);
    info!("Session ID: {}", iex_header.session_id);
    info!("Payload length: {}", iex_header.payload_length);
    info!("Message count: {}", iex_header.message_count);
    info!("First msg seq num: {}", iex_header.first_message_sequence_number);
    info!("Send time: {}", iex_header.send_time);
    info!("");
}

#[derive(Debug)]
enum LoadPcapError {
    NoFileExtension,
    WrongFileExtension,
    FileError(io::Error),
    DeflateError(io::Error),
    PcapError(pcap::Error),
}

fn load_capture_from_pcap<P: AsRef<path::Path>>(path: P) -> Result<pcap::Capture<pcap::Offline>, LoadPcapError> {
    Capture::from_file(path).or_else(|e| Err(LoadPcapError::PcapError(e)))
}

fn load_capture_from_gz(path: &str) -> Result<pcap::Capture<pcap::Offline>, LoadPcapError> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            return Err(LoadPcapError::FileError(e));
        },
    };
    let mut data = Vec::new();
    if let Err(e) = flate2::read::GzDecoder::new(io::BufReader::new(f)).read_to_end(&mut data) {
        return Err(LoadPcapError::DeflateError(e));
    }
    let temp_path = {
        let p = path::Path::new(path);
        let mut temp_dir = env::temp_dir();
        temp_dir.push(p.file_stem().unwrap());
        temp_dir
    };
    let temp_path2 = {
        let p = path::Path::new(path);
        let mut temp_dir = env::temp_dir();
        temp_dir.push(p.file_stem().unwrap());
        temp_dir
    };
    let mut pcap_file = match fs::File::create(temp_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(LoadPcapError::FileError(e));
        },
    };
    if let Err(e) = pcap_file.write_all(&data) {
        return Err(LoadPcapError::FileError(e));
    }
    info!("Decompressed gz to temp file {:?}", temp_path2);
    load_capture_from_pcap(temp_path2)
}

// TODO(sherry): avoid uncompressing into temp pcap and read directly from gz
fn load_capture_from_file(file: &str) -> Result<pcap::Capture<pcap::Offline>, LoadPcapError> {
    let path = path::Path::new(file);
    if let Some(extension) = path.extension() {
        if extension == ffi::OsStr::new("pcap") {
            load_capture_from_pcap(file)
        } else if extension == ffi::OsStr::new("gz") {
            load_capture_from_gz(file)
        } else {
            Err(LoadPcapError::WrongFileExtension)
        }
    } else {
        Err(LoadPcapError::NoFileExtension)
    }
}

fn main() {
    pretty_env_logger::formatted_timed_builder()
        .default_format_timestamp_nanos(true)
        .init();

    let _ = hdf5::silence_errors();

    let vargs: Vec<String> = env::args().collect();
    if vargs.len() < 2 {
        panic!("Needs at least 2 args");
    }

    let pcap = &vargs[1];
    let mut capture = match load_capture_from_file(pcap) {
        Ok(cap) => cap,
        Err(e) => panic!("Failed to load {} with error: {:?}", pcap, e),
    };

    // let mut system_ticks = Vec::new();
    let mut stonks_ticks = HashMap::new();
    let mut tick_type_count = HashMap::new();

    let mut packet_counter = 0;
    let mut tick_counter = 0;
    while let Ok(raw_packet) = capture.next() {
        let packet = match etherparse::SlicedPacket::from_ethernet(raw_packet.data) {
            Err(value) => panic!("Failed to parse from ethernet: {:?}", value),
            Ok(value) => value,
        };
        let iex_header = match parse_header(packet.payload) {
            Some(hdr) => hdr,
            None => panic!("Failed to parse header because it was too short"),
        };
        assert!(iex_header.version == 0x1);
        assert!(iex_header.message_protocol_id == 0x8004);

        // dump_header(&iex_header);

        let messages = parse_body(&packet.payload[std::mem::size_of::<IexTpHeader>()..], packet_counter, iex_header.first_message_sequence_number);
        for message in messages {
            if let Some(serialized_tick) = message.to_serialized_tick() {
                let symbol = match message.symbol() {
                    Some(symbol) => symbol,
                    None => panic!("Trade tick needs to have a symbol"),
                };
                let entry = stonks_ticks.entry(symbol).or_insert(Vec::new());
                (*entry).push(serialized_tick);
            }
            tick_counter += 1;
            let entry = tick_type_count.entry(message.message_type).or_insert(0);
            (*entry) += 1;
        }

        packet_counter += 1;
    }

    info!("packets processed: {}", packet_counter);
    info!("ticks processed: {}", tick_counter);

    let trade_date = libiex::trade_date_from_deep_pcap(pcap)
        .unwrap_or_else(|e| panic!("{:?}", e));
    let file = match hdf5::file::File::open(format!("{}.h5", trade_date.format("%Y%m%d")), "w") {
        Ok(f) => f,
        Err(e) => panic!("Failed to open hdf5 handle: {}", e),
    };

    for (symbol, ticks) in &stonks_ticks {
        info!("writing {} ticks for symbol {}", ticks.len(), symbol);
        let dataset = match file.new_dataset::<libh5::Tick>().create(symbol, ticks.len()) {
            Ok(x) => x,
            Err(e) => panic!("Failed to create dataset for {}: {}", symbol, e),
        };
        match dataset.write(&ticks) {
            Ok(x) => {},
            Err(e) => panic!("Failed to write ticks for {}: {}", symbol, e),
        };
    }

    for (tick_type, count) in &tick_type_count {
        info!("tick type: {} has {} count", tick_type.clone() as char, count);
    }

    info!("Hello, world!");
}
