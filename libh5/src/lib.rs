extern crate hdf5;

#[derive(hdf5::H5Type, Clone, PartialEq)]
#[repr(C)]
pub struct Tick {
    pub message_type: u8,
    pub message_subtype: u8,
    // unit is nanoseconds
    pub timestamp: u64,
    // Omit symbol because it should be inferred from h5's file name.
    pub size: u32,
    pub price: u64,
    pub price_multiplier: u64,
    pub packet_number: u64,
    pub message_sequence_number: u64,
}

// TODO(sherry): return Result<Vec<libh5::Tick>>
pub fn load_ticks_from_file(symbol: &str, file: &str) -> Vec<Tick> {
    let file = match hdf5::file::File::open(file, "r") {
        Ok(f) => f,
        Err(e) => panic!("Failed to open {}: {}", file, e),
    };

    let dataset = match file.dataset(symbol) {
        Ok(d) => d,
        Err(e) => panic!("Failed to load dataset '{}': {}", symbol, e),
    };
    let ticks = match dataset.read_raw::<Tick>() {
        Ok(d) => d,
        Err(e) => panic!("Failed to read data: {}", e),
    };

    ticks
}
