use core::fmt;
use csv::Writer;
use std::{error::Error, io::Write, time::Duration};

#[derive(Debug, Clone)]
pub struct Measurement {
    pub name: String,
    pub cycles: usize,
    pub num_shards: usize,
    pub core_time: Option<Duration>,
    pub compress_time: Option<Duration>,
    pub shrink_time: Duration,
    pub wrap_time: Duration,
}

pub fn write_measurements_to_csv(
    measurements: &[Measurement],
    filename: &str,
) -> Result<(), Box<dyn Error>> {
    let mut wtr = Writer::from_path(filename)?;
    wtr.write_record([
        "Program Name",
        "Cycles",
        "Shards",
        "Core kHz",
        "Compress kHz",
        "Total kHz",
        "Core Time (s)",
        "Compress Time (s)",
        "Shrink Time (s)",
        "Wrap Time (s)",
        "Total Core + Compress Time (s)",
        "Compress Fraction (%)",
        "Total Time (s)",
    ])?;

    for measurement in measurements {
        let record = measurement.to_csv_record();
        wtr.serialize(record)?;
    }

    wtr.flush()?;
    Ok(())
}

impl Measurement {
    #[allow(clippy::type_complexity)]
    fn to_csv_record(
        &self,
    ) -> (String, usize, usize, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64) {
        let total_core_compress_time =
            self.core_time.unwrap_or(Duration::ZERO) + self.compress_time.unwrap_or(Duration::ZERO);
        let total_time = total_core_compress_time + self.shrink_time + self.wrap_time;
        let core_khz = self
            .core_time
            .map(|t| (self.cycles as f64 / (t.as_secs_f64() * 1e3)).round())
            .unwrap_or(f64::NAN);
        let compress_khz = self
            .compress_time
            .map(|t| (self.cycles as f64 / (t.as_secs_f64() * 1e3)).round())
            .unwrap_or(f64::NAN);
        let khz = (self.cycles as f64 / (total_time.as_secs_f64() * 1e3)).round();
        let compress_fraction = (self.compress_time.unwrap_or(Duration::ZERO).as_secs_f64()
            / total_time.as_secs_f64())
            * 100.0;

        (
            self.name.clone(),
            self.cycles,
            self.num_shards,
            core_khz,
            compress_khz,
            khz,
            self.core_time.unwrap_or(Duration::ZERO).as_secs_f64(),
            self.compress_time.unwrap_or(Duration::ZERO).as_secs_f64(),
            self.shrink_time.as_secs_f64(),
            self.wrap_time.as_secs_f64(),
            total_core_compress_time.as_secs_f64(),
            compress_fraction,
            total_time.as_secs_f64(),
        )
    }

    pub fn write<W: Write>(&self, writer: &mut csv::Writer<W>) -> std::io::Result<()> {
        writer.write_record([
            "Program Name",
            "Cycles",
            "Shards",
            "Core kHz",
            "Compress kHz",
            "Total kHz",
            "Core Time (s)",
            "Compress Time (s)",
            "Shrink Time (s)",
            "Wrap Time (s)",
            "Total Core + Compress Time (s)",
            "Compress Fraction (%)",
            "Total Time (s)",
        ])?;

        let record = self.to_csv_record();
        writer.serialize(record)?;
        Ok(())
    }
}

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = Vec::new();

        let mut writer = csv::Writer::from_writer(&mut buffer);
        self.write(&mut writer).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let s = String::from_utf8(buffer).unwrap();
        let mut table = prettytable::Table::new();
        let mut rdr = csv::Reader::from_reader(s.as_bytes());

        let headers = rdr.headers().unwrap();
        table.add_row(prettytable::Row::new(headers.iter().map(prettytable::Cell::new).collect()));

        for result in rdr.records() {
            let record = result.unwrap();
            table.add_row(prettytable::Row::new(
                record.iter().map(prettytable::Cell::new).collect(),
            ));
        }

        table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        write!(f, "{table}")
    }
}
