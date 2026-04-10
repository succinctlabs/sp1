use sp1_test::{utils::pretty_comparison, BenchEntry};

pub fn main() {
    let old_path =
        std::env::var("OLD_CYCLE_STATS").unwrap_or_else(|_| "../old_cycle_stats.json".to_string());
    let new_path =
        std::env::var("NEW_CYCLE_STATS").unwrap_or_else(|_| "../new_cycle_stats.json".to_string());

    let old_cycle_stats = std::fs::read_to_string(&old_path).unwrap();
    let new_cycle_stats = std::fs::read_to_string(&new_path).unwrap();

    let old_cycle_stats: Vec<BenchEntry> = serde_json::from_str(&old_cycle_stats).unwrap();
    let new_cycle_stats: Vec<BenchEntry> = serde_json::from_str(&new_cycle_stats).unwrap();

    let comparison = pretty_comparison(old_cycle_stats, new_cycle_stats).unwrap();

    println!("{comparison}");
}
