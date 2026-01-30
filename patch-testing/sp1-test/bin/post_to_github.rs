use sp1_test::{
    utils::{post_to_github_pr_sync, pretty_comparison},
    BenchEntry,
};

pub fn main() {
    let old_cycle_stats = std::fs::read_to_string("old_cycle_stats.json").unwrap();
    let new_cycle_stats = std::fs::read_to_string("new_cycle_stats.json").unwrap();

    let old_cycle_stats: Vec<BenchEntry> = serde_json::from_str(&old_cycle_stats).unwrap();
    let new_cycle_stats: Vec<BenchEntry> = serde_json::from_str(&new_cycle_stats).unwrap();

    let comparison = pretty_comparison(old_cycle_stats, new_cycle_stats).unwrap();

    println!("{comparison}");

    let pr_number = std::env::var("PR_NUMBER").unwrap();
    let token = std::env::var("GITHUB_TOKEN").unwrap();
    let github_repo = std::env::var("GITHUB_REPOSITORY").unwrap();
    let (owner, repo) = github_repo.split_once('/').unwrap();

    post_to_github_pr_sync(owner, repo, &pr_number, &token, &comparison).unwrap();
}
