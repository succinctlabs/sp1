use sp1_test::{
    utils::{post_to_github_pr_sync, pretty_comparison},
    BenchEntry,
};

fn normalize_pr_number(pr_number: Option<String>) -> Option<String> {
    pr_number.and_then(|pr_number| {
        let pr_number = pr_number.trim();
        (!pr_number.is_empty()).then(|| pr_number.to_string())
    })
}

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

    let Some(pr_number) = normalize_pr_number(std::env::var("PR_NUMBER").ok()) else {
        eprintln!("PR_NUMBER is missing or empty; skipping PR comment.");
        return;
    };
    let token = std::env::var("GITHUB_TOKEN").unwrap();
    let github_repo = std::env::var("GITHUB_REPOSITORY").unwrap();
    let (owner, repo) = github_repo.split_once('/').unwrap();

    post_to_github_pr_sync(owner, repo, &pr_number, &token, &comparison).unwrap();
}

#[cfg(test)]
mod tests {
    use super::normalize_pr_number;

    #[test]
    fn normalize_pr_number_rejects_missing_value() {
        assert_eq!(normalize_pr_number(None), None);
    }

    #[test]
    fn normalize_pr_number_rejects_whitespace_only_value() {
        assert_eq!(normalize_pr_number(Some("   ".to_string())), None);
    }

    #[test]
    fn normalize_pr_number_keeps_trimmed_pr_number() {
        assert_eq!(normalize_pr_number(Some(" 2821 ".to_string())), Some("2821".to_string()));
    }
}
