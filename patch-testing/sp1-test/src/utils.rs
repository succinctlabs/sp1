use crate::BenchEntry;
use reqwest::Client;
use serde_json::json;
use std::{collections::HashMap, fmt::Write};

pub fn post_to_github_pr_sync(
    owner: &str,
    repo: &str,
    pr_number: &str,
    token: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(post_to_github_pr(owner, repo, pr_number, token, message))
}

/// Posts the provided message on the provided PR on Github.
pub async fn post_to_github_pr(
    owner: &str,
    repo: &str,
    pr_number: &str,
    token: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let base_url = format!("https://api.github.com/repos/{owner}/{repo}");

    // Get all comments on the PR.
    let comments_url = format!("{base_url}/issues/{pr_number}/comments");
    let comments_response = client
        .get(&comments_url)
        .header("Authorization", format!("token {token}",))
        .header("User-Agent", "sp1-perf-bot")
        .send()
        .await?;

    let comments: Vec<serde_json::Value> = comments_response.json().await?;

    // Look for an existing comment from our bot.
    let bot_comment = comments.iter().find(|comment| {
        comment["user"]["login"]
            .as_str()
            .map(|login| login == "github-actions[bot]")
            .unwrap_or(false)
    });

    if let Some(existing_comment) = bot_comment {
        // Update the existing comment.
        let comment_url = existing_comment["url"].as_str().unwrap();
        let response = client
            .patch(comment_url)
            .header("Authorization", format!("token {token}"))
            .header("User-Agent", "sp1-perf-bot")
            .json(&json!({
                "body": message
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to update comment: {:?}", response.text().await?).into());
        }
    } else {
        // Create a new comment.
        let response = client
            .post(&comments_url)
            .header("Authorization", format!("token {token}"))
            .header("User-Agent", "sp1-perf-bot")
            .json(&json!({
                "body": message
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to post comment: {:?}", response.text().await?).into());
        }
    }

    Ok(())
}

pub fn pretty_comparison(
    old: Vec<BenchEntry>,
    new: Vec<BenchEntry>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::new();

    writeln!(output, "| {:<50} | {:<25} | {:<25} | {:<25} |", "Test", "Old", "New", "Diff")?;
    writeln!(output, "|----------------------------------------------------|---------------------------|---------------------------|---------------------------|")?;

    let mut organized = HashMap::<String, (u64, u64)>::new();

    for entry in old {
        organized.insert(entry.name, (entry.cycles, 0));
    }

    for entry in new {
        organized
            .entry(entry.name)
            .and_modify(|(_, new)| *new = entry.cycles)
            .or_insert((0, entry.cycles));
    }

    for (name, (old, new)) in organized {
        writeln!(
            output,
            "| {:<50} | {:<25} | {:<25} | {:<25.4}% |",
            name,
            old,
            new,
            ((new as f64 - old as f64) / old as f64) * 100.0
        )?;
    }

    Ok(output)
}
