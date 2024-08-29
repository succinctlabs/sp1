use anyhow::Result;
use clap::{command, Parser};
use reqwest::Client;
use serde::Serialize;
use serde_json::json;
use slack_rust::chat::post_message::{post_message, PostMessageRequest};
use slack_rust::http_client::default_client;
use sp1_prover::{components::SP1ProverComponents, utils::get_cycles, SP1Prover};
use sp1_sdk::SP1Context;
use sp1_stark::SP1ProverOpts;
use std::time::{Duration, Instant};

use program::load_program;

use crate::program::{TesterProgram, PROGRAMS};

mod program;

#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
struct EvalArgs {
    /// The programs to evaluate, specified by name. If not specified, all programs will be evaluated.
    #[arg(long, use_value_delimiter = true, value_delimiter = ',')]
    pub programs: Vec<String>,

    /// The shard size to use for the prover.
    #[arg(long)]
    pub shard_size: Option<usize>,

    /// Whether to post results to Slack.
    #[arg(long, default_missing_value="true", num_args=0..=1)]
    pub post_to_slack: Option<bool>,

    /// The Slack channel ID to post results to, only used if post_to_slack is true.
    #[arg(long)]
    pub slack_channel_id: Option<String>,

    /// The Slack bot token to post results to, only used if post_to_slack is true.
    #[arg(long)]
    pub slack_token: Option<String>,

    /// Whether to post results to GitHub PR.
    #[arg(long, default_missing_value="true", num_args=0..=1)]
    pub post_to_github: Option<bool>,

    /// The GitHub token for authentication, only used if post_to_github is true.
    #[arg(long)]
    pub github_token: Option<String>,

    /// The GitHub repository owner.
    #[arg(long)]
    pub repo_owner: Option<String>,

    /// The GitHub repository name.
    #[arg(long)]
    pub repo_name: Option<String>,

    /// The GitHub PR number.
    #[arg(long)]
    pub pr_number: Option<String>,

    /// The name of the pull request.
    #[arg(long)]
    pub pr_name: Option<String>,

    /// The name of the branch.
    #[arg(long)]
    pub branch_name: Option<String>,

    /// The commit hash.
    #[arg(long)]
    pub commit_hash: Option<String>,

    /// The author of the commit.
    #[arg(long)]
    pub author: Option<String>,
}

pub async fn evaluate_performance<C: SP1ProverComponents>() -> Result<(), Box<dyn std::error::Error>>
{
    let args = EvalArgs::parse();

    // Set environment variables to configure the prover.
    if let Some(shard_size) = args.shard_size {
        std::env::set_var("SHARD_SIZE", format!("{}", 1 << shard_size));
    }

    // Choose which programs to evaluate.
    let programs: Vec<&TesterProgram> = if args.programs.is_empty() {
        PROGRAMS.iter().collect()
    } else {
        PROGRAMS
            .iter()
            .filter(|p| args.programs.iter().any(|arg| arg.eq_ignore_ascii_case(p.name)))
            .collect()
    };

    // Run the evaluations on each program.
    let mut reports = Vec::new();
    for program in &programs {
        println!("Evaluating program: {}", program.name);
        let report = run_evaluation::<C>(program.name, program.elf, program.input);
        reports.push(report);
        println!("Program: {} completed", program.name);
    }

    // Prepare and format the results.
    let reports_len = reports.len();
    let success_count = reports.iter().filter(|r| r.success).count();
    let results_text = format_results(&args, &reports);

    // Print results
    println!("{}", results_text.join("\n"));

    // Post to Slack if applicable
    if args.post_to_slack.unwrap_or(false) {
        match (&args.slack_token, &args.slack_channel_id) {
            (Some(token), Some(channel)) => {
                for message in &results_text {
                    post_to_slack(token, channel, message).await?;
                }
            }
            _ => println!("Warning: post_to_slack is true, required Slack arguments are missing."),
        }
    }

    // Post to GitHub PR if applicable
    if args.post_to_github.unwrap_or(false) {
        match (&args.repo_owner, &args.repo_name, &args.pr_number, &args.github_token) {
            (Some(owner), Some(repo), Some(pr_number), Some(token)) => {
                let message = format_github_message(&results_text);
                post_to_github_pr(owner, repo, pr_number, token, &message).await?;
            }
            _ => {
                println!("Warning: post_to_github is true, required GitHub arguments are missing.")
            }
        }
    }

    // Exit with an error if any programs failed.
    let all_successful = success_count == reports_len;
    if !all_successful {
        println!("Some programs failed. Please check the results above.");
        std::process::exit(1);
    }

    Ok(())
}

#[derive(Debug, Serialize)]
pub struct PerformanceReport {
    program: String,
    cycles: u64,
    exec_khz: f64,
    core_khz: f64,
    compressed_khz: f64,
    time: f64,
    success: bool,
}

fn run_evaluation<C: SP1ProverComponents>(
    program_name: &str,
    elf_path: &str,
    input_path: &str,
) -> PerformanceReport {
    let (elf, stdin) = load_program(elf_path, input_path);
    let cycles = get_cycles(&elf, &stdin);

    let prover = SP1Prover::<C>::new();
    let (pk, vk) = prover.setup(&elf);

    let opts = SP1ProverOpts::default();
    let context = SP1Context::default();

    let (_, exec_duration) = time_operation(|| prover.execute(&elf, &stdin, context.clone()));

    let (core_proof, core_duration) =
        time_operation(|| prover.prove_core(&pk, &stdin, opts, context).unwrap());

    let (_, compress_duration) =
        time_operation(|| prover.compress(&vk, core_proof, vec![], opts).unwrap());

    let total_duration = exec_duration + core_duration + compress_duration;

    PerformanceReport {
        program: program_name.to_string(),
        cycles,
        exec_khz: calculate_khz(cycles, exec_duration),
        core_khz: calculate_khz(cycles, core_duration),
        compressed_khz: calculate_khz(cycles, compress_duration),
        time: total_duration.as_secs_f64(),
        success: true,
    }
}

fn format_results(args: &EvalArgs, results: &[PerformanceReport]) -> Vec<String> {
    let mut detail_text = String::new();
    if let Some(pr_name) = &args.pr_name {
        detail_text.push_str(&format!("*PR*: {}\n", pr_name));
    }
    if let Some(branch_name) = &args.branch_name {
        detail_text.push_str(&format!("*Branch*: {}\n", branch_name));
    }
    if let Some(commit_hash) = &args.commit_hash {
        detail_text.push_str(&format!("*Commit*: {}\n", &commit_hash[..8]));
    }
    if let Some(author) = &args.author {
        detail_text.push_str(&format!("*Author*: {}\n", author));
    }

    let mut table_text = String::new();
    table_text.push_str("```\n");
    table_text.push_str("| program           | cycles      | execute (mHz)  | core (kHZ)     | compress (KHz) | time   | success  |\n");
    table_text.push_str("|-------------------|-------------|----------------|----------------|----------------|--------|----------|");

    for result in results.iter() {
        table_text.push_str(&format!(
            "\n| {:<17} | {:>11} | {:>14.2} | {:>14.2} | {:>14.2} | {:>6} | {:<7} |",
            result.program,
            result.cycles,
            result.exec_khz / 1000.0,
            result.core_khz,
            result.compressed_khz,
            format_duration(result.time),
            if result.success { "✅" } else { "❌" }
        ));
    }
    table_text.push_str("\n```");

    vec!["*SP1 Performance Test Results*\n".to_string(), detail_text, table_text]
}

pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

fn calculate_khz(cycles: u64, duration: Duration) -> f64 {
    let duration_secs = duration.as_secs_f64();
    if duration_secs > 0.0 {
        (cycles as f64 / duration_secs) / 1_000.0
    } else {
        0.0
    }
}

fn format_duration(duration: f64) -> String {
    let secs = duration.round() as u64;
    let minutes = secs / 60;
    let seconds = secs % 60;

    if minutes > 0 {
        format!("{}m{}s", minutes, seconds)
    } else if seconds > 0 {
        format!("{}s", seconds)
    } else {
        format!("{}ms", (duration * 1000.0).round() as u64)
    }
}

async fn post_to_slack(slack_token: &str, slack_channel_id: &str, message: &str) -> Result<()> {
    let slack_api_client = default_client();
    let request = PostMessageRequest {
        channel: slack_channel_id.to_string(),
        text: Some(message.to_string()),
        ..Default::default()
    };

    post_message(&slack_api_client, &request, slack_token).await.expect("slack api call error");

    Ok(())
}

fn format_github_message(results_text: &[String]) -> String {
    let mut formatted_message = String::new();

    if let Some(title) = results_text.first() {
        // Add an extra asterisk for GitHub bold formatting
        formatted_message.push_str(&title.replace('*', "**"));
        formatted_message.push('\n');
    }

    if let Some(details) = results_text.get(1) {
        // Add an extra asterisk for GitHub bold formatting
        formatted_message.push_str(&details.replace('*', "**"));
        formatted_message.push('\n');
    }

    if let Some(table) = results_text.get(2) {
        // Remove the triple backticks as GitHub doesn't require them for table formatting
        let cleaned_table = table.trim_start_matches("```").trim_end_matches("```");
        formatted_message.push_str(cleaned_table);
    }

    formatted_message
}

async fn post_to_github_pr(
    owner: &str,
    repo: &str,
    pr_number: &str,
    token: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let base_url = format!("https://api.github.com/repos/{}/{}", owner, repo);

    // Get all comments on the PR
    let comments_url = format!("{}/issues/{}/comments", base_url, pr_number);
    let comments_response = client
        .get(&comments_url)
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "sp1-perf-bot")
        .send()
        .await?;

    let comments: Vec<serde_json::Value> = comments_response.json().await?;

    // Look for an existing comment from our bot
    let bot_comment = comments.iter().find(|comment| {
        comment["user"]["login"]
            .as_str()
            .map(|login| login == "github-actions[bot]")
            .unwrap_or(false)
    });

    if let Some(existing_comment) = bot_comment {
        // Update the existing comment
        let comment_url = existing_comment["url"].as_str().unwrap();
        let response = client
            .patch(comment_url)
            .header("Authorization", format!("token {}", token))
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
        // Create a new comment
        let response = client
            .post(&comments_url)
            .header("Authorization", format!("token {}", token))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_results() {
        let dummy_reports = vec![
            PerformanceReport {
                program: "fibonacci".to_string(),
                cycles: 11291,
                exec_khz: 29290.0,
                core_khz: 30.0,
                compressed_khz: 0.1,
                time: 622.385,
                success: true,
            },
            PerformanceReport {
                program: "super-program".to_string(),
                cycles: 275735600,
                exec_khz: 70190.0,
                core_khz: 310.0,
                compressed_khz: 120.0,
                time: 812.285,
                success: true,
            },
        ];

        let args = EvalArgs {
            programs: vec!["fibonacci".to_string(), "super-program".to_string()],
            shard_size: None,
            post_to_slack: Some(false),
            slack_channel_id: None,
            slack_token: None,
            post_to_github: Some(true),
            github_token: Some("abcdef1234567890".to_string()),
            repo_owner: Some("succinctlabs".to_string()),
            repo_name: Some("sp1".to_string()),
            pr_number: Some("123456".to_string()),
            pr_name: Some("Test PR".to_string()),
            branch_name: Some("feature-branch".to_string()),
            commit_hash: Some("abcdef1234567890".to_string()),
            author: Some("John Doe".to_string()),
        };

        let formatted_results = format_results(&args, &dummy_reports);

        for line in &formatted_results {
            println!("{}", line);
        }

        assert_eq!(formatted_results.len(), 3);
        assert!(formatted_results[0].contains("SP1 Performance Test Results"));
        assert!(formatted_results[1].contains("*PR*: Test PR"));
        assert!(formatted_results[1].contains("*Branch*: feature-branch"));
        assert!(formatted_results[1].contains("*Commit*: abcdef12"));
        assert!(formatted_results[1].contains("*Author*: John Doe"));
        assert!(formatted_results[2].contains("fibonacci"));
        assert!(formatted_results[2].contains("super-program"));
    }
}
