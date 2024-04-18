use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

pub struct StageProgressBar {
    pb: ProgressBar,
    current_stage: u32,
    current_stage_name: String,
    total_stages: String,
}

impl StageProgressBar {
    pub fn new() -> Self {
        let pb = ProgressBar::new(1);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.green}")
                .unwrap()
                .progress_chars("#>-")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
        );
        pb.enable_steady_tick(Duration::from_millis(50));

        let mp = MultiProgress::new();
        let pb = mp.add(pb);

        Self {
            pb,
            current_stage: 0,
            current_stage_name: "Starting".to_string(),
            total_stages: "?".to_string(),
        }
    }

    pub fn update(
        &mut self,
        stage: u32,
        total_stages: u32,
        stage_name: &str,
        stage_progress: Option<(u32, u32)>,
    ) {
        if stage > self.current_stage {
            self.pb.set_position(0);
            self.pb.reset_eta();
        }
        if let Some(progress) = stage_progress {
            self.pb.set_position(progress.0.into());
            self.pb.set_length(progress.1.into());
            self.pb.set_style(
                ProgressStyle::with_template("\n{msg}\n{spinner:.green} [{elapsed}] [{wide_bar:.cyan/blue}] {pos}/{len} (eta {eta})")
                    .unwrap()
                    .progress_chars("#>-")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
            );
        } else {
            self.pb.set_style(
                ProgressStyle::with_template("\n{msg}\n{spinner:.green} [{elapsed}]")
                    .unwrap()
                    .progress_chars("#>-")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
            );
        }

        self.current_stage = stage;
        self.total_stages = total_stages.to_string();
        self.current_stage_name = stage_name.to_string();
        self.pb
            .set_message(format!("[{}/{}] {}", stage, total_stages, stage_name));
    }

    pub fn finish(&mut self) {
        self.pb.finish_and_clear();
    }
}
