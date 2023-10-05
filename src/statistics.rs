use std::time::SystemTime;
use std::fmt::{Display, Formatter, Result};

#[derive(Debug)]
pub struct AcmeStatistics {
    pub started: SystemTime,
    pub ended: Option<SystemTime>,
    pub items: Vec<AcmeItem>,
}

#[derive(Debug)]
pub enum AcmeStatus {
    Success,
    // Skipped,
    Fail(String),
}

impl Display for AcmeStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            AcmeStatus::Success => write!(f, "Success"),
            AcmeStatus::Fail(message) => write!(f, "Failed: {}", message),
        }
    }
}

#[derive(Debug)]
pub struct AcmeItem {
    pub domains: Vec<String>,
    pub status: AcmeStatus,
}

impl Display for AcmeItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "Domains: {}; {}", self.domains.join(", "), &self.status)
    }
}

impl Display for AcmeStatistics {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut sb = String::with_capacity(512);
        let df = simpledateformat::fmt("yyyy-MM-dd HH:mm:ss z").unwrap();
        let started_time = df.format_local(self.started.clone());
        sb.push_str(&format!("Started: {}", &started_time));
        if let Some(ended) = &self.ended {
            let ended_time = df.format_local(ended.clone());
            sb.push_str(&format!("\nEnded: {}", &ended_time));
            let cost_result = ended.duration_since(self.started);
            if let Ok(cost) = cost_result {
                sb.push_str(&format!(", cost: {}", simpledateformat::format_human(cost)));
            }
        }
        let mut success_count: i32 = 0;
        let mut failed_count: i32 = 0;
        for item in &self.items {
            match &item.status {
                AcmeStatus::Success => {
                    success_count += 1;
                }
                AcmeStatus::Fail(_) => {
                    failed_count += 1;
                    sb.push_str(&format!("\n - {}", &item));
                }
            }
        }
        sb.push_str(&format!("\nTotal count: {}, success count: {}, failed count: {}",
                             success_count + failed_count,
                             success_count,
                             failed_count,
        ));
        write!(f, "{}", &sb)
    }
}

impl AcmeStatistics {
    pub fn start() -> AcmeStatistics {
        AcmeStatistics {
            started: SystemTime::now(),
            ended: None,
            items: Vec::new(),
        }
    }

    pub fn end(&mut self) {
        self.ended = Some(SystemTime::now());
    }

    pub fn add_item(&mut self, domains: Vec<String>, status: AcmeStatus) {
        self.items.push(AcmeItem {
            domains,
            status,
        });
    }
}