use crate::guard::config::CircuitBreakerConfig;
use serde_json::Value;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitBreakerTrip {
    RateLimitExceeded {
        count: usize,
        limit: usize,
        window_secs: u64,
    },
    RepetitionLoopDetected {
        tool: String,
        consecutive_calls: usize,
    },
}

impl CircuitBreakerTrip {
    pub fn message(&self) -> String {
        match self {
            Self::RateLimitExceeded { count, limit, window_secs } => {
                format!(
                    "Runaway Agent Circuit Breaker: Rate limit exceeded ({} calls in {}s, limit: {}).",
                    count, window_secs, limit
                )
            }
            Self::RepetitionLoopDetected { tool, consecutive_calls } => {
                format!(
                    "Runaway Agent Circuit Breaker: {} identical consecutive calls to tool '{}' detected.",
                    consecutive_calls, tool
                )
            }
        }
    }
}

#[derive(Debug)]
pub struct CircuitBreaker {
    call_timestamps: VecDeque<Instant>,
    max_calls_per_minute: usize,
    max_identical_consecutive_calls: usize,
    window_duration: Duration,
    last_tool: Option<String>,
    last_arguments: Option<String>,
    consecutive_count: usize,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(None)
    }
}

impl CircuitBreaker {
    pub fn new(config: Option<&CircuitBreakerConfig>) -> Self {
        let max_calls = config
            .and_then(|c| c.max_calls_per_minute)
            .unwrap_or(30);

        let max_consecutive = config
            .and_then(|c| c.max_identical_consecutive_calls)
            .unwrap_or(3);

        Self {
            call_timestamps: VecDeque::new(),
            max_calls_per_minute: max_calls,
            max_identical_consecutive_calls: max_consecutive,
            window_duration: Duration::from_secs(60),
            last_tool: None,
            last_arguments: None,
            consecutive_count: 0,
        }
    }

    /// Evaluates if the current tool call trips rate limits or repetition loops.
    /// If tripped, returns Err(CircuitBreakerTrip).
    pub fn check_and_record(
        &mut self,
        tool: &str,
        arguments: &Value,
    ) -> Result<(), CircuitBreakerTrip> {
        let now = Instant::now();

        // 1. Evict timestamps outside the 60s sliding window
        while let Some(&ts) = self.call_timestamps.front() {
            if now.saturating_duration_since(ts) > self.window_duration {
                self.call_timestamps.pop_front();
            } else {
                break;
            }
        }

        // 2. Check Rate Limit
        if self.call_timestamps.len() >= self.max_calls_per_minute {
            return Err(CircuitBreakerTrip::RateLimitExceeded {
                count: self.call_timestamps.len() + 1,
                limit: self.max_calls_per_minute,
                window_secs: self.window_duration.as_secs(),
            });
        }

        // 3. Check Repetition Loop
        let args_str = serde_json::to_string(arguments).unwrap_or_default();
        if self.last_tool.as_deref() == Some(tool) && self.last_arguments.as_deref() == Some(&args_str) {
            self.consecutive_count += 1;
            if self.consecutive_count >= self.max_identical_consecutive_calls {
                return Err(CircuitBreakerTrip::RepetitionLoopDetected {
                    tool: tool.to_string(),
                    consecutive_calls: self.consecutive_count,
                });
            }
        } else {
            self.last_tool = Some(tool.to_string());
            self.last_arguments = Some(args_str);
            self.consecutive_count = 1;
        }

        // Record timestamp for rate limiting
        self.call_timestamps.push_back(now);

        Ok(())
    }

    /// Resets consecutive counter (e.g. after human manual approval or new user turn)
    pub fn reset_consecutive(&mut self) {
        self.consecutive_count = 0;
        self.last_tool = None;
        self.last_arguments = None;
    }
}
