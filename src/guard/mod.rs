pub mod circuit_breaker;
pub mod config;
pub mod hitl;
pub mod policy;
pub mod rollback;
pub mod tool_router;

/// Safely truncates a string to at most `max_chars` UTF-8 codepoints without ever panicking
/// on multi-byte character boundaries. Appends "..." if truncated.
pub fn safe_truncate(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let mut truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        truncated.push_str("...");
    }
    truncated
}
