use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ParsedMessage {
    ToolCall {
        id: Value,
        tool_name: String,
        arguments: Value,
        raw_json: Value,
    },
    Batch(Vec<ParsedMessage>),
    Other(Value),
    Invalid(String),
}

impl ParsedMessage {
    pub fn parse(line: &str) -> Self {
        let mut trimmed = line.trim();
        // Strip UTF-8 Byte Order Mark (BOM) if present to prevent parser bypass
        if let Some(stripped) = trimmed.strip_prefix('\u{FEFF}') {
            trimmed = stripped;
        }

        if trimmed.is_empty() {
            return ParsedMessage::Invalid(line.to_string());
        }

        let val: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return ParsedMessage::Invalid(line.to_string()),
        };

        Self::from_value(val)
    }

    pub fn from_value(val: Value) -> Self {
        // Handle JSON-RPC 2.0 Batch Arrays
        if let Some(arr) = val.as_array() {
            if arr.is_empty() {
                return ParsedMessage::Other(val);
            }
            let messages: Vec<ParsedMessage> = arr.iter().cloned().map(Self::from_value).collect();
            return ParsedMessage::Batch(messages);
        }

        if let (Some(method), Some(params)) = (val.get("method").and_then(|m| m.as_str()), val.get("params")) {
            if method == "tools/call" {
                let id = val.get("id").cloned().unwrap_or(Value::Null);
                let tool_name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

                return ParsedMessage::ToolCall {
                    id,
                    tool_name,
                    arguments,
                    raw_json: val,
                };
            }
        }

        ParsedMessage::Other(val)
    }

    pub fn make_error_response(id: &Value, code: i64, message: &str) -> String {
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        });
        format!("{}\n", response)
    }

    pub fn make_batch_error_response(errors: &[(&Value, i64, &str)]) -> String {
        let responses: Vec<Value> = errors
            .iter()
            .map(|(id, code, msg)| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": code,
                        "message": msg
                    }
                })
            })
            .collect();
        format!("{}\n", Value::Array(responses))
    }
}
