use crate::guard::config::ProjectConfig;
use serde_json::Value;

pub struct ToolRouter {
    config: ProjectConfig,
}

impl ToolRouter {
    pub fn new(config: ProjectConfig) -> Self {
        Self { config }
    }

    /// Checks if a JSON-RPC message is a `tools/list` response
    pub fn is_tools_list_response(val: &Value) -> bool {
        val.get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .is_some()
    }

    /// Transforms and minifies a `tools/list` response, returning (modified_value, original_size, new_size)
    pub fn process_tools_list_response(&self, mut val: Value) -> (Value, usize, usize) {
        let original_str = val.to_string();
        let original_size = original_str.len();

        let router_config = self.config.tool_router.clone().unwrap_or_default();
        let minify_enabled = router_config.minify_schemas.unwrap_or(true);
        let allowed = &router_config.allowed_tools;
        let excluded = &router_config.excluded_tools;

        if let Some(result) = val.get_mut("result") {
            if let Some(tools_val) = result.get_mut("tools") {
                if let Some(tools_arr) = tools_val.as_array_mut() {
                    // 1. Tool Filtering
                    tools_arr.retain(|t| {
                        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        if !allowed.is_empty() && !allowed.iter().any(|a| a == name) {
                            return false;
                        }
                        if excluded.iter().any(|e| e == name) {
                            return false;
                        }
                        true
                    });

                    // 2. Schema Minification
                    if minify_enabled {
                        for tool in tools_arr.iter_mut() {
                            Self::minify_single_tool(tool);
                        }
                    }
                }
            }
        }

        let new_size = val.to_string().len();
        (val, original_size, new_size)
    }

    fn minify_single_tool(tool: &mut Value) {
        // Compress tool description
        if let Some(desc_val) = tool.get_mut("description") {
            if let Some(desc_str) = desc_val.as_str() {
                let compressed = Self::compress_description(desc_str, 160);
                *desc_val = Value::String(compressed);
            }
        }

        // Minify inputSchema
        if let Some(schema) = tool.get_mut("inputSchema") {
            if let Some(schema_obj) = schema.as_object_mut() {
                // Remove redundant top-level schema metadata
                schema_obj.remove("$schema");
                schema_obj.remove("title");

                // Compress parameter descriptions
                if let Some(props) = schema_obj.get_mut("properties") {
                    if let Some(props_obj) = props.as_object_mut() {
                        for (_, prop_val) in props_obj.iter_mut() {
                            if let Some(prop_map) = prop_val.as_object_mut() {
                                if let Some(p_desc) = prop_map.get_mut("description") {
                                    if let Some(p_str) = p_desc.as_str() {
                                        *p_desc = Value::String(Self::compress_description(p_str, 80));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn compress_description(input: &str, max_len: usize) -> String {
        // 1. Take first sentence or first non-empty line
        let first_line = input.lines().find(|l| !l.trim().is_empty()).unwrap_or(input);
        let first_sentence = if let Some(idx) = first_line.find(". ") {
            &first_line[..idx + 1]
        } else {
            first_line
        };

        // 2. Strip markdown headers and bolding
        let clean = first_sentence
            .trim_start_matches('#')
            .replace("**", "")
            .replace("__", "")
            .replace('`', "");

        crate::guard::safe_truncate(clean.trim(), max_len)
    }
}
