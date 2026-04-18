use serde_json::Value;

/// An RPC response — body + optional flags.
pub struct RpcResponse {
    pub body: Value,
    pub flags: Vec<String>,
}

impl RpcResponse {
    pub fn new(body: Value) -> Self {
        Self {
            body,
            flags: vec![],
        }
    }

    pub fn with_flags(body: Value, flags: Vec<&str>) -> Self {
        Self {
            body,
            flags: flags.into_iter().map(String::from).collect(),
        }
    }
}

/// An RPC error returned as the result of a command.
#[derive(Debug)]
pub struct RpcError {
    pub status: String,
    pub message: String,
    pub body: Value,
}

impl RpcError {
    pub fn new(status: &str, message: impl Into<String>) -> Self {
        Self {
            status: status.to_string(),
            message: message.into(),
            body: serde_json::json!({}),
        }
    }

    pub fn with_body(status: &str, message: impl Into<String>, body: Value) -> Self {
        Self {
            status: status.to_string(),
            message: message.into(),
            body,
        }
    }

    pub fn invalid_command(message: impl Into<String>) -> Self {
        Self::new("invalid-command", message)
    }

    pub fn no_such_action(name: &str) -> Self {
        Self::invalid_command(format!("No such action: {name}"))
    }

    pub fn no_such_node(name: &str) -> Self {
        Self::invalid_command(format!("No such node: {name}"))
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::invalid_command(format!("Invalid parameters: {}", message.into()))
    }

    pub fn state_reset(message: &str, path: Vec<String>) -> Self {
        Self::with_body(
            "state-reset",
            if message.is_empty() {
                "State reset in node"
            } else {
                message
            },
            serde_json::json!({ "path": path }),
        )
    }

    pub fn timeout() -> Self {
        Self::new(
            "user-action-timeout",
            "Failed action due to user inactivity.",
        )
    }

    pub fn auth_required() -> Self {
        Self::new("auth-required", "Authentication is required")
    }

    pub fn pin_complexity() -> Self {
        Self::new(
            "pin-complexity",
            "PIN does not meet complexity requirements",
        )
    }

    pub fn connection_error(device: &str, connection: &str, exc_type: &str) -> Self {
        Self::with_body(
            "connection-error",
            format!("Error connecting to {connection} interface"),
            serde_json::json!({
                "device": device,
                "connection": connection,
                "exc_type": exc_type,
            }),
        )
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for RpcError {}

/// Internal exception to signal that a child node must be closed
/// and a state-reset error raised with path tracking.
#[derive(Debug)]
pub struct ChildResetException {
    pub message: String,
}

/// Secret store state.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStore {
    Unknown,
    Allowed,
    Failed,
}

impl SecretStore {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Allowed => "allowed",
            Self::Failed => "failed",
        }
    }
}

impl serde::Serialize for SecretStore {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
