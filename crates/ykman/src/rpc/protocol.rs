use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_json::value::RawValue;
use yubikit::__internal::SecretValue;

pub const RPC_PROTOCOL_VERSION: &str = "0.1";

pub fn rpc_protocol_version_parts(version: &str) -> Option<(u16, u16)> {
    let (major, minor) = version.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Opaque JSON stored as zeroizing text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawJson(SecretValue<String>);

impl RawJson {
    pub fn empty_object() -> Self {
        Self(SecretValue::new("{}".to_string()))
    }

    pub fn from_value(value: Value) -> Result<Self, serde_json::Error> {
        serde_json::to_string(&value).and_then(Self::from_string)
    }

    pub fn from_string(raw: String) -> Result<Self, serde_json::Error> {
        RawValue::from_string(raw.clone())?;
        Ok(Self(SecretValue::new(raw)))
    }

    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }

    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_str(self.as_str())
    }
}

impl Default for RawJson {
    fn default() -> Self {
        Self::empty_object()
    }
}

impl Serialize for RawJson {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw =
            RawValue::from_string(self.as_str().to_string()).map_err(serde::ser::Error::custom)?;
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RawJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum ClientMessage {
    Command(CommandMessage),
    Signal(SignalMessage),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandMessage {
    pub action: String,
    #[serde(default)]
    pub target: Vec<String>,
    #[serde(default)]
    pub body: RawJson,
}

impl CommandMessage {
    pub fn new(
        action: &str,
        target: &[impl AsRef<str>],
        body: Value,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            action: action.to_string(),
            target: target.iter().map(|s| s.as_ref().to_string()).collect(),
            body: RawJson::from_value(body)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalMessage {
    pub status: String,
    #[serde(default)]
    pub body: RawJson,
}

impl SignalMessage {
    pub fn new(status: impl Into<String>, body: Value) -> Result<Self, serde_json::Error> {
        Ok(Self {
            status: status.into(),
            body: RawJson::from_value(body)?,
        })
    }

    pub fn cancel() -> Self {
        Self {
            status: "cancel".to_string(),
            body: RawJson::empty_object(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum ServerMessage {
    Success(SuccessMessage),
    Error(ErrorMessage),
    Signal(SignalMessage),
}

impl ServerMessage {
    pub fn success(body: Value, flags: Vec<String>) -> Result<Self, serde_json::Error> {
        Ok(Self::Success(SuccessMessage {
            body: RawJson::from_value(body)?,
            flags,
        }))
    }

    pub fn error(
        status: impl Into<String>,
        message: impl Into<String>,
        body: Value,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self::Error(ErrorMessage {
            status: status.into(),
            message: message.into(),
            body: RawJson::from_value(body)?,
        }))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessMessage {
    pub body: RawJson,
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorMessage {
    pub status: String,
    pub message: String,
    #[serde(default)]
    pub body: RawJson,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rpc_protocol_version_parses() {
        assert_eq!(
            rpc_protocol_version_parts(RPC_PROTOCOL_VERSION),
            Some((0, 1))
        );
        assert_eq!(rpc_protocol_version_parts("1"), None);
        assert_eq!(rpc_protocol_version_parts("1.x"), None);
    }

    #[test]
    fn command_body_round_trips_as_raw_json() {
        let message = ClientMessage::Command(
            CommandMessage::new(
                "call",
                &["device", "ctap"],
                json!({"cmd": 1, "data": "abcd"}),
            )
            .unwrap(),
        );

        let encoded = serde_json::to_string(&message).unwrap();
        assert_eq!(
            encoded,
            r#"{"kind":"command","action":"call","target":["device","ctap"],"body":{"cmd":1,"data":"abcd"}}"#
        );

        let decoded: ClientMessage = serde_json::from_str(&encoded).unwrap();
        let ClientMessage::Command(command) = decoded else {
            panic!("expected command");
        };
        assert_eq!(command.action, "call");
        assert_eq!(
            command.target,
            vec!["device".to_string(), "ctap".to_string()]
        );
        assert_eq!(
            command.body.to_value().unwrap(),
            json!({"cmd": 1, "data": "abcd"})
        );
    }

    #[test]
    fn command_rejects_unknown_fields() {
        let err = serde_json::from_str::<ClientMessage>(
            r#"{"kind":"command","action":"get","target":[],"body":{},"extra":true}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn success_defaults_missing_flags() {
        let decoded: ServerMessage =
            serde_json::from_str(r#"{"kind":"success","body":{"ok":true}}"#).unwrap();
        let ServerMessage::Success(success) = decoded else {
            panic!("expected success");
        };
        assert!(success.flags.is_empty());
        assert_eq!(success.body.to_value().unwrap(), json!({"ok": true}));
    }
}
