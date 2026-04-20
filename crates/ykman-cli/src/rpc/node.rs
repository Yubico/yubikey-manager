use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

use serde_json::{Value, json};

use super::error::{ChildResetException, RpcError, RpcResponse};

/// Signal callback type.
pub type SignalFn<'a> = &'a dyn Fn(&str, Value);

/// Trait for an RPC node in the tree.
pub trait RpcNode {
    /// Get node-specific data (returned in the `get` action).
    fn get_data(&self) -> Value {
        json!({})
    }

    /// List available actions on this node.
    fn list_actions(&self) -> Vec<&'static str> {
        vec![]
    }

    /// List available children with their metadata.
    fn list_children(&mut self) -> BTreeMap<String, Value> {
        BTreeMap::new()
    }

    /// Execute an action on this node.
    fn call_action(
        &mut self,
        action: &str,
        params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError>;

    /// Create a child node by name.
    fn create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        Err(RpcError::no_such_node(name))
    }

    /// Close this node and release resources.
    fn close(&mut self) {}

    /// Whether `closes_child` should be set for a specific action.
    /// Default is true for all actions.
    fn action_closes_child(&self, _action: &str) -> bool {
        true
    }

    /// Whether this node keeps all children alive when switching between them.
    /// When true, children are cached in a map and not closed when a different
    /// child is accessed. Used by RootNode to preserve USB/NFC subtrees.
    fn retains_children(&self) -> bool {
        false
    }

    /// Check if a cached child is still valid. Returns false if the child
    /// should be closed and recreated (e.g., after device removal/reinsertion).
    fn is_child_valid(&self, _name: &str) -> bool {
        true
    }

    /// Called on parent nodes when a child action returns a response with flags.
    /// Allows parent nodes to react to flags (e.g., refresh data on "device_info",
    /// invalidate state on "device_closed").
    fn handle_child_response(&mut self, _response: &mut RpcResponse) {}
}

/// Hosts an RpcNode, managing a single cached child and routing.
pub struct NodeHost {
    node: Box<dyn RpcNode>,
    child: Option<Box<NodeHost>>,
    child_name: Option<String>,
    /// Persistent children for nodes that retain children across switches.
    retained_children: BTreeMap<String, Box<NodeHost>>,
}

impl NodeHost {
    pub fn new(node: Box<dyn RpcNode>) -> Self {
        Self {
            node,
            child: None,
            child_name: None,
            retained_children: BTreeMap::new(),
        }
    }

    fn close_child(&mut self) {
        if let Some(mut child) = self.child.take() {
            log::debug!("Closing child: {:?}", self.child_name);
            child.close();
        }
        self.child_name = None;
    }

    fn close(&mut self) {
        self.close_child();
        for (name, child) in self.retained_children.iter_mut() {
            log::debug!("Closing retained child: {name}");
            child.close();
        }
        self.retained_children.clear();
        self.node.close();
    }

    fn get_or_create_child(&mut self, name: &str) -> Result<&mut NodeHost, RpcError> {
        if self.node.retains_children() {
            // Multi-child mode: keep all children alive in a map
            if self.retained_children.contains_key(name)
                && !self.node.is_child_valid(name)
                && let Some(mut child) = self.retained_children.remove(name)
            {
                log::debug!("Closing invalid retained child: {name}");
                child.close();
            }
            if !self.retained_children.contains_key(name) {
                let child_node = self.node.create_child(name)?;
                self.retained_children
                    .insert(name.to_string(), Box::new(NodeHost::new(child_node)));
                log::debug!("Created retained child: {name}");
            }
            Ok(self.retained_children.get_mut(name).unwrap())
        } else {
            // Single-child mode: close old child when switching
            if self.child_name.as_deref() == Some(name) && !self.node.is_child_valid(name) {
                log::debug!("Closing invalid child: {name}");
                self.close_child();
            } else if self.child_name.as_deref() != Some(name) {
                self.close_child();
            }

            if self.child.is_none() {
                let child_node = self.node.create_child(name)?;
                self.child = Some(Box::new(NodeHost::new(child_node)));
                self.child_name = Some(name.to_string());
                log::debug!("Created child: {name}");
            }

            Ok(self.child.as_mut().unwrap())
        }
    }

    /// Handle an RPC call, routing through the node tree.
    pub fn call(
        &mut self,
        action: &str,
        target: &[String],
        params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        let mut traversed: Vec<String> = vec![];
        self.call_inner(action, target, params, signal, cancel, &mut traversed)
    }

    fn call_inner(
        &mut self,
        action: &str,
        target: &[String],
        params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
        traversed: &mut Vec<String>,
    ) -> Result<RpcResponse, RpcError> {
        let result = if !target.is_empty() {
            traversed.push(target[0].clone());
            match self.get_or_create_child(&target[0]) {
                Ok(child) => {
                    let mut result =
                        child.call_inner(action, &target[1..], params, signal, cancel, traversed);
                    // Let the current node handle flags from child responses
                    if let Ok(ref mut response) = result
                        && !response.flags.is_empty()
                    {
                        self.node.handle_child_response(response);
                    }
                    result
                }
                Err(e) => Err(e),
            }
        } else if action == "get" {
            // Built-in get action
            let data = self.node.get_data();
            let mut actions = self.node.list_actions();
            // Python includes "get" in list_actions (it's an @action on the base class)
            if !actions.contains(&"get") {
                actions.insert(0, "get");
            }
            actions.sort();
            let children = self.node.list_children();
            Ok(RpcResponse::new(json!({
                "data": data,
                "actions": actions,
                "children": children,
            })))
        } else if self.node.list_actions().contains(&action) {
            // Check if action should close child
            if self.node.action_closes_child(action) {
                self.close_child();
            }
            self.node.call_action(action, params, signal, cancel)
        } else if self.node.list_children().contains_key(action) {
            // Action name matches a child — navigate to it and call get
            traversed.push(action.to_string());
            match self.get_or_create_child(action) {
                Ok(child) => child.call_inner("get", &[], params, signal, cancel, traversed),
                Err(e) => Err(e),
            }
        } else {
            Err(RpcError::no_such_action(action))
        };

        match result {
            Err(e) if e.status == "child-reset" => {
                self.close_child();
                Err(RpcError::state_reset(&e.message, traversed.clone()))
            }
            other => other,
        }
    }
}

/// Convert a ChildResetException into an RpcError with status "child-reset"
/// (internal marker, converted to "state-reset" by the parent).
impl From<ChildResetException> for RpcError {
    fn from(e: ChildResetException) -> Self {
        RpcError::new("child-reset", e.message)
    }
}
