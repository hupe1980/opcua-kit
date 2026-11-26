use open62541::DataType;

use super::{
    Client, Namespaces, ReadError, ReadSession, ua,
    units::{MAX_PAGES, MAX_REFERENCES, Page, local_target, references},
};
use crate::NodeId;

const MAX_PATH: usize = 16;
const MAX_TEXT: usize = 4096;
const MAX_RESULT_BYTES: usize = 1024 * 1024;

/// A browse name qualified by its namespace URI. Names use case-sensitive exact matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowseName {
    /// Namespace URI of the BrowseName, independent of the target NodeId namespace.
    pub namespace: String,
    /// Nonempty UTF-8 name.
    pub name: String,
}

impl BrowseName {
    /// Construct one path component. Each field accepts up to 4096 UTF-8 bytes.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Result<Self, BrowseError> {
        let value = Self {
            namespace: namespace.into(),
            name: name.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn validate(&self) -> Result<(), BrowseError> {
        if self.namespace.trim().is_empty()
            || self.name.is_empty()
            || [&self.namespace, &self.name]
                .iter()
                .any(|s| s.len() > MAX_TEXT || s.chars().any(char::is_control))
        {
            return Err(BrowseError::InvalidName);
        }
        Ok(())
    }
}

/// One forward hierarchical reference. Browsing does not read its target Value.
#[derive(Debug, Clone)]
pub struct BrowseEntry {
    /// Stable identity of the local target.
    pub node: NodeId,
    /// Namespace-qualified name used for relative navigation.
    pub browse_name: BrowseName,
    /// Actual reference subtype, such as HasComponent or HasProperty.
    pub reference_type: NodeId,
    /// Server-reported class of the target.
    pub node_class: ua::NodeClass,
}

/// A local navigation request could not be completed unambiguously.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BrowseError {
    /// Transport or pinned session failure.
    #[error(transparent)]
    Session(ReadError),
    /// One Browse or BrowseNext item had a nonzero status.
    #[error("browse item status 0x{0:08X}")]
    Status(u32),
    /// Server returned an incomplete, remote or invalid reference.
    #[error("invalid browse response or nonlocal reference")]
    InvalidReference,
    /// A name exceeds the byte limit, contains a control character, or is empty.
    #[error("browse name and namespace must be nonempty and at most 4096 bytes without controls")]
    InvalidName,
    /// A listing or path exceeded a documented bound.
    #[error("browse exceeded its reference, page, text or path limit")]
    Limit,
    /// No exact matching child at this zero-based path step.
    #[error("no matching child for path component {0}")]
    NotFound(usize),
    /// More than one reference matched this zero-based path step.
    #[error("ambiguous child at path component {0}")]
    Ambiguous(usize),
}

impl From<ReadError> for BrowseError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::InvalidUnitReference | ReadError::InvalidDataType => Self::InvalidReference,
            other => Self::Session(other),
        }
    }
}

fn entry(
    namespaces: &Namespaces,
    reference: &ua::ReferenceDescription,
) -> Result<BrowseEntry, BrowseError> {
    let valid_class = [
        ua::NodeClass::OBJECT,
        ua::NodeClass::VARIABLE,
        ua::NodeClass::METHOD,
        ua::NodeClass::OBJECTTYPE,
        ua::NodeClass::VARIABLETYPE,
        ua::NodeClass::REFERENCETYPE,
        ua::NodeClass::DATATYPE,
        ua::NodeClass::VIEW,
    ]
    .contains(reference.node_class());
    if !reference.is_forward() || reference.reference_type_id().is_null() || !valid_class {
        return Err(BrowseError::InvalidReference);
    }
    let qualified = reference.browse_name();
    let namespace = namespaces
        .by_index
        .get(usize::from(qualified.namespace_index()))
        .ok_or(BrowseError::InvalidReference)?;
    let name = qualified
        .name()
        .as_str()
        .ok_or(BrowseError::InvalidReference)?;
    if namespace.len() > MAX_TEXT || name.len() > MAX_TEXT {
        return Err(BrowseError::Limit);
    }
    let node = local_target(namespaces, reference.node_id())?;
    if node.namespace() == "http://opcfoundation.org/UA/" && node.identifier() == "i=0" {
        return Err(BrowseError::InvalidReference);
    }
    Ok(BrowseEntry {
        browse_name: BrowseName::new(namespace.as_ref(), name)?,
        node,
        reference_type: namespaces.stable_node(reference.reference_type_id())?,
        node_class: reference.node_class().clone(),
    })
}

impl Client {
    /// List all forward local hierarchical children of one node, including reference subtypes.
    /// Output preserves server order. A listing is limited to 256 references, 256 pages,
    /// and 1 MiB of retained identifier/name text. A failure discards the partial listing.
    pub async fn browse_children(&self, node: &NodeId) -> Result<Vec<BrowseEntry>, BrowseError> {
        let (mut session, metadata) = self.read_session().await?;
        let mut pages = MAX_PAGES;
        self.children_locked(&mut session, &metadata.namespaces, node, &mut pages)
            .await
    }

    /// Follow 1–16 exact forward hierarchical browse names. Each step must match exactly
    /// one child on this server. The complete path shares one 256-page budget.
    pub async fn resolve_path(
        &self,
        start: &NodeId,
        path: &[BrowseName],
    ) -> Result<NodeId, BrowseError> {
        if path.is_empty() || path.len() > MAX_PATH {
            return Err(BrowseError::Limit);
        }
        for component in path {
            component.validate()?;
        }
        let (mut session, metadata) = self.read_session().await?;
        let mut node = start.clone();
        let mut pages = MAX_PAGES;
        for (index, component) in path.iter().enumerate() {
            let children = self
                .children_locked(&mut session, &metadata.namespaces, &node, &mut pages)
                .await?;
            let mut matching = children
                .into_iter()
                .filter(|child| &child.browse_name == component);
            node = matching.next().ok_or(BrowseError::NotFound(index))?.node;
            if matching.next().is_some() {
                return Err(BrowseError::Ambiguous(index));
            }
        }
        Ok(node)
    }

    async fn children_locked(
        &self,
        session: &mut ReadSession,
        namespaces: &Namespaces,
        node: &NodeId,
        pages_left: &mut usize,
    ) -> Result<Vec<BrowseEntry>, BrowseError> {
        if *pages_left == 0 {
            return Err(BrowseError::Limit);
        }
        let mask = ua::BrowseResultMask::REFERENCETYPEINFO
            | ua::BrowseResultMask::BROWSENAME
            | ua::BrowseResultMask::NODECLASS;
        let description = ua::BrowseDescription::default()
            .with_node_id(&namespaces.wire_node(node, 0)?)
            .with_result_mask(&mask);
        let request = ua::BrowseRequest::init()
            .with_requested_max_references_per_node(MAX_REFERENCES as u32)
            .with_nodes_to_browse(&[description]);
        let mut page = Page::First(
            self.guarded(session, self.inner.service_request(request))
                .await?,
        );
        let mut children = Vec::new();
        let mut bytes = MAX_RESULT_BYTES;
        loop {
            *pages_left -= 1;
            let (result, point) = page.checked(session)?;
            let inspected = (|| {
                let status = result.status_code().into_raw();
                if status != 0 {
                    return Err(BrowseError::Status(status));
                }
                let batch = references(result)?;
                if batch.len() > MAX_REFERENCES - children.len() {
                    return Err(BrowseError::Limit);
                }
                for reference in batch {
                    let child = entry(namespaces, reference)?;
                    for field in [
                        &child.browse_name.namespace,
                        &child.browse_name.name,
                        child.node.namespace(),
                        child.node.identifier(),
                        child.reference_type.namespace(),
                        child.reference_type.identifier(),
                    ] {
                        bytes = bytes.checked_sub(field.len()).ok_or(BrowseError::Limit)?;
                    }
                    children.push(child);
                }
                Ok(())
            })();
            let Some(point) = point else {
                inspected?;
                return Ok(children);
            };
            if inspected.is_err() || *pages_left == 0 {
                self.next_browse_page(session, point, true).await?;
                inspected?;
                return Err(BrowseError::Limit);
            }
            page = Page::Next(self.next_browse_page(session, point, false).await?);
        }
    }
}
