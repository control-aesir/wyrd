use wyrd_format::ContentId;

use super::types::{ConflictVersion, Node, ViewError};

/// Merge per-head resolutions: unanimous absence is not-found,
/// unanimous presence with agreement serves, presence with all-dir
/// disagreement merges structurally — the path is a directory in every
/// head, so it serves as one directory and only its children can
/// conflict. Anything else — kind divergence, presence versus deletion,
/// differing leaf identity — is a path conflict. Presence versus
/// deletion disagrees — deletion is a state change, so a path surviving
/// in only some heads never serves quietly. Versions list only the
/// heads where the path resolves.
pub(crate) fn merge(
    resolutions: Vec<(wyrd_format::SnapshotId, Option<Node>)>,
) -> Result<Node, ViewError> {
    let mut present = Vec::with_capacity(resolutions.len());
    for (snapshot, node) in &resolutions {
        if let Some(node) = node {
            present.push((*snapshot, node.clone()));
        }
    }
    if present.is_empty() {
        return Err(ViewError::NotFound);
    }
    if present.len() == resolutions.len() {
        let first = &present[0].1;
        if present.iter().all(|(_, node)| node == first) {
            return Ok(first.clone());
        }
        if let Some(subtrees) = all_dirs(&present) {
            return Ok(Node::MergedDir { subtrees });
        }
    }
    Ok(Node::Conflict {
        versions: present
            .into_iter()
            .map(|(snapshot, node)| ConflictVersion { snapshot, node })
            .collect(),
    })
}

/// The per-head subtrees when every head resolves the path to a
/// directory, or `None` when any head resolves to a different kind.
fn all_dirs(
    present: &[(wyrd_format::SnapshotId, Node)],
) -> Option<Vec<(wyrd_format::SnapshotId, ContentId)>> {
    present
        .iter()
        .map(|(snapshot, node)| match node {
            Node::Dir { subtree } => Some((*snapshot, *subtree)),
            _ => None,
        })
        .collect()
}
