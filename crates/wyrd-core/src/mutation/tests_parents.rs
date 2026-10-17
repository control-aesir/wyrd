use super::*;

#[test]
fn parent_tokens_survive_descendants_and_rotate_after_replacement() {
    let queue = MutationQueue::default();
    let parent = queue.capture_parent("parent").unwrap();
    let child = queue.capture_parent("parent/child").unwrap();
    let sibling = queue.capture_parent("sibling").unwrap();

    assert_eq!(queue.capture_parent("parent"), Some(parent));
    assert_eq!(queue.capture_parent("parent/child"), Some(child));
    assert_eq!(queue.capture_parent("sibling"), Some(sibling));

    queue.invalidate_parent_subtree("parent");
    assert!(!queue.validate_parent("parent", parent));
    assert!(!queue.validate_parent("parent/child", child));
    assert!(queue.validate_parent("sibling", sibling));
    assert_eq!(queue.capture_parent("parent"), None);

    queue.publish_parent_tokens();
    let replacement = queue.capture_parent("parent").unwrap();
    assert_ne!(replacement, parent);
    assert_eq!(queue.capture_parent("sibling"), Some(sibling));
}

#[test]
fn parent_tokens_block_all_until_a_new_projection_is_published() {
    let queue = MutationQueue::default();
    let root = queue.capture_parent("").unwrap();
    let child = queue.capture_parent("child").unwrap();

    queue.invalidate_parent_tokens();
    assert!(!queue.validate_parent("", root));
    assert!(!queue.validate_parent("child", child));
    assert_eq!(queue.capture_parent("child"), None);

    queue.publish_parent_tokens();
    assert_ne!(queue.capture_parent(""), Some(root));
    assert_ne!(queue.capture_parent("child"), Some(child));
}

#[test]
fn parent_tokens_fail_closed_at_the_configured_bound() {
    let queue = MutationQueue::with_limits(1, 1);
    let first = queue.capture_parent("first").unwrap();
    assert_eq!(queue.capture_parent("first"), Some(first));
    assert_eq!(queue.capture_parent("second"), None);

    queue.invalidate_parent_subtree("first");
    queue.publish_parent_tokens();
    assert!(queue.capture_parent("second").is_some());
}

#[test]
fn parent_tokens_ignore_sibling_changes() {
    let queue = MutationQueue::default();
    let parent = queue.capture_parent("parent").unwrap();
    let sibling = queue.capture_parent("sibling").unwrap();

    queue.invalidate_parent_subtree("sibling");
    assert!(queue.validate_parent("parent", parent));
    assert!(!queue.validate_parent("sibling", sibling));
    queue.publish_parent_tokens();
    assert_eq!(queue.capture_parent("parent"), Some(parent));
}
