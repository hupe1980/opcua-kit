use super::ua::{BinaryEncodable, ContextOwned, Variant};
use std::sync::LazyLock;

/// Encoded size including the Variant tag and array dimensions.
pub(super) fn variant_size(value: &Variant) -> Option<usize> {
    static CONTEXT: LazyLock<ContextOwned> = LazyLock::new(ContextOwned::default);
    value.encoded_len(&CONTEXT.context()).ok()
}
