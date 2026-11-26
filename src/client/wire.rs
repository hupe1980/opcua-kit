/// Borrow a counted array in an SDK-owned, decoded UA structure. The owner must
/// remain alive and immutable for the entire lifetime of the result.
pub(super) unsafe fn slice<'a, T>(ptr: *const T, count: usize, max: usize) -> Option<&'a [T]> {
    if count == 0 {
        return Some(&[]);
    }
    if count > max || ptr.addr() <= 1 || !ptr.is_aligned() {
        return None;
    }
    // SAFETY: the SDK constructed count valid elements, and the caller retains the owner.
    Some(unsafe { std::slice::from_raw_parts(ptr, count) })
}

// Each owned wrapper corresponds to precisely one entry in the SDK type table.
// UA_copy/UA_clear own all nested allocations and use the same allocator as the service.
macro_rules! owned {
    ($name:ident,$inner:ident,$kind:ident) => {
        #[repr(transparent)]
        pub(super) struct $name(pub(super) sys::$inner);
        // SAFETY: transparent owned OPC UA structure with no shared interior state.
        unsafe impl DataType for $name {
            type Inner = sys::$inner;
            fn data_type() -> *const sys::UA_DataType {
                unsafe { &sys::UA_TYPES[sys::$kind as usize] }
            }
            unsafe fn from_raw(raw: Self::Inner) -> Self {
                Self(raw)
            }
            fn into_raw(self) -> Self::Inner {
                unsafe { std::ptr::read(&std::mem::ManuallyDrop::new(self).0) }
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
        impl Clone for $name {
            fn clone(&self) -> Self {
                Self::clone_raw(&self.0)
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    sys::UA_clear((&raw mut self.0).cast(), Self::data_type());
                }
            }
        }
        // SAFETY: the wrapper has sole ownership of the allocations and read-only borrows do not mutate them.
        unsafe impl Send for $name {}
        unsafe impl Sync for $name {}
    };
}
pub(super) use owned;

/// Size of the UA Binary Variant, including its built-in type and shape.
pub(super) fn variant_size(value: &open62541::ua::Variant) -> Option<usize> {
    use open62541::{DataType, ua};
    // SAFETY: the SDK-owned Variant and its static descriptor remain live throughout this query.
    let size = unsafe {
        open62541_sys::UA_calcSizeBinary(
            value.as_ptr().cast(),
            ua::Variant::data_type(),
            std::ptr::null_mut(),
        )
    };
    (size != 0).then_some(size)
}
