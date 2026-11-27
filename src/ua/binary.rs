use super::StatusCode;
use std::{
    io::{Read, Write},
    sync::atomic::{AtomicUsize, Ordering},
};

/// Collects encoded bytes within a negotiated message or field limit.
pub(crate) struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedBuffer {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed
    }
}
impl Write for BoundedBuffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > self.limit - self.bytes.len() {
            self.overflowed = true;
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let needed = self.bytes.len() + data.len();
        if needed > self.bytes.capacity() {
            let capacity = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .max(64)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| std::io::ErrorKind::OutOfMemory)?;
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Allocation and recursion limits for one UA Binary message.
#[derive(Clone, Debug)]
pub struct DecodingOptions {
    pub max_array_length: usize,
    pub max_byte_string_length: usize,
    pub max_string_length: usize,
    pub max_depth: usize,
    /// Total backing storage allowed for values decoded from one message, including nested bodies.
    pub max_allocation_bytes: usize,
}
impl Default for DecodingOptions {
    fn default() -> Self {
        Self {
            max_array_length: 65536,
            max_byte_string_length: 16 << 20,
            max_string_length: 1 << 20,
            max_depth: 32,
            max_allocation_bytes: 16 << 20,
        }
    }
}

/// Configuration shared by decoders across messages.
#[derive(Default)]
pub struct ContextOwned(pub DecodingOptions);
impl ContextOwned {
    /// Start a message with a fresh allocation budget. Pass the resulting context to every field decoder.
    pub fn context(&self) -> Context<'_> {
        Context {
            limits: &self.0,
            depth: 0,
            budget: Budget::Message(AtomicUsize::new(self.0.max_allocation_bytes)),
        }
    }
}
enum Budget<'a> {
    Message(AtomicUsize),
    Nested(&'a AtomicUsize),
}

/// Limits at the current nesting depth. Child contexts share the message’s remaining allocation budget.
pub struct Context<'a> {
    limits: &'a DecodingOptions,
    depth: usize,
    budget: Budget<'a>,
}
impl std::ops::Deref for Context<'_> {
    type Target = DecodingOptions;
    fn deref(&self) -> &Self::Target {
        self.limits
    }
}
impl Context<'_> {
    fn remaining(&self) -> &AtomicUsize {
        match &self.budget {
            Budget::Message(n) => n,
            Budget::Nested(n) => n,
        }
    }

    pub(super) fn charge<T>(&self, count: usize) -> Result<(), StatusCode> {
        let bytes = count
            .checked_mul(size_of::<T>())
            .ok_or(StatusCode::BadEncodingLimitsExceeded)?;
        let counter = self.remaining();
        let mut remaining = counter.load(Ordering::Relaxed);
        loop {
            let next = remaining
                .checked_sub(bytes)
                .ok_or(StatusCode::BadEncodingLimitsExceeded)?;
            match counter.compare_exchange_weak(
                remaining,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => remaining = actual,
            }
        }
    }

    pub fn nested(&self) -> Result<Context<'_>, StatusCode> {
        if self.depth >= self.max_depth {
            return Err(StatusCode::BadEncodingLimitsExceeded);
        }
        Ok(Context {
            limits: self.limits,
            depth: self.depth + 1,
            budget: Budget::Nested(self.remaining()),
        })
    }
}

/// Encode a value using OPC UA Part 6 binary encoding.
pub trait BinaryEncodable {
    fn encode<W: Write + ?Sized>(&self, out: &mut W, ctx: &Context<'_>) -> Result<(), StatusCode>;
    /// Measure the encoded value under the same limits used when writing it.
    fn encoded_len(&self, ctx: &Context<'_>) -> Result<usize, StatusCode> {
        let mut counter = Counter(0);
        self.encode(&mut counter, ctx)?;
        Ok(counter.0)
    }
}
struct Counter(usize);
impl Write for Counter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(data.len())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Decode one value, leaving the reader positioned at the next field.
pub trait BinaryDecodable: Sized {
    fn decode<R: Read + ?Sized>(input: &mut R, ctx: &Context<'_>) -> Result<Self, StatusCode>;
}
macro_rules! numeric {
    ($($ty:ty),*) => {$(
        impl BinaryEncodable for $ty {
            fn encode<W:Write + ?Sized>(&self,w:&mut W,_:&Context<'_>)->Result<(),StatusCode>{
                w.write_all(&self.to_le_bytes()).map_err(|_|StatusCode::BadEncodingError)
            }
        }
        impl BinaryDecodable for $ty {
            fn decode<R:Read + ?Sized>(r:&mut R,_:&Context<'_>)->Result<Self,StatusCode>{
                let mut bytes=[0u8; size_of::<$ty>()];
                r.read_exact(&mut bytes).map_err(|_|StatusCode::BadDecodingError)?;
                Ok(Self::from_le_bytes(bytes))
            }
        }
    )*};
}
numeric!(u8, i8, u16, i16, u32, i32, u64, i64, f32, f64);
impl BinaryEncodable for bool {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        u8::from(*self).encode(w, c)
    }
}
impl BinaryDecodable for bool {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        Ok(u8::decode(r, c)? != 0)
    }
}
pub(super) fn length<R: Read + ?Sized>(
    r: &mut R,
    c: &Context<'_>,
    max: usize,
) -> Result<Option<usize>, StatusCode> {
    match i32::decode(r, c)? {
        -1 => Ok(None),
        n if n < 0 => Err(StatusCode::BadDecodingError),
        n if n as usize > max => Err(StatusCode::BadEncodingLimitsExceeded),
        n => Ok(Some(n as usize)),
    }
}
pub(super) fn read_bytes<R: Read + ?Sized>(
    r: &mut R,
    c: &Context<'_>,
    max: usize,
) -> Result<Option<Vec<u8>>, StatusCode> {
    let Some(length) = length(r, c, max)? else {
        return Ok(None);
    };
    c.charge::<u8>(length)?;
    let mut data = Vec::new();
    let mut scratch = [0u8; 4096];
    while data.len() < length {
        let take = scratch.len().min(length - data.len());
        r.read_exact(&mut scratch[..take])
            .map_err(|_| StatusCode::BadDecodingError)?;
        if data.is_empty() {
            data.try_reserve_exact(length)
                .map_err(|_| StatusCode::BadEncodingLimitsExceeded)?;
        }
        data.extend_from_slice(&scratch[..take]);
    }
    Ok(Some(data))
}
pub(super) fn write_bytes<W: Write + ?Sized>(
    bytes: Option<&[u8]>,
    w: &mut W,
    c: &Context<'_>,
) -> Result<(), StatusCode> {
    let Some(data) = bytes else {
        return (-1i32).encode(w, c);
    };
    i32::try_from(data.len())
        .map_err(|_| StatusCode::BadEncodingLimitsExceeded)?
        .encode(w, c)?;
    w.write_all(data).map_err(|_| StatusCode::BadEncodingError)
}
impl<T: BinaryEncodable> BinaryEncodable for Option<Vec<T>> {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        let Some(items) = self else {
            return (-1i32).encode(w, c);
        };
        i32::try_from(items.len())
            .map_err(|_| StatusCode::BadEncodingLimitsExceeded)?
            .encode(w, c)?;
        for item in items {
            item.encode(w, c)?;
        }
        Ok(())
    }
}
impl<T: BinaryDecodable> BinaryDecodable for Option<Vec<T>> {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        let Some(n) = length(r, c, c.max_array_length)? else {
            return Ok(None);
        };
        Ok(Some(decode_array(n, c, || T::decode(r, c))?))
    }
}

// Charge the complete backing store, then reserve once the first element is available.
pub(super) fn decode_array<T>(
    count: usize,
    c: &Context<'_>,
    mut decode: impl FnMut() -> Result<T, StatusCode>,
) -> Result<Vec<T>, StatusCode> {
    c.charge::<T>(count)?;
    let mut values = Vec::new();
    for _ in 0..count {
        let item = decode()?;
        if values.is_empty() {
            values
                .try_reserve_exact(count)
                .map_err(|_| StatusCode::BadEncodingLimitsExceeded)?;
        }
        values.push(item);
    }
    Ok(values)
}

impl<T: BinaryDecodable> BinaryDecodable for Box<T> {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        c.charge::<T>(1)?;
        Ok(Box::new(T::decode(r, c)?))
    }
}
