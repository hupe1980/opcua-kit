use super::DiscoveryError;
use DiscoveryError::Protocol;

#[derive(Default)]
pub(super) struct Encoder(pub Vec<u8>);

impl Encoder {
    pub fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    pub fn null(&mut self) {
        self.u32(u32::MAX);
    }
    pub fn blob(&mut self, bytes: &[u8]) {
        self.u32(bytes.len() as u32);
        self.0.extend_from_slice(bytes);
    }
    pub fn node(&mut self, id: u16) {
        if id <= 255 {
            self.0.extend_from_slice(&[0, id as u8]);
        } else {
            self.0.extend_from_slice(&[1, 0]);
            self.0.extend_from_slice(&id.to_le_bytes());
        }
    }
}

pub(super) struct Decoder<'a> {
    rest: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DiscoveryError> {
        let (value, rest) = self
            .rest
            .split_at_checked(n)
            .ok_or(Protocol("truncated binary field"))?;
        self.rest = rest;
        Ok(value)
    }
    pub fn remaining(&self) -> &'a [u8] {
        self.rest
    }
    pub fn finish(self) -> Result<(), DiscoveryError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Protocol("unexpected trailing bytes"))
        }
    }
    pub fn byte(&mut self) -> Result<u8, DiscoveryError> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32, DiscoveryError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn count(&mut self, max: usize) -> Result<usize, DiscoveryError> {
        match self.u32()? as i32 {
            -1 => Ok(0),
            n if n >= 0 && n as usize <= max => Ok(n as usize),
            _ => Err(Protocol("invalid or excessive field length")),
        }
    }
    pub fn blob(&mut self, max: usize) -> Result<&'a [u8], DiscoveryError> {
        let size = self.count(max)?;
        self.take(size)
    }
    pub fn text(&mut self) -> Result<&'a str, DiscoveryError> {
        std::str::from_utf8(self.blob(4096)?).map_err(|_| Protocol("invalid UTF-8"))
    }
    pub fn localized_text(&mut self) -> Result<(), DiscoveryError> {
        let flags = self.byte()?;
        if flags & !3 != 0 {
            return Err(Protocol("invalid LocalizedText mask"));
        }
        if flags & 1 != 0 {
            self.text()?;
        }
        if flags & 2 != 0 {
            self.text()?;
        }
        Ok(())
    }
    fn node(&mut self) -> Result<(u16, u32), DiscoveryError> {
        match self.byte()? {
            0 => Ok((0, self.byte()?.into())),
            1 => Ok((
                self.byte()?.into(),
                u16::from_le_bytes(self.take(2)?.try_into().unwrap()).into(),
            )),
            2 => Ok((
                u16::from_le_bytes(self.take(2)?.try_into().unwrap()),
                self.u32()?,
            )),
            _ => Err(Protocol("expected numeric type identifier")),
        }
    }
    fn diagnostics(&mut self) -> Result<(), DiscoveryError> {
        for _ in 0..32 {
            let mask = self.byte()?;
            if mask & 0x80 != 0 {
                return Err(Protocol("invalid diagnostic mask"));
            }
            self.take(((mask & 0x0f).count_ones() * 4) as usize)?;
            if mask & 0x10 != 0 {
                self.text()?;
            }
            if mask & 0x20 != 0 {
                self.u32()?;
            }
            if mask & 0x40 == 0 {
                return Ok(());
            }
        }
        Err(Protocol("nested diagnostics limit exceeded"))
    }
    pub fn response(&mut self, kind: u16, handle: u32) -> Result<(), DiscoveryError> {
        let id = self.node()?;
        if id != (0, kind.into()) && id != (0, 397) {
            return Err(Protocol("unexpected service response"));
        }
        self.take(8)?; // Timestamp.
        if self.u32()? != handle {
            return Err(Protocol("unexpected request handle"));
        }
        let status = self.u32()?;
        if status != 0 {
            return Err(DiscoveryError::Status(status));
        }
        if id == (0, 397) {
            return Err(Protocol("ServiceFault without an error"));
        }
        self.diagnostics()?;
        for _ in 0..self.count(256)? {
            self.text()?;
        }
        self.node()?; // AdditionalHeader type.
        match self.byte()? {
            0 => (),
            1 | 2 => {
                self.blob(1024 * 1024)?;
            }
            _ => return Err(Protocol("invalid extension encoding")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_lengths_are_checked_before_reading_contents() {
        assert!(Decoder::new(&(-2i32).to_le_bytes()).text().is_err());
        assert!(Decoder::new(&4097i32.to_le_bytes()).text().is_err());
        assert!(Decoder::new(&[2, 0, 0, 0, b'x']).text().is_err());
        assert_eq!(Decoder::new(&(-1i32).to_le_bytes()).text().unwrap(), "");
    }

    #[test]
    fn service_fault_retains_status_and_requires_matching_handle() {
        let mut out = Encoder::default();
        out.node(397);
        out.0.extend_from_slice(&[0; 8]);
        out.u32(2);
        out.u32(0x800b_0000);
        assert!(matches!(
            Decoder::new(&out.0).response(431, 2),
            Err(DiscoveryError::Status(0x800b_0000))
        ));
        assert!(matches!(
            Decoder::new(&out.0).response(431, 3),
            Err(DiscoveryError::Protocol(_))
        ));
    }
}
