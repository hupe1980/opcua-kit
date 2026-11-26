//! Exchange one unsigned UADP key frame with a configured loopback UDP peer.
//! The host owns the socket, destination, identity and field layout.
use opcua_kit::pubsub::{DataSetId, Field, KeyFrame};
use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    num::NonZeroU16,
    time::Duration,
};

fn main() -> Result<(), Box<dyn Error>> {
    let arg = std::env::args()
        .nth(1)
        .ok_or("expected loopback UDP peer port")?;
    let port: NonZeroU16 = arg.parse()?;
    let peer = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port.get());
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.connect(peer)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    let id = DataSetId {
        publisher: NonZeroU16::new(12).unwrap(),
        writer_group: NonZeroU16::new(34).unwrap(),
        writer: NonZeroU16::new(56).unwrap(),
    };
    let reading = KeyFrame {
        id,
        sequence: u16::MAX,
        fields: vec![Field::UInt64(9_007_199_254_740_993), Field::Boolean(true)],
    };
    socket.send(&reading.encode()?)?;
    // A buffer larger than the accepted wire maximum also distinguishes oversized datagrams.
    let mut bytes = [0_u8; 1024];
    let count = socket.recv(&mut bytes)?;
    let reply = KeyFrame::decode(&bytes[..count])?;
    if reply.id != id || reply.sequence != reading.sequence.wrapping_add(1) {
        return Err("unexpected dataset identity or sequence".into());
    }
    let [Field::UInt64(total), Field::Boolean(running)] = reply.fields.as_slice() else {
        return Err("unexpected field layout".into());
    };
    println!("parts={total} running={running}");
    Ok(())
}
