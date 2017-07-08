use std::cmp;
use std::result;
use std::os::unix::io::RawFd;

extern crate nix;
pub use self::nix::unistd;
pub use self::nix::sys::socket::*;


// The header to include in all packets. It is 4 bytes long:
// * \x08: ICMP echo request
// * \x42: a byte we choose not totally at random to separate our packets from the rest of the
// ICMP trafic
// * \x00\x00: place holder for the checksum
// * \x00: place holder for the communicator's id
const PKT_HEADER: &[u8; 5] = b"\x08\x42\x00\x00\x00";

// IP packet header is 20 bytes long
const IP_SIZE: usize = 20;

#[derive(Debug, Copy, Clone)]
pub enum ICError {
    /// Error reported by nix
    Nix(nix::Error),
    /// Other error
    Unknown,
}

type Result<T> = result::Result<T, ICError>;


pub struct IcmpCommunicator {
    id:   u8,
    sock: RawFd,
}

impl IcmpCommunicator {

    pub fn new(id: u8) -> Result<IcmpCommunicator> {
        socket(AddressFamily::Inet, SockType::Raw, SockFlag::empty(), 0x01 /* IPPROTO_ICMP */)
            .map_err(|e| ICError::Nix(e))
            .map    (|s| IcmpCommunicator { id: id, sock: s })
    }

    pub fn rawfd(&self) -> RawFd {
        self.sock
    }

    pub fn close(&self) -> Result<()> {
        unistd::close(self.sock).map_err(|e| ICError::Nix(e))
    }

    /// Send the data contained in `buf` to `peer` inside an ICMP packet.
    pub fn sendto(&self, buf: &[u8], peer: InetAddr) -> Result<usize> {

        // first add the header
        let mut data = PKT_HEADER.to_vec();

        // add this comminucator's id
        data[4] = self.id;

        // add user data
        data.extend_from_slice(buf);

        // compute the checksum
        let mut accum: u64 = 0;
        for (i, &b) in data.iter().enumerate() {
            accum += (b as u64) << (8 * (i % 2));
        }
        while (accum >> 16) > 0 {
            accum = (accum & 0xFFFF) + (accum >> 16);
        }
        accum = !accum;

        // write the checsum in the header; we need to swap bytes because of the way we computed
        // the checksum
        data[2] = (accum & 0xFF) as u8;
        data[3] = (accum >> 8)   as u8;

        // Finally, send
        let addr = SockAddr::Inet(peer);
        sendto(self.sock, &data, &addr, MsgFlags::empty())
            .map_err(|e| ICError::Nix(e))
            .map    (|s| if s > PKT_HEADER.len() { s - PKT_HEADER.len() } else { 0 })
    }

    /// Read an ICMP packet. If the packet looks like regular ICMP trafic Ok(None) is returned;
    /// otherwise the message contained in the packet is copied to `buf` and its length (regardless
    /// of `buf`'s size) along with its origin is returned. If `buf` is smaller than the message's
    /// length, then only `buf.len()` bytes are copied.
    pub fn recvfrom(&self, buf: &mut [u8]) -> Result<Option<(usize, InetAddr)>> {
        let mut data = [0; 4096];

        let (sz, addr) = recvfrom(self.sock, &mut data).map_err(|e| ICError::Nix(e))?;

        if sz < IP_SIZE+PKT_HEADER.len() {
            return Ok(None);
        }

        let data      = &data[..sz];
        let icmp_data = &data[IP_SIZE..];
        let user_data = &icmp_data[PKT_HEADER.len()..];

        if icmp_data[0] != 0x08 {
            // not an ICMP echo request
            return Ok(None);
        }
        if icmp_data[1] != 0x42 {
            // our signature is not there => this is probably some other icmp trafic
            return Ok(None);
        }
        // bytes at idx 2 and 3 are the checksum, skip them
        if icmp_data[4] == self.id {
            // this packet was emmited using our id, ignore it
            return Ok(None);
        }

        match addr {
            SockAddr::Inet(peer) => {
                let copysize = cmp::min(buf.len(), user_data.len());
                buf[..copysize].copy_from_slice(&user_data[..copysize]);
                return Ok(Some((user_data.len(), peer)));
            }
            _ => unreachable!()
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
