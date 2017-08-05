use std::io;
use std::cmp;
use std::result;
use std::rc::Rc;

extern crate mio;
use self::mio::*;
use self::mio::unix::EventedFd;

extern crate byteorder;
use self::byteorder::{ByteOrder, LittleEndian};

extern crate icmp_communicator;
use self::icmp_communicator::*;


const TYPE_SND: u8 = 'S' as u8; // new packet
const TYPE_ACK: u8 = 'A' as u8; // packet ack
const TYPE_AGN: u8 = 'G' as u8; // resend request

const PKT_HDR_SIZE: usize = 10;
const PKT_MAX_SIZE: usize = 1480;

const WINDOW_SIZE: usize = 2;

#[derive(Debug, Copy, Clone)]
pub enum ODPError {
    ICError(icmp_communicator::ICError),
    ProtocolError,
    AckError,
    SndError,
    RemoteWindowFull,
    Unknown,
}

pub type Result<T> = result::Result<T, ODPError>;

pub type Seqnum = u64;

pub struct ODP {
    com:         Rc<IcmpCommunicator>,
    peer:        InetAddr,
    seqnum:      Seqnum,
    peer_seqnum: Seqnum,
    ack_wait:    Vec<(Seqnum, Vec<u8>)>,
}

impl ODP {

    pub fn new(com: Rc<IcmpCommunicator>, peer: InetAddr) -> ODP {
        ODP {
            com:         com,
            peer:        peer,
            seqnum:      0,
            peer_seqnum: 0,
            ack_wait:    Vec::new(),
        }
    }

    pub fn rawfd(&self) -> &RawFd {
        self.com.rawfd()
    }

    pub fn send(&mut self, buf: &[u8]) -> Result<usize> {

        if self.ack_wait.len() >= WINDOW_SIZE {
            return Err(ODPError::RemoteWindowFull);
        }

        // buffer to build the packet
        let mut sysbuf = vec![0; PKT_HDR_SIZE];

        sysbuf[0] = TYPE_SND; // add type
        sysbuf[1] = 0;        // reserved byte

        // write seqnum
        let seqnum = self.seqnum;
        LittleEndian::write_u64(&mut sysbuf[2..], seqnum);
        self.seqnum += 1;

        //debug!("> SND {} {:?}", seqnum, String::from_utf8(buf.to_vec()));
        debug!("> SND {}", seqnum);

        // add user data
        let to_write = cmp::min(PKT_MAX_SIZE-PKT_HDR_SIZE, buf.len());
        sysbuf.extend_from_slice(&buf[..to_write]);

        match self.com.sendto(&sysbuf, self.peer) {
            Err(e)                    => Err(ODPError::ICError(e)),
            Ok(n) if n < PKT_HDR_SIZE => Err(ODPError::SndError),
            Ok(n)                     => {
                self.ack_wait.push((seqnum, sysbuf));
                Ok(n-PKT_HDR_SIZE)
            }
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        let mut sysbuf = [0; PKT_MAX_SIZE];

        match self.com.recvfrom(&mut sysbuf).map_err(ODPError::ICError)? {
            None                              => Ok(None),
            Some((_, p)) if p != self.peer    => Ok(None),
            Some((s, _)) if s  < PKT_HDR_SIZE => Err(ODPError::ProtocolError),
            Some((s, _)) => {
                let pkttype   = sysbuf[0];
                let _reserved = sysbuf[1];
                match pkttype {
                    TYPE_ACK => { self.handle_ack_(&sysbuf[..s]) }
                    TYPE_AGN => { self.handle_agn_(&sysbuf[..s]) }
                    TYPE_SND => { self.handle_snd_(&sysbuf[..s], buf) }
                    _        => { Err(ODPError::ProtocolError) }
                }
            }
        }
    }

    fn handle_ack_(&mut self, ack: &[u8]) -> Result<Option<usize>> {
        let seqnum = LittleEndian::read_u64(&ack[2..]);

        debug!("< ACK {}", seqnum);

        // remove packets whose seqnum is below the one found in the ack packet
        self.ack_wait.retain(|&(s, _)| s > seqnum);
        self.peer_seqnum = cmp::max(self.peer_seqnum, seqnum);
        Ok(None)
    }

    fn handle_snd_(&mut self, snd: &[u8], buf: &mut [u8]) -> Result<Option<usize>> {
        let seqnum = LittleEndian::read_u64(&snd[2..]);

        debug!("< SND {}", seqnum);

        if seqnum < self.peer_seqnum {
            // we already sent an ack for this packet, maybe our peer didn't get it?
            // craft another ack packet with the last seqnum we acknowledged.
            self.send_ack_(self.peer_seqnum)?;
            Ok(None)
        }
        else if seqnum == self.peer_seqnum {
            self.send_ack_(self.peer_seqnum)?;
            self.peer_seqnum += 1;
            Ok(Some(copy_buf(buf, &snd[PKT_HDR_SIZE..])))
        }
        else {
            // we missed some packets, drop this one and request resending everything that we
            // missed. TODO: store the packet and don't include it in the resend request.
            self.send_agn_(self.peer_seqnum, seqnum)?;
            Ok(None)
        }
    }

    fn handle_agn_(&mut self, agn: &[u8]) -> Result<Option<usize>> {
        let from = LittleEndian::read_u64(&agn[ 2..]);
        let to   = LittleEndian::read_u64(&agn[10..]);

        debug!("< AGN {} -> {}", from, to);

        if from > to {
            return Err(ODPError::ProtocolError);
        }

        // use the 'from' as an ack
        self.ack_wait.retain(|&(s, _)| s >= from);
        self.peer_seqnum = cmp::max(self.peer_seqnum, from);

        // resend packets (ignore the 'to' param for now, resend everything)
        for &(seq, ref buf) in &self.ack_wait {
            debug!("> RESND {}", seq);
            self.com.sendto(buf, self.peer).map_err(ODPError::ICError)?;
        }

        Ok(None)
    }

    fn send_agn_(&self, from: Seqnum, to: Seqnum) -> Result<()> {
        let mut ack = [0; PKT_HDR_SIZE+8];

        debug!("> AGN {} -> {}", from, to);

        ack[0] = TYPE_AGN; // type
        ack[1] = 0;        // reserved byte
        LittleEndian::write_u64(&mut ack[ 2..], from);
        LittleEndian::write_u64(&mut ack[10..], to);

        match self.com.sendto(&ack, self.peer) {
            Err(e) => Err(ODPError::ICError(e)),
            Ok(n)  => {
                if n != ack.len() {
                    Err(ODPError::Unknown)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn send_ack_(&self, seqnum: Seqnum) -> Result<()> {
        let mut ack = [0; PKT_HDR_SIZE];

        debug!("> ACK {}", seqnum);

        ack[0] = TYPE_ACK; // type
        ack[1] = 0;        // reserved byte
        LittleEndian::write_u64(&mut ack[2..], seqnum);

        match self.com.sendto(&ack, self.peer) {
            Ok(PKT_HDR_SIZE) => Ok(()),
            Ok(_)            => Err(ODPError::ProtocolError),
            Err(e)           => Err(ODPError::ICError(e)),
        }
    }
}


impl Evented for ODP {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
      -> io::Result<()> {
        EventedFd(&self.com.rawfd()).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
      -> io::Result<()> {
        EventedFd(&self.com.rawfd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.com.rawfd()).deregister(poll)
    }
}


fn copy_buf(dst: &mut[u8], src: &[u8]) -> usize {
    let copylen = cmp::min(dst.len(), src.len());
    dst[..copylen].copy_from_slice(&src[..copylen]);
    copylen
}
