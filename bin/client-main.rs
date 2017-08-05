use std::rc::Rc;
use std::time::Duration;
use std::thread::sleep;
use std::os::unix::io::RawFd;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate mio;
use mio::*;
use mio::unix::EventedFd;
//use mio::tcp::{TcpListener};

extern crate nix;
use nix::libc;
use nix::unistd;

extern crate icmp_communicator;
use icmp_communicator::IcmpCommunicator;

extern crate icmp_tunnel;
use icmp_tunnel::odp::ODP;
use icmp_tunnel::odp::ODPError;
use icmp_tunnel::privs;

static STDIN: RawFd = libc::STDIN_FILENO;

const SERV: Token = Token(0);
const ICMP: Token = Token(1);

fn main() {
    let com = Rc::new(IcmpCommunicator::new(1).unwrap());
    privs::drop_privs();

    env_logger::init().unwrap();

    let addr = "127.0.0.1:0".parse().unwrap();
    let peer = icmp_communicator::InetAddr::from_std(&addr);

    let mut odp = ODP::new(com, peer);

    // Setup the server socket
    //let addr = "127.0.0.1:4242".parse().unwrap();
    //let srv  = TcpListener::bind(&addr).unwrap();
    let srv = EventedFd(&STDIN);

    let poll = Poll::new().unwrap();
    //poll.register(&srv, SERV, Ready::readable(), PollOpt::level()).unwrap();
    poll.register(&odp, ICMP, Ready::readable(), PollOpt::level()).unwrap();
    poll.register(&srv, SERV, Ready::readable(), PollOpt::level()).unwrap();

    let mut tosend = 0;
    let mut buf    = [0; 10];
    let mut events = Events::with_capacity(1024);

    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                ICMP => {
                    let ret = odp.recv(&mut buf);
                    //debug!("{:?}", ret);
                }
                SERV => {
                    if tosend == 0 {
                        tosend = unistd::read(STDIN, &mut buf).unwrap();
                    }
                    if tosend == 0 {
                        return;
                    }
                    match odp.send(&buf[..tosend]) {
                        Ok(_) => {
                            tosend = 0;
                        }
                        Err(ODPError::RemoteWindowFull) => {
                            debug!("Queue full!");
                            sleep(Duration::new(0, 1000000));
                        }
                        Err(e) => panic!("{:?}", e),
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}
