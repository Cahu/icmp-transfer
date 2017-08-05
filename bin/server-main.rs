use std::io::{self, Write};
use std::rc::Rc;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate icmp_communicator;
use icmp_communicator::IcmpCommunicator;

extern crate icmp_tunnel;
use icmp_tunnel::odp::ODP;
use icmp_tunnel::privs;


fn main() {
    let com = Rc::new(IcmpCommunicator::new(2).expect("Make sure you have the necessary permissions"));
    privs::drop_privs();

    env_logger::init().unwrap();

    let addr = "127.0.0.1:0".parse().unwrap();
    let peer = icmp_communicator::InetAddr::from_std(&addr);

    let mut odp = ODP::new(com, peer);

    let mut buf = [0; 4096];
    loop {
        match odp.recv(&mut buf) {
            Ok(Some(n)) => {
                //println!("{:?}", String::from_utf8(buf[..n].to_vec()));
                io::stdout().write_all(&buf[..n]).unwrap();
            }
            Err(e) => panic!("{:?}", e),
            _ => {} //println!("{:?}", e),
        }
    }
}
