use std::thread::sleep;
use std::time::Duration;

extern crate icmp_communicator;
use icmp_communicator::IcmpCommunicator;

fn main() {
    let com = IcmpCommunicator::new().expect("Make sure you have the necessary permissions");

    let addr = "127.0.0.1:0".parse().unwrap();
    let peer = icmp_communicator::InetAddr::from_std(&addr);
    loop {
        println!("{:?}", com.sendto(b"Hello!\n", peer));
        sleep(Duration::new(1, 0));
    }
}
