extern crate icmp_communicator;
use icmp_communicator::IcmpCommunicator;

fn main() {
    let com = IcmpCommunicator::new(2).expect("Make sure you have the necessary permissions");

    let mut buf = [0; 4096];
    loop {
        match com.recvfrom(&mut buf) {
            Ok(None)          => println!("None"),
            Ok(Some((sz, _))) => println!("{:?}", String::from_utf8(buf[..sz].to_vec())),
            Err(e)            => println!("Error: {:?}", e),
        }
    }
}
