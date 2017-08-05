extern crate nix;
use self::nix::unistd::{setgid, getgid, setuid, getuid};

pub fn drop_privs() {
    setgid(getgid()).expect("Could not drop privileges");
    setuid(getuid()).expect("Could not drop privileges");
}
