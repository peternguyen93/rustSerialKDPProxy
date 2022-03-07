
use cc;

fn main() {
	cc::Build::new().file("src/kdp_serial.c").compile("lib_kdp_serial.a");
}
