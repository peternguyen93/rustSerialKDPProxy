# rustSerialKDPProxy

* This project inspired from https://github.com/stefanesser/serialKDPproxy and rewritten in Rust.
* rustSerialKDPProxy supported to connect to unix socket as a serial socket which is available in some Virtual Machines likes VMWare, Virtual Box.
* rustSerialKDPProxy help to debug macOS kernel in KVM Linux via internet.

# How to use

* Installing a lastest Rust version via their website.
* Run following command to build.
		```
		$ cd rustSerialKDPProxy;
		$ cargo build --release
		```
* Start a proxy with pts device in KVM :
		```
		$ sudo ./target/release/rustSerialKDPProxy -k "<virtual machine name>" --port <port> --listen <interface>
		```
* Start a proxy with pts device / unix socket :
		```
		$ sudo ./target/release/rustSerialKDPProxy -s "/dev/pts/<num> or </path/unix.sock>" --port <port> --listen <interface>
		```
