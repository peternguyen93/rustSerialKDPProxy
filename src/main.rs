#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::panic;
use std::{net::UdpSocket, os::unix::prelude::IntoRawFd};
use std::os::unix::net::UnixStream;
use std::io::{self, Write};
use clap::Parser;
use libc::{c_void, c_char, sockaddr_in};

mod kdp_export;
use kdp_export::*;

static mut opt_verbose: bool = false;
static mut g_linecount: u32 = 0; 
static mut serial_fd: i32 = -1;
static mut out_ip_id: u16 = 0;

const REVERSE_VIDEO: &str = "\x1b[7m";
const NORMAL_VIDEO: &str = "\x1b[0m";

static DEFAULT_LISTEN_IP: &str = "0.0.0.0";
static client_macaddr: [u8 ; ETHER_ADDR_LEN as usize] = [b's', b'e', b'r', b'i', b'a', b'l'];
static our_macaddr: [u8 ; ETHER_ADDR_LEN as usize]    = [b'f', b'o', b'o', b'b', b'a', b'r'];

unsafe extern "C" fn serial_putc(chr: c_char)
{
	assert!(serial_fd != -1, "Serial port didn't open");

	assert!(libc::write(serial_fd, std::ptr::addr_of!(chr) as *mut c_void, 1) == 1, "Unable to write data to serial_fd");
	
	if g_linecount != 0 && (g_linecount % 16) == 0 {
		g_linecount = 0;
	}

	if opt_verbose {
		if chr as u8 == 0xfb {
			// stop character
			print!("\n");
			io::stdout().flush().unwrap();
			g_linecount = 0;
		} else {
			if chr as u8 != 0xfa {
				// skip star character
				print!("{:#04X} ", chr as u8);
				io::stdout().flush().unwrap();
				g_linecount+=1;
			}
		}
	}
}

fn set_termopts(serial_dev_fd: i32)
{
	let mut rc : i32;
	unsafe {
		let mut options: libc::termios = std::mem::zeroed();
		
		libc::tcgetattr(serial_dev_fd, std::ptr::addr_of_mut!(options));
		rc = libc::cfsetispeed(std::ptr::addr_of_mut!(options), libc::B115200);
		if rc == -1 {
			panic!("[!] Error, could not set baud rate");
		}

		rc = libc::cfsetospeed(std::ptr::addr_of_mut!(options), libc::B115200);
		if rc == -1 {
			panic!("[!] Error, could not set baud rate");
		}

		options.c_iflag = 0;
		options.c_oflag = 0;
		options.c_cflag = libc::CS8 | libc::CREAD | libc::CLOCAL;
		options.c_lflag = 0;
		options.c_cc[libc::VMIN] = 1;
		options.c_cc[libc::VTIME] = 5;

		libc::tcflush(serial_dev_fd, libc::TCIFLUSH);
		rc = libc::tcsetattr(serial_dev_fd, libc::TCSANOW, std::ptr::addr_of_mut!(options));
		if rc == -1 {
			panic!("[!] Error, call tcsetattr was failed");
		}
	}
}

fn setup_udp_frame(pframe: &mut frame_t, sAddr: libc::in_addr, port: u32, dataLen: usize)
{
	let sizeof_ip = std::mem::size_of::<ip>() as u32;
	let sizeof_uphdr = std::mem::size_of::<udphdr>() as u32;

	unsafe {
		for i in 0..client_macaddr.len() {
			pframe.h.eh.ether_dhost[i] = client_macaddr[i];
		}

		for i in 0..our_macaddr.len() {
			pframe.h.eh.ether_shost[i] = our_macaddr[i];
		}

		pframe.h.eh.ether_type = htons(ETHERTYPE_IP as u16);
		pframe.h.ih.set_ip_v(4);
		pframe.h.ih.set_ip_hl((sizeof_ip >> 2) as u8);
		pframe.h.ih.ip_tos = 0;

		let ip_len = sizeof_ip + sizeof_uphdr + dataLen as u32;

		pframe.h.ih.ip_len = htons(ip_len as u16);
		out_ip_id += 1;
		pframe.h.ih.ip_id = htons(out_ip_id as u16);
		pframe.h.ih.ip_off = 0;
		pframe.h.ih.ip_ttl = 60; // UDP_TTL from kdp_udp.c
		pframe.h.ih.ip_p = libc::IPPROTO_UDP as u8;
		pframe.h.ih.ip_sum = 0;
		pframe.h.ih.ip_src = sAddr;
		pframe.h.ih.ip_dst.s_addr =  0xABADBABE; // FIXME: Endian.. little to little will be fine here.

		let ip_sum_result = !ip_sum(std::ptr::addr_of_mut!(pframe.h.ih) as *mut u8, pframe.h.ih.get_ip_hl() as u32);

		pframe.h.ih.ip_sum = ip_sum_result.to_be();
		pframe.h.uh.uh_sport = port as u16;
		pframe.h.uh.uh_dport = htons(41139);
		pframe.h.uh.uh_ulen = htons((sizeof_uphdr + dataLen as u32) as u16);
		pframe.h.uh.uh_sum = 0;
	}
}

#[cfg(target_os = "linux")]
fn timval_set(tv: &mut libc::timeval, timeout : i64)
{
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 10;
}

#[cfg(target_os = "macos")]
fn timval_set(tv: &mut libc::timeval, timeout: i64)
{
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout as i32 % 1000) * 10;
}

#[cfg(target_os = "linux")]
fn sockaddr_in_set(sockaddr: &mut libc::sockaddr_in, port: u16, s_addr: u32)
{
	sockaddr.sin_family = libc::AF_INET as u16;
	sockaddr.sin_port = port as u16;
	sockaddr.sin_addr.s_addr = s_addr as u32;
}

#[cfg(target_os = "macos")]
fn sockaddr_in_set(sockaddr: &mut libc::sockaddr_in, port: u16, s_addr: u32)
{
	sockaddr.sin_family = libc::AF_INET as u8;
	sockaddr.sin_port = port as u16;
	sockaddr.sin_addr.s_addr = s_addr as u32;
}

fn working_pool(fds: &mut Vec<libc::pollfd>, timeout: i32) -> i32
{
	unsafe {
		let mut readfds : libc::fd_set  = std::mem::zeroed();
		let mut writefds : libc::fd_set = std::mem::zeroed();
		let mut errfds : libc::fd_set   = std::mem::zeroed();
		let mut tv : libc::timeval = std::mem::zeroed();
		let mut maxfd = 0;
		let mut ret;
		let tv_ptr ;

		if timeout > 0 {
			timval_set(&mut tv, timeout as i64);
			tv_ptr = std::ptr::addr_of_mut!(tv);
		} else {
			tv_ptr = std::ptr::null_mut() as *mut libc::timeval;
		}

		for i in 0..fds.len() {
			if fds[i].fd + 1 > maxfd {
				maxfd = fds[i].fd + 1;
			}

			if (fds[i].events & libc::POLLIN) != 0 {
				libc::FD_SET(fds[i].fd, std::ptr::addr_of_mut!(readfds));
			}

			if (fds[i].events & libc::POLLOUT) != 0 {
				libc::FD_SET(fds[i].fd, std::ptr::addr_of_mut!(writefds));
			}
		}

		
		ret = libc::select(maxfd, std::ptr::addr_of_mut!(readfds),
						std::ptr::addr_of_mut!(writefds),
						std::ptr::addr_of_mut!(errfds),
						tv_ptr);
		if ret <= 0 {
			libc::perror("select".as_ptr() as *const i8);
			return ret;
		}

		ret = 0;
		for i in 0..fds.len() {
			fds[i].revents = 0;

			if libc::FD_ISSET(fds[i].fd, std::ptr::addr_of_mut!(readfds)) {
				fds[i].revents |= libc::POLLIN;
			}

			if libc::FD_ISSET(fds[i].fd, std::ptr::addr_of_mut!(writefds)) {
				fds[i].revents |= libc::POLLOUT;
			}

			if libc::FD_ISSET(fds[i].fd, std::ptr::addr_of_mut!(writefds)) {
				fds[i].revents |= libc::POLLERR;
			}

			if fds[i].revents != 0 {
				ret += 1;
			}
		}

		return ret;
	}
}


fn serialKDPProxy(listen_ip: &String, port: u32)
{
	let bindip = &format!("{}:{}", listen_ip, port);
	let r_udp_sock = UdpSocket::bind(bindip).expect("Couldn't bind udp socket");
	let udp_fd = r_udp_sock.into_raw_fd();

	println!("[+] Waiting for receving packaget at {}...", bindip);

	unsafe {
		let mut fds : Vec<libc::pollfd> = Vec::new();
		fds.push(libc::pollfd {
			fd: udp_fd,
			events : libc::POLLIN,
			revents : 0
		});
		fds.push(libc::pollfd {
			fd: serial_fd,
			events : libc::POLLIN,
			revents : 0
		});
		fds.push(libc::pollfd {
			fd: libc::STDOUT_FILENO,
			events : libc::POLLIN,
			revents : 0
		});
		let mut frame : Box<frame_t> = Box::new(frame_t {
			buf : std::mem::zeroed(),
		});

		while working_pool(&mut fds, -1) > 0 {
			if (fds[0].revents & libc::POLLIN) != 0 {
				let mut sock_addr : sockaddr_in = std::mem::zeroed();
				let mut sock_addr_size : u32 = std::mem::size_of::<sockaddr_in>() as u32;
				let bytesReceived : isize = libc::recvfrom(udp_fd,
										frame.buf.as_ptr().offset(std::mem::size_of::<udp_ip_ether_frame_hdr>() as isize) as *mut c_void,
										std::mem::size_of::<frame_t>() - std::mem::size_of::<udp_ip_ether_frame_hdr>(),
										0,
										std::ptr::addr_of_mut!(sock_addr) as *mut libc::sockaddr,
										std::ptr::addr_of_mut!(sock_addr_size));

				if opt_verbose {
					eprintln!("Receiving {} bytes from {}:{}", bytesReceived, inet_ntoa(sock_addr.sin_addr).as_str(), sock_addr.sin_port);
				}

				setup_udp_frame(frame.as_mut(), sock_addr.sin_addr, sock_addr.sin_port as u32, bytesReceived as usize);
				kdp_serialize_packet(frame.buf.as_ptr() as *mut u8,
					(bytesReceived as usize + std::mem::size_of::<udp_ip_ether_frame_hdr>()) as u32,
					serial_putc);
				io::stderr().flush().unwrap();
			} else if fds[0].revents != 0 {
				eprintln!("[!] Unexpected revents of udp socket");
			}

			if (fds[1].revents & libc::POLLIN) != 0{
				let mut chr : char = std::mem::zeroed();

				if libc::read(serial_fd, std::ptr::addr_of_mut!(chr) as *mut c_void, 1) == 1{
					// serial_fd is readable
					let mut input_len: u32 = SERIALIZE::SERIALIZE_READING as u32;
					let p_input_package = kdp_unserialize_packet(chr as u8, std::ptr::addr_of_mut!(input_len));

					if !p_input_package.is_null() {
						let p_kdp_package : Box<frame_t> = Box::new(std::ptr::read(p_input_package as *const frame_t));
						if p_kdp_package.h.ih.ip_p == 17 {
							// send data to udp_fd
							let mut client_addr : libc::sockaddr_in = std::mem::zeroed();
							sockaddr_in_set(&mut client_addr, p_kdp_package.h.uh.uh_dport, p_kdp_package.h.ih.ip_dst.s_addr);

							libc::sendto(udp_fd,
									p_kdp_package.buf.as_ptr().offset(std::mem::size_of::<udp_ip_ether_frame_hdr>() as isize) as *const c_void,
									input_len as usize - std::mem::size_of::<udp_ip_ether_frame_hdr>(), 0,
									std::ptr::addr_of_mut!(client_addr) as *const libc::sockaddr,
									std::mem::size_of::<udp_ip_ether_frame_hdr>() as u32);
						
						} else {
							eprintln!("[!] Unable to deserialize kdp package");
						}
					} else {
						if input_len == SERIALIZE::SERIALIZE_WAIT_START as u32 {
							let b = chr as u8;

							if (b >= 0x80) || (b > 26 && chr < ' ') {
								print!("{}{:#04X}{}", REVERSE_VIDEO, b, NORMAL_VIDEO);
								io::stdout().flush().unwrap();
							} else if (b <= 26) && (chr != '\r') && (chr != '\n'){
								print!("{}^{}{}", REVERSE_VIDEO, (b + '@' as u8) as char, NORMAL_VIDEO);
								io::stdout().flush().unwrap();
							} else {
								libc::putchar(b as i32);
							}
						}
					}
				}
			} else {
				if fds[1].revents != 0 {
					eprintln!("Shutting down serial input due to {:#04X}", fds[1].revents);
					fds[1].revents = 0;
				}
			}
		}
	}
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct SerialKDPArg {
	/// The pattern to look fr
	#[clap(parse(from_os_str))]
	serial_path : std::path::PathBuf, // store serial device path
	#[clap(short, long)]
	listen : Option<String>,
	#[clap(short, long, default_value_t = 4444)]
	port   : u32,
	#[clap(short, long, default_value_t = 0)]
	verbose : u8
}

fn main()
{
	let serial_path : std::path::PathBuf;
	let listen_ip : String;
	let port : u32;
	let args = SerialKDPArg::parse();

	serial_path = args.serial_path;
	listen_ip = args.listen.unwrap_or(DEFAULT_LISTEN_IP.to_string());
	port = args.port;

	unsafe {
		opt_verbose = args.verbose == 1;
	}

	if !serial_path.exists() {
		panic!("Serial port {} doesn't exists.", serial_path.to_str().unwrap());
	}

	unsafe {
		// asume this serial device is pty
		let raw_serial_path : &str = serial_path.to_str().unwrap();

		print!("[!] Trying to open {} as pty device...", raw_serial_path);

		serial_fd = libc::open(
			raw_serial_path.as_ptr() as *mut std::os::raw::c_schar,
			libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOCTTY
		);

		if serial_fd < 0 {
			print!("\n[!] Trying to open {} as unix socket...", raw_serial_path);
			let unix_stream = UnixStream::connect(raw_serial_path).expect(
									&format!("Unable to open device {} as unix socket", raw_serial_path));
			serial_fd = unix_stream.into_raw_fd();

			println!("OK");
		} else {
			println!("OK");
			set_termopts(serial_fd);
		}
	}

	serialKDPProxy(&listen_ip, port);
}
