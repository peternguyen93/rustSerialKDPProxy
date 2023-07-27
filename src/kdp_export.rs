
use std::os::raw::{c_char, c_uchar};
pub const ETHER_ADDR_LEN: u32 = 6;
pub const ETHERTYPE_IP: u32 = 2048;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ether_header {
    pub ether_dhost: [c_uchar; ETHER_ADDR_LEN as usize],
    pub ether_shost: [c_uchar; ETHER_ADDR_LEN as usize],
    pub ether_type: u16
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct udphdr {
    pub uh_sport: u16, /* source port */
    pub uh_dport: u16, /* destination port */
    pub uh_ulen: u16,  /* udp length */
    pub uh_sum: u16    /* udp checksum */
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ip {
    pub ip_vhl: libc::c_uchar,
    pub ip_tos: libc::c_uchar,
    pub ip_len: libc::c_ushort,
    pub ip_id : libc::c_ushort,
    pub ip_off: libc::c_ushort,
    pub ip_ttl: libc::c_uchar,
    pub ip_p  : libc::c_uchar,
    pub ip_sum: libc::c_ushort,
    pub ip_src: libc::in_addr,
    pub ip_dst: libc::in_addr
}

impl ip {
    // implement set_ip_v / get_ip_v and set_ip_hl / get_ip_hl
    pub fn set_ip_v(&mut self, v: u8) {
        self.ip_vhl |= v & 0xF;
    }

    pub fn get_ip_v(&self) -> u8 {
        return self.ip_vhl & 0xF;
    }

    pub fn set_ip_hl(&mut self, hl: u8) {
        self.ip_vhl |= (hl & 0xF) << 4;
    }

    pub fn get_ip_hl(&self) -> u8 {
        return (self.ip_vhl >> 4) & 0xF;
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct udp_ip_ether_frame_hdr {
    pub eh: ether_header,
    pub ih: ip,
    pub uh: udphdr
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union frame_t {
    pub h: udp_ip_ether_frame_hdr,
    pub buf: [c_uchar; 1500]
}

// C exported functions
pub enum SERIALIZE {
    SERIALIZE_WAIT_START,
    SERIALIZE_READING
}

extern "C" {
    //pub fn ip_sum(buffer: *mut c_uchar, hlen: u32) -> u16;
    pub fn kdp_serialize_packet(buffer: *mut c_uchar, len: u32, func: unsafe extern "C" fn(chr: c_char));
    pub fn kdp_unserialize_packet (chr: c_uchar, out_len: *mut u32) -> *mut c_uchar;
}

// utilities function
pub fn htons(u_value: u16) -> u16
{
    return u_value.to_be();
}

pub fn inet_ntoa(sin_addr: libc::in_addr) -> String
{
    let mut ip_addr: String = String::new();

    for i in 0..4 {
        let num = (sin_addr.s_addr >> 8 * i) & 0xFF;
        ip_addr.push_str(num.to_string().as_str());
        if i < 3 {
            ip_addr.push('.');
        }
    }
    return ip_addr;
}

pub fn ip_sum(buffer: *mut u8, hlen: u32) -> u16
{
    let mut high: u32 = 0;
    let mut low: u32 = 0;
    let mut pbuffer: *mut u8 = buffer;
    let mut tlen: u32 = hlen;

    unsafe {
        while tlen > 0 {
            low += pbuffer.add(1).read() as u32 + pbuffer.add(3).read() as u32;
            high += pbuffer.read() as u32 + pbuffer.add(2).read() as u32;
            pbuffer = pbuffer.add(4);
            tlen -= 1;
        }
    }

	let mut sum: u32 = (high << 8) + low;
	sum = (sum >> 16) + (sum & 65535);

    if sum > 0xFFFF {
        return (sum - 0xFFFF) as u16;
    }
	return sum as u16;
}
