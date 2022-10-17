/*
 *
 * Implementation KVM connect, parse and extract tty device for a KVM virtual machine
 * Author: peternguyen
 */
use virt::connect::Connect;
use virt::domain::Domain;
use regex::Regex;

pub fn kvm_extract_pty(vm_name: &str) -> String {

    let conn = Connect::open("qemu:///system").expect(
                            "Unable to connect to \"qemu:///system\" ");

    let select_domain = Domain::lookup_by_name(&conn, vm_name);
    if select_domain.is_err() {
        panic!("Unable to find domain: {}", vm_name);
    }

    let xml_desc = select_domain.unwrap()
                        .get_xml_desc(virt::domain::VIR_DOMAIN_NONE)
                            .expect("Unable to extract xml_desc");

    //parse xml description to get pty device path
    let re = Regex::new(r"<source path='(/dev/pts/\d+)'/>")
                        .expect("Unable to etract tty dev path from XML");
    let caps = re.captures(&xml_desc).expect("Unable to get tty dev from XML Desc");

    let pty_device = caps.get(1).map_or("", |m| m.as_str());
    return pty_device.to_string();
}
