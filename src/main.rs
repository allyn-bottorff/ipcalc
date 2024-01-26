// Copyright 2023 Allyn L. Bottorff
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::Parser;
use std::{net::Ipv4Addr, process::exit};

const COL1: usize = 15; // spacing constant for column 1
const COL2: usize = 17; // spacing constant for column 2

// Classful IP constants
const CLASS_A_SUBNET: Ipv4Addr = Ipv4Addr::new(255, 0, 0, 0);
const CLASS_B_SUBNET: Ipv4Addr = Ipv4Addr::new(255, 255, 0, 0);
const CLASS_C_SUBNET: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const CLASS_A_START: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const CLASS_A_END: Ipv4Addr = Ipv4Addr::new(127, 255, 255, 255);
const CLASS_B_START: Ipv4Addr = Ipv4Addr::new(128, 0, 0, 0);
const CLASS_B_END: Ipv4Addr = Ipv4Addr::new(191, 255, 255, 255);
const CLASS_C_START: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 0);
const CLASS_C_END: Ipv4Addr = Ipv4Addr::new(223, 255, 255, 255);
// const CLASS_D_START: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 0);
// const CLASS_D_END: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 255);
// const CLASS_E_START: Ipv4Addr = Ipv4Addr::new(240, 0, 0, 0);
// const CLASS_E_END: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// IP address and subnet calculator.
#[derive(Parser)]
#[command(author, version, about, long_about=None)]
struct Cli {
    /// IP Address (v4)
    ip: String,
    /// Subnet (CIDR notation e.g. "/24")
    subnet: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let ip_parsed = match parse_ip_v4(&cli.ip) {
        Some(ip) => ip,
        None => {
            eprintln!("Unable to parse IP addresss argument.");
            exit(1);
        }
    };

    // Print IP address line
    print!("{:COL1$} {:COL2$}", "IP: ", ip_parsed);
    ip_parsed.octets().map(|o| print!("{o:08b} "));
    println!();

    let subnet_mask = match cli.subnet {
        Some(sub) => match parse_cidr(&sub) {
            Some(cidr) => Some(cidr),
            None => {
                eprintln!("Unable to parse subnet mask.");
                exit(1);
            }
        },
        None => get_default_subnet(&ip_parsed),
    };

    // Process the subnet dependent parts if there is a subnet mask
    if let Some(subnet_mask) = subnet_mask {
        let net_addr = get_network_addr(&ip_parsed, &subnet_mask);
        let first_host = get_first_host(&net_addr);
        let host_mask = get_host_mask(&subnet_mask);
        let last_host = get_last_host(&net_addr, &host_mask);
        let broadcast = get_broadcast(&net_addr, &host_mask);
        let hosts_per_net = get_hosts_per_net(&first_host, &broadcast);

        print!("{:COL1$} {:COL2$}", "Subnet mask: ", subnet_mask);
        subnet_mask.octets().map(|o| print!("{o:08b} "));
        println!();
        print!("{:COL1$} {:COL2$}", "Network: ", net_addr);
        net_addr.octets().map(|o| print!("{o:08b} "));
        println!();
        print!("{:COL1$} {:COL2$}", "Broadcast: ", broadcast);
        broadcast.octets().map(|o| print!("{o:08b} "));
        println!();
        print!("{:COL1$} {:COL2$}", "Host Mask: ", host_mask);
        host_mask.octets().map(|o| print!("{o:08b} "));
        println!();
        print!("{:COL1$} {:COL2$}", "First host: ", first_host);
        first_host.octets().map(|o| print!("{o:08b} "));
        println!();
        print!("{:COL1$} {:COL2$}", "Last host: ", last_host);
        last_host.octets().map(|o| print!("{o:08b} "));
        println!();
        println!("{:COL1$} {}", "Hosts per net: ", hosts_per_net);
    }
}

/// Parse the IPV4 address string into an optional IP address. Return None if something goes wrong
/// with the conversion or if the address is malformed.
fn parse_ip_v4(ip_string: &str) -> Option<Ipv4Addr> {
    let str_split: Vec<&str> = ip_string.split('.').collect();

    let mut u8vec = Vec::new();

    for s in str_split {
        let octet = s.parse::<u8>();
        match octet {
            Ok(o) => u8vec.push(o),
            Err(_) => return None,
        }
    }

    let mut u8s: [u8; 4] = [0; 4];
    if u8vec.len() != 4 {
        return None;
    } else {
        u8s[..4].copy_from_slice(&u8vec[..4]);
    }
    Some(Ipv4Addr::from(u8s))
}

/// Find default subnet for the IP (assuming classful routing and not CIDR)
fn get_default_subnet(ip: &Ipv4Addr) -> Option<Ipv4Addr> {
    let ip_u32: u32 = (*ip).into();

    if ip_u32 >= u32::from(CLASS_C_START) && ip_u32 <= u32::from(CLASS_C_END) {
        return Some(CLASS_C_SUBNET);
    }
    if ip_u32 >= u32::from(CLASS_B_START) && ip_u32 <= u32::from(CLASS_B_END) {
        return Some(CLASS_B_SUBNET);
    }
    if ip_u32 >= u32::from(CLASS_A_START) && ip_u32 <= u32::from(CLASS_A_END) {
        return Some(CLASS_A_SUBNET);
    }

    None
}

/// Parse the CIDR formatted string into a netmask formatted as an IP address
fn parse_cidr(cidr_string: &str) -> Option<Ipv4Addr> {
    if &cidr_string[..1] != "/" {
        return None;
    }
    let cidr_val = &cidr_string[1..];
    let cidr = match cidr_val.parse::<u8>() {
        Ok(c) => c,
        Err(_) => return None,
    };

    if cidr > 32 {
        return None;
    }
    let mut mask: u32 = u32::MAX;

    let bit_shift = 32 - cidr;

    mask <<= bit_shift;

    Some(Ipv4Addr::from(mask))
}

/// Get the first address available for hosts in the network
fn get_first_host(net: &Ipv4Addr) -> Ipv4Addr {
    let host: u32 = (*net).into();

    Ipv4Addr::from(host + 1)
}

/// Get the host mask for the network (wildcard mask)
fn get_host_mask(subnet: &Ipv4Addr) -> Ipv4Addr {
    let subnet: u32 = (*subnet).into();
    let mask: u32 = u32::MAX;
    let broadcast: u32 = !(subnet & mask);

    Ipv4Addr::from(broadcast)
}

/// Get the last host address available for hosts in the network
fn get_last_host(network: &Ipv4Addr, host_mask: &Ipv4Addr) -> Ipv4Addr {
    let subnet: u32 = (*network).into();
    let host_mask: u32 = (*host_mask).into();
    let last_host: u32 = (subnet | host_mask) - 1;

    Ipv4Addr::from(last_host)
}

/// Get the number of addresses available to assign to hosts in the network
fn get_hosts_per_net(first_host: &Ipv4Addr, broadcast: &Ipv4Addr) -> u32 {
    let broadcast: u32 = (*broadcast).into();
    let first_host: u32 = (*first_host).into();

    broadcast - first_host
}

/// Get the network address of the network
fn get_network_addr(ip: &Ipv4Addr, subnet: &Ipv4Addr) -> Ipv4Addr {
    let host: u32 = (*ip).into();
    let subnet: u32 = (*subnet).into();
    let net_addr = host & subnet;

    Ipv4Addr::from(net_addr)
}

/// Get the broadcast address of the network
fn get_broadcast(network: &Ipv4Addr, host_mask: &Ipv4Addr) -> Ipv4Addr {
    let subnet: u32 = (*network).into();
    let host_mask: u32 = (*host_mask).into();
    let broadcast: u32 = subnet | host_mask;

    Ipv4Addr::from(broadcast)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_broadcast() {
        let expected: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 255);
        let network: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 0);
        let host_mask: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 255);
        let broadcast = get_broadcast(&network, &host_mask);
        assert_eq!(expected, broadcast);
    }
    #[test]
    fn test_get_hosts_per_net() {
        let expected = 254;
        let first: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
        let broadcast: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 255);
        let hosts_per_net = get_hosts_per_net(&first, &broadcast);
        assert_eq!(expected, hosts_per_net);
    }
    #[test]
    fn test_get_last_host() {
        let expected: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 254);
        let network: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 0);
        let host_mask: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 255);
        let last_host = get_last_host(&network, &host_mask);
        assert_eq!(expected, last_host);
    }

    #[test]
    fn test_get_host_mask() {
        let expected: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 255);
        let subnet: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
        let broadcast = get_host_mask(&subnet);
        assert_eq!(expected, broadcast);
    }

    #[test]
    fn test_get_first_addr() {
        let expected: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
        let host: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 15);
        let subnet: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
        let net_addr = get_network_addr(&host, &subnet);
        let first_addr = get_first_host(&net_addr);
        assert_eq!(expected, first_addr);
    }

    #[test]
    fn test_get_net_addr() {
        let expected: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 0);
        let host: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 15);
        let subnet: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
        let net_addr = get_network_addr(&host, &subnet);
        assert_eq!(expected, net_addr);
    }

    #[test]
    fn test_parse_cidr_class_c() {
        let expected: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
        let test_cidr = "/24";
        let mask = parse_cidr(test_cidr);
        assert_eq!(mask.unwrap(), expected);
    }
    #[test]
    fn test_parse_cidr_partial() {
        let expected: Ipv4Addr = Ipv4Addr::new(255, 255, 254, 0);
        let test_cidr = "/23";
        let mask = parse_cidr(test_cidr);
        assert_eq!(mask.unwrap(), expected);
    }

    #[test]
    fn test_parse_good_ip_v4() {
        let expected: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
        let test_string: String = "127.0.0.1".to_string();
        let test_ip = parse_ip_v4(&test_string);
        assert_eq!(test_ip.unwrap(), expected);
    }
    #[test]
    fn test_parse_long_ip_v4() {
        let test_string: String = "127.0.0.1.2".to_string();
        let test_ip = parse_ip_v4(&test_string);
        assert_eq!(test_ip, None);
    }
    #[test]
    fn test_parse_bad_ip_v4() {
        let test_string: String = "127.0.340.2".to_string();
        let test_ip = parse_ip_v4(&test_string);
        assert_eq!(test_ip, None);
    }
    #[test]
    fn test_parse_short_ip_v4() {
        let test_string: String = "127.0.40".to_string();
        let test_ip = parse_ip_v4(&test_string);
        assert_eq!(test_ip, None);
    }
    #[test]
    fn test_parse_not_an_ip_v4() {
        let test_string: String = "stuff".to_string();
        let test_ip = parse_ip_v4(&test_string);
        assert_eq!(test_ip, None);
    }
}
