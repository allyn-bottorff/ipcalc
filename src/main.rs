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

use std::env;
use std::net::Ipv4Addr;

fn main() {
    let mut args = env::args();

    let _path = args.next();
    let ip_arg = args.next();
    let subnet_arg = args.next();

    let ip_string = match ip_arg {
        Some(s) => s,
        None => panic!("Please enter an IP address."),
    };

    let ip_parsed = match parse_ip_v4(&ip_string) {
        Some(ip) => ip,
        None => panic!("Unable to parse IP addresss argument."),
    };

    let cidr = match subnet_arg {
        Some(c) => match parse_cidr(&c) {
            Some(cidr) => cidr,
            None => panic!("Unable to parse subnet mask."),
        },
        None => panic!("Please enter a subnet mask in CIDR format."),
    };

    let net_addr = get_network_addr(&ip_parsed, &cidr);
    let first_host = get_first_host(&net_addr);
    let host_mask = get_host_mask(&cidr);
    let last_host = get_last_host(&net_addr, &host_mask);
    let broadcast = get_broadcast(&net_addr, &host_mask);
    let hosts_per_net = get_hosts_per_net(&first_host, &broadcast);

    print!("{:15} {:15}", "IP: ", ip_parsed);
    ip_parsed.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "Subnet mask: ", cidr);
    cidr.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "Network: ", net_addr);
    net_addr.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "Broadcast: ", broadcast);
    broadcast.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "Host Mask: ", host_mask);
    host_mask.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "First host: ", first_host);
    first_host.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "Last host: ", last_host);
    last_host.octets().map(|o| print!("{o:08b} "));
    println!();
    println!("{:15} {}", "Hosts per net: ", hosts_per_net);
}

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

fn get_first_host(net: &Ipv4Addr) -> Ipv4Addr {
    let host: u32 = (*net).into();
    Ipv4Addr::from(host + 1)
}

fn get_host_mask(subnet: &Ipv4Addr) -> Ipv4Addr {
    let subnet: u32 = (*subnet).into();
    let mask: u32 = u32::MAX;
    let broadcast: u32 = !(subnet & mask);

    Ipv4Addr::from(broadcast)
}

fn get_last_host(network: &Ipv4Addr, host_mask: &Ipv4Addr) -> Ipv4Addr {
    let subnet: u32 = (*network).into();
    let host_mask: u32 = (*host_mask).into();
    let last_host: u32 = subnet | host_mask - 1;

    Ipv4Addr::from(last_host)
}

fn get_hosts_per_net(first_host: &Ipv4Addr, broadcast: &Ipv4Addr) -> u32 {
    let broadcast: u32 = (*broadcast).into();
    let first_host: u32 = (*first_host).into();

    broadcast - first_host
}

fn get_network_addr(ip: &Ipv4Addr, subnet: &Ipv4Addr) -> Ipv4Addr {
    let host: u32 = (*ip).into();
    let subnet: u32 = (*subnet).into();
    let net_addr = host & subnet;
    Ipv4Addr::from(net_addr)
}

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
        let expected: Ipv4Addr = [192, 168, 1, 255].into();
        let network: Ipv4Addr = [192, 168, 1, 0].into();
        let host_mask: Ipv4Addr = [0, 0, 0, 255].into();
        let broadcast = get_broadcast(&network, &host_mask);
        assert_eq!(expected, broadcast);
    }
    #[test]
    fn test_get_hosts_per_net() {
        let expected = 254;
        let first: Ipv4Addr = [192, 168, 1, 1].into();
        let broadcast: Ipv4Addr = [192, 168, 1, 255].into();
        let hosts_per_net = get_hosts_per_net(&first, &broadcast);

        assert_eq!(expected, hosts_per_net);
    }
    #[test]
    fn test_get_last_host() {
        let expected: Ipv4Addr = [192, 168, 1, 254].into();
        let network: Ipv4Addr = [192, 168, 1, 0].into();
        let host_mask: Ipv4Addr = [0, 0, 0, 255].into();
        let last_host = get_last_host(&network, &host_mask);

        assert_eq!(expected, last_host);
    }

    #[test]
    fn test_get_host_mask() {
        let expected: Ipv4Addr = [0, 0, 0, 255].into();
        let subnet: Ipv4Addr = [255, 255, 255, 0].into();
        let broadcast = get_host_mask(&subnet);
        assert_eq!(expected, broadcast);
    }

    #[test]
    fn test_get_first_addr() {
        let expected: Ipv4Addr = [192, 168, 1, 1].into();
        let host: Ipv4Addr = [192, 168, 1, 15].into();
        let subnet: Ipv4Addr = [255, 255, 255, 0].into();

        let net_addr = get_network_addr(&host, &subnet);
        let first_addr = get_first_host(&net_addr);

        assert_eq!(expected, first_addr);
    }

    #[test]
    fn test_get_net_addr() {
        let expected: Ipv4Addr = [192, 168, 1, 0].into();
        let host: Ipv4Addr = [192, 168, 1, 15].into();
        let subnet: Ipv4Addr = [255, 255, 255, 0].into();

        let net_addr = get_network_addr(&host, &subnet);

        assert_eq!(expected, net_addr);
    }

    #[test]
    fn test_parse_cidr_class_c() {
        let expected: Ipv4Addr = [255, 255, 255, 0].into();
        let test_cidr = "/24";
        let mask = parse_cidr(test_cidr);
        assert_eq!(mask.unwrap(), expected);
    }
    #[test]
    fn test_parse_cidr_partial() {
        let expected: Ipv4Addr = [255, 255, 254, 0].into();
        let test_cidr = "/23";
        let mask = parse_cidr(test_cidr);
        assert_eq!(mask.unwrap(), expected);
    }

    #[test]
    fn test_parse_good_ip_v4() {
        let expected: Ipv4Addr = [127, 0, 0, 1].into();
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
