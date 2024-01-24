use std::env;
use std::net::Ipv4Addr;
// use std::ops::BitAnd;

/*
Address:   192.168.0.1           11000000.10101000.00000000 .00000001
Netmask:   255.255.255.0 = 24    11111111.11111111.11111111 .00000000
Wildcard:  0.0.0.255             00000000.00000000.00000000 .11111111
=>
Network:   192.168.0.0/24        11000000.10101000.00000000 .00000000 (Class C)
Broadcast: 192.168.0.255         11000000.10101000.00000000 .11111111
HostMin:   192.168.0.1           11000000.10101000.00000000 .00000001
HostMax:   192.168.0.254         11000000.10101000.00000000 .11111110
Hosts/Net: 254                   (Private Internet)
*/

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

    print!("{:15} {:15}", "IP: ", ip_parsed);
    ip_parsed.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "Subnet mask: ", cidr);
    cidr.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "Network: ", net_addr);
    net_addr.octets().map(|o| print!("{o:08b} "));
    println!();
    print!("{:15} {:15}", "First host: ", first_host);
    first_host.octets().map(|o| print!("{o:08b} "));
    println!();
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
    let mut mask: [u8; 4] = [255; 4];

    let bit_shift = 32 - cidr;

    let mut cleared_octets = (bit_shift / 8) as usize;
    let partial_octet_bits = 8 - (cidr % 8);

    for i in 0..mask.len() {
        let k = mask.len() - 1 - i; //reverse the loop
        mask[k] = 0;
        if cleared_octets > 0 {
            cleared_octets -= 1;
        }
        if cleared_octets == 0 {
            if k >= 1 && partial_octet_bits != 8 {
                //Shift bits as long as there are actual
                //leftovers and we won't run off the end of the
                //array.
                mask[k - 1] <<= partial_octet_bits;
            }
            break;
        }
    }

    Some(Ipv4Addr::from(mask))
}

fn get_first_host(net: &Ipv4Addr) -> Ipv4Addr {
    let mut host: [u8; 4] = net.octets();

    if host[3] == 255 {
        if host[2] == 255 {
            if host[1] == 255 {
                host[0] += 1;
            } else {
                host[1] += 1;
            }
        } else {
            host[2] += 1;
        }
    } else {
        host[3] += 1;
    }

    Ipv4Addr::from(host)
}

fn get_last_host(net_addr: &Ipv4Addr, subnet: &Ipv4Addr) -> Ipv4Addr {
    let mut host: [u8;4] = [0;4];


    for i in 0..net_addr.octets().len() {
        host[i] = net_addr.octets()[i] & subnet.octets()[i];
    }

    Ipv4Addr::from(host)

}

fn get_network_addr(ip: &Ipv4Addr, subnet: &Ipv4Addr) -> Ipv4Addr {
    let hosts = ip.octets();
    let subnet = subnet.octets();

    let mut net_addr: [u8; 4] = [0; 4];

    for i in 0..hosts.len() {
        net_addr[i] = hosts[i] & subnet[i];
    }

    Ipv4Addr::from(net_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

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
