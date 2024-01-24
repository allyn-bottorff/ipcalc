use std::env;
use std::net::Ipv4Addr;

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
    let _subnet_arg = args.next();

    let ip_string = match ip_arg {
        Some(s) => s,
        None => panic!("Please enter an IP address."),
    };

    let ip_parsed = match parse_ip_v4(&ip_string) {
        Some(ip) => ip,
        None => panic!("Unable to parse IP addresss argument."),
    };

    print!("{} ", ip_string);
    ip_parsed.octets().map(|o| print!("{o:08b} "));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_tests() {}

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
