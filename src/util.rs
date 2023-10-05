use rust_util::XResult;

// "example.com" -> ("@", "example.com")
// "www.example.com" -> ("www", "example.com")
pub fn parse_dns_record(record: &str) -> XResult<(String, String)> {
    let r = if record.ends_with(".") {
        record.chars().take(record.len() - 1).collect::<String>().to_ascii_lowercase()
    } else {
        record.to_ascii_lowercase()
    };

    let parts: Vec<&str> = r.split(".").collect();
    if parts.len() < 2 {
        return simple_error!("Invalid record : {}", record);
    }

    let last_part = parts[parts.len() - 1];
    let last_part_2 = parts[parts.len() - 2];

    // SHOULD read from: https://publicsuffix.org/
    let domain_parts_len = match last_part {
        "cn" => match last_part_2 {
            "com" | "net" | "org" | "gov" | "edu" => 3,
            _ => 2,
        },
        _ => 2,
    };

    if parts.len() < domain_parts_len {
        return simple_error!("Invalid record: {}", record);
    }

    let domain = parts.iter().skip(parts.len() - domain_parts_len).map(|s| s.to_string()).collect::<Vec<String>>().join(".");
    let rr = parts.iter().take(parts.len() - domain_parts_len).map(|s| s.to_string()).collect::<Vec<String>>().join(".");

    Ok((if rr.is_empty() { "@".to_string() } else { rr }, domain))
}