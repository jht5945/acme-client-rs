use std::error::Error;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use rust_util::XResult;
use x509_parser::{pem::parse_x509_pem, parse_x509_certificate};
use x509_parser::extensions::{ParsedExtension, GeneralName};
use x509_parser::der_parser::{ber::BerObjectContent, oid::Oid, parse_der};
use x509_parser::x509::SubjectPublicKeyInfo;

lazy_static! {
    static ref OID_COMMON_NAME: Oid<'static> = Oid::from_str("2.5.4.3").unwrap();
    static ref OID_RSA_WITH_SHA256: Oid<'static> = Oid::from_str("1.2.840.113549.1.1.11").unwrap();
    static ref OID_ECDSA_WITH_SHA256: Oid<'static> = Oid::from_str("1.2.840.10045.4.3.2").unwrap();

    static ref OID_EC_PUBLIC_KEY: Oid<'static> = Oid::from_str("1.2.840.10045.2.1").unwrap();
    static ref OID_RSA_PUBLIC_KEY: Oid<'static> = Oid::from_str("1.2.840.113549.1.1.1").unwrap();

    static ref OID_SECP256R1: Oid<'static> = Oid::from_str("1.2.840.10045.3.1.7").unwrap();
    static ref OID_SECP384R1: Oid<'static> = Oid::from_str("1.3.132.0.34").unwrap();
    static ref OID_SECP521R1: Oid<'static> = Oid::from_str("1.3.132.0.35").unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509IssuerAlgo {
    RsaWithSha256,
    EcdsaWithSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum X509EcPublicKeyAlgo {
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum X509PublicKeyAlgo {
    EcKey(X509EcPublicKeyAlgo),
    Rsa(u32),
}

impl Default for X509PublicKeyAlgo {
    fn default() -> Self {
        X509PublicKeyAlgo::Rsa(2048)
    }
}

impl ToString for X509PublicKeyAlgo {
    fn to_string(&self) -> String {
        match self {
            Self::Rsa(bit_length) => format!("rsa{}", bit_length),
            Self::EcKey(X509EcPublicKeyAlgo::Secp256r1) => "p256".into(),
            Self::EcKey(X509EcPublicKeyAlgo::Secp384r1) => "p384".into(),
            Self::EcKey(X509EcPublicKeyAlgo::Secp521r1) => "p521".into(),
        }
    }
}

impl FromStr for X509PublicKeyAlgo {
    type Err = Box<dyn Error>;

    fn from_str(algo_str: &str) -> Result<Self, Self::Err> {
        match algo_str {
            "ec256" | "p256" => Ok(Self::EcKey(X509EcPublicKeyAlgo::Secp256r1)),
            "ec384" | "p384" => Ok(Self::EcKey(X509EcPublicKeyAlgo::Secp384r1)),
            "ec521" | "p521" => Ok(Self::EcKey(X509EcPublicKeyAlgo::Secp521r1)),
            "rsa2048" => Ok(Self::Rsa(2048)),
            "rsa3072" => Ok(Self::Rsa(3072)),
            "rsa4096" => Ok(Self::Rsa(4096)),
            _ => simple_error!("Unknown public key algo: {}", algo_str),
        }
    }
}

impl X509PublicKeyAlgo {
    pub fn parse<'a>(pem_id: &str, public_key_info: &SubjectPublicKeyInfo<'a>) -> XResult<Self> {
        let algorithm = &public_key_info.algorithm;
        let public_key_algo_oid = &algorithm.algorithm;
        if public_key_algo_oid == &*OID_EC_PUBLIC_KEY {
            let parameters = match &algorithm.parameters {
                None => return simple_error!("Cannot find ec public key parameters: {}", pem_id),
                Some(parameters) => parameters,
            };
            let ec_public_key_algo_oid = opt_result!(parameters.content.as_oid(), "Parse public algo: {}, failed: {}", pem_id);
            let ec_public_key_algo = if ec_public_key_algo_oid == &*OID_SECP256R1 {
                X509EcPublicKeyAlgo::Secp256r1
            } else if ec_public_key_algo_oid == &*OID_SECP384R1 {
                X509EcPublicKeyAlgo::Secp384r1
            } else if ec_public_key_algo_oid == &*OID_SECP521R1 {
                X509EcPublicKeyAlgo::Secp521r1
            } else {
                return simple_error!("Parse : {}, unknown ec public key algo: {:?}", pem_id, ec_public_key_algo_oid);
            };
            Ok(Self::EcKey(ec_public_key_algo))
        } else if public_key_algo_oid == &*OID_RSA_PUBLIC_KEY {
            let public_key_data = parse_der(public_key_info.subject_public_key.data);
            if let BerObjectContent::Sequence(seq) = &public_key_data.as_ref().unwrap().1.content {
                let mut rsa_n_len = 0;
                if let BerObjectContent::Integer(n) = seq[0].content {
                    rsa_n_len = n.len() - (if n[0] == 0 { 1 } else { 0 });
                }
                let get_rsa_bit_length = || -> Option<i32> {
                    for bit_len in &[1024, 2048, 3072, 4096] {
                        if i32::abs(bit_len - (rsa_n_len as i32 * 8)) <= 32 {
                            return Some(*bit_len);
                        }
                    }
                    None
                };
                if let Some(rsa_bit_length) = get_rsa_bit_length() {
                    return Ok(Self::Rsa(rsa_bit_length as u32));
                }
            }
            simple_error!("Parse cert: {}, not valid rsa public key", pem_id)
        } else {
            simple_error!("Parse cert: {}, unknown public key algo oid: {}", pem_id, public_key_algo_oid)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Certificate {
    pub issuer_algo: X509IssuerAlgo,
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub public_key_algo: X509PublicKeyAlgo,
    pub certificate_not_after: i64,
}

pub fn parse_x509(pem_id: &str, pem: &str) -> XResult<X509Certificate> {
    let (_, der) = opt_result!(parse_x509_pem(pem.as_bytes()), "Parse pem: {} to der failed: {}", pem_id);
    let (_, cert) = opt_result!(parse_x509_certificate(der.contents.as_slice()), "Parse cert: {} failed: {}", pem_id);

    let mut common_name = None;
    cert.subject().iter_common_name().for_each(|c| {
        if c.attr_type == *OID_COMMON_NAME {
            common_name = c.attr_value.content.as_str().ok();
        }
    });
    let cert_algorithm_oid = &cert.signature_algorithm.algorithm;
    let issuer_algo = if cert_algorithm_oid == &*OID_RSA_WITH_SHA256 {
        X509IssuerAlgo::RsaWithSha256
    } else if cert_algorithm_oid == &*OID_ECDSA_WITH_SHA256 {
        X509IssuerAlgo::EcdsaWithSha256
    } else {
        return simple_error!("Parse pem: {}, unknown x509 algorithm oid: {:?}", pem_id, cert_algorithm_oid);
    };
    let common_name = match common_name {
        None => return simple_error!("Cannot find common name from: {}", pem_id),
        Some(common_name) => common_name.to_string(),
    };
    let mut alt_names = vec![];
    for (_oid, ext) in cert.extensions().iter() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns_name) => alt_names.push(dns_name.to_string()),
                    n => warning!("Unknown general name from: {}, name: {:?}", pem_id, n),
                }
            }
        }
    }
    let public_key_algo = X509PublicKeyAlgo::parse(pem_id, &cert.tbs_certificate.subject_pki)?;

    let certificate_not_after = cert.tbs_certificate.validity.not_after.timestamp();

    Ok(X509Certificate {
        issuer_algo,
        common_name,
        alt_names,
        public_key_algo,
        certificate_not_after,
    })
}

#[test]
fn test_sample_cert() {
    let cert_pem = include_str!("sample_cert.pem");
    let x509_certificate = parse_x509("test", cert_pem).unwrap();
    assert_eq!(X509IssuerAlgo::RsaWithSha256, x509_certificate.issuer_algo);
    assert_eq!("zigstack.org", x509_certificate.common_name.as_str());
    assert_eq!(vec!["www.zigstack.org", "zigstack.org"], x509_certificate.alt_names);
    assert_eq!(X509PublicKeyAlgo::Rsa(2048), x509_certificate.public_key_algo);
}
