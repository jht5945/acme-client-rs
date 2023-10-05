use std::fs;
use std::sync::RwLock;
use std::collections::BTreeMap;
use acme_lib::{Directory, create_p256_key, create_p384_key, create_rsa_key, DirectoryUrl};
use acme_lib::persist::FilePersist;
use rust_util::XResult;
use crate::util::parse_dns_record;
use crate::network::{get_resolver, resolve_first_ipv4};
use crate::config::{AcmeChallenge, AcmeMode};
use crate::dns::{DnsClient, DnsClientFactory, DnsRecord};
use crate::x509::{X509PublicKeyAlgo, X509EcPublicKeyAlgo};


lazy_static! {
    pub static ref TOKEN_MAP: RwLock<BTreeMap<String, String>> = RwLock::new(BTreeMap::new());
}

#[derive(Debug, Default)]
pub struct AcmeRequest<'a> {
    pub challenge: AcmeChallenge,
    // issue, single acme request can only process one supplier
    pub credential_supplier: Option<&'a str>,
    pub allow_interact: bool,
    pub contract_email: &'a str,
    pub primary_name: &'a str,
    pub alt_names: &'a [&'a str],
    pub algo: X509PublicKeyAlgo,
    pub mode: AcmeMode,
    pub directory_url: Option<String>,
    pub account_dir: &'a str,
    pub timeout: u64,
    pub local_public_ip: Option<&'a str>,
    pub key_file: Option<String>,
    pub cert_file: Option<String>,
    pub outputs_file: Option<String>,
}

pub fn request_acme_certificate(acme_request: AcmeRequest, dns_cleaned_domains: &mut Vec<String>) -> XResult<()> {
    if let Some(local_public_ip) = acme_request.local_public_ip {
        let mut all_domains = vec![acme_request.primary_name.to_string()];
        for alt_name in acme_request.alt_names {
            all_domains.push(alt_name.to_string());
        }
        information!("Checking domain dns records, domains: {:?}", all_domains);
        let resolver = opt_result!(get_resolver(), "Get resolver failed: {}");

        if acme_request.challenge == AcmeChallenge::Http {
            for domain in &all_domains {
                debugging!("Checking domain: {}", domain);
                let ipv4 = opt_result!(resolve_first_ipv4(&resolver, domain), "{}");
                match ipv4 {
                    None => return simple_error!("Resolve domain ip failed: {}", domain),
                    Some(ipv4) => if local_public_ip != ipv4 {
                        return simple_error!("Check domain ip: {}, mis-match, local: {} vs domain: {}", domain, local_public_ip, ipv4);
                    }
                }
            }
        }
    }

    information!("Acme mode: {:?}", acme_request.mode);
    let url = if let Some(directory_url) = &acme_request.directory_url {
        DirectoryUrl::Other(directory_url)
    } else {
        acme_request.mode.directory_url()
    };
    debugging!("Directory URL: {:?}", url);
    let persist = FilePersist::new(acme_request.account_dir);
    let dir = opt_result!(Directory::from_url(persist, url), "Create directory from url failed: {}");
    let acc = opt_result!(dir.account(acme_request.contract_email), "Directory set account failed: {}");
    let mut ord_new = opt_result!( acc.new_order(acme_request.primary_name, acme_request.alt_names), "Create order failed: {}");
    let mut dns_client: Option<Box<dyn DnsClient>> = match acme_request.credential_supplier {
        Some(credential_supplier) => Some(
            opt_result!(DnsClientFactory::build(credential_supplier), "Build dns client failed: {}")),
        None => None,
    };

    let mut order_csr_index = 0;
    let ord_csr = loop {
        if let Some(ord_csr) = ord_new.confirm_validations() {
            debugging!("Valid acme certificate http challenge success");
            break ord_csr;
        }

        information!("Loop for acme challenge auth, #{}", order_csr_index);
        order_csr_index += 1;

        debugging!("Start acme certificate http challenge");
        let auths = opt_result!(ord_new.authorizations(), "Order auth failed: {}");
        for auth in &auths {
            match acme_request.challenge {
                AcmeChallenge::Http => {
                    let chall = auth.http_challenge();
                    let token = chall.http_token();
                    let proof = chall.http_proof();

                    {
                        information!("Add acme http challenge: {} -> {}",token, proof);
                        TOKEN_MAP.write().unwrap().insert(token.to_string(), proof);
                    }
                    debugging!("Valid acme certificate http challenge");
                    opt_result!(chall.validate(acme_request.timeout), "Validate http challenge failed: {}");
                }
                AcmeChallenge::Dns => {
                    let chall = auth.dns_challenge();
                    let record = format!("_acme-challenge.{}.", auth.domain_name());
                    let proof = chall.dns_proof();
                    information!("Add acme dns challenge: {} -> {}", record, proof);

                    let rr_and_domain = opt_result!(parse_dns_record(&record), "Parse record to rr&domain failed: {}");

                    if !dns_cleaned_domains.contains(&rr_and_domain.1) {
                        information!("Clearing domain: {}", &rr_and_domain.1);
                        dns_cleaned_domains.push(rr_and_domain.1.clone());
                        dns_client.as_mut().map(|client| {
                            match client.list_dns_records(&rr_and_domain.1) {
                                Err(e) => warning!("List dns for: {}, failed: {}", &rr_and_domain.1, e),
                                Ok(records) => {
                                    for r in &records {
                                        let rr = &r.rr;
                                        if rr == "_acme-challenge" || rr.starts_with("_acme-challenge.") {
                                            match client.delete_dns_record(&r.id) {
                                                Err(e) => warning!("Delete dns: {}.{}, failed: {}", rr, r.domain, e),
                                                Ok(_) => success!("Delete dns: {}.{}", rr, r.domain),
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }

                    match &mut dns_client {
                        Some(client) => {
                            let dns_record = DnsRecord {
                                id: String::new(),
                                domain: rr_and_domain.1,
                                rr: rr_and_domain.0,
                                r#type: "TXT".into(),
                                ttl: -1,
                                value: proof,
                            };
                            let _ = opt_result!(client.add_dns_record(&dns_record), "Add DNS TXT record failed: {}");
                            success!("Add dns txt record successes: {}.{} -> {}", dns_record.rr, dns_record.domain, dns_record.value);
                        }
                        None => if acme_request.allow_interact {
                            let mut line = String::new();
                            information!("You need to config dns manually, press enter to continue...");
                            let _ = std::io::stdin().read_line(&mut line).unwrap();
                            information!("Continued")
                        } else {
                            return simple_error!("Interact is not allowed, --allow-interact to allow interact");
                        }
                    }

                    debugging!("Valid acme certificate dns challenge");
                    opt_result!(chall.validate(acme_request.timeout), "Validate dns challenge failed: {}");
                }
            }
        }

        debugging!("Refresh acme certificate order");
        opt_result!(ord_new.refresh(), "Refresh order failed: {}");
    };

    information!("Generate private key, key type: {:?}", acme_request.algo);
    let pkey_pri = match acme_request.algo {
        X509PublicKeyAlgo::EcKey(X509EcPublicKeyAlgo::Secp256r1) => create_p256_key(),
        X509PublicKeyAlgo::EcKey(X509EcPublicKeyAlgo::Secp384r1) => create_p384_key(),
        X509PublicKeyAlgo::EcKey(X509EcPublicKeyAlgo::Secp521r1) => return simple_error!("Algo ec521 is not supported"),
        X509PublicKeyAlgo::Rsa(bits) => create_rsa_key(bits),
    };

    debugging!("Invoking csr finalize pkey");
    let ord_cert = opt_result!( ord_csr.finalize_pkey(pkey_pri, acme_request.timeout), "Submit CSR failed: {}");
    debugging!("Downloading and save cert");
    let cert = opt_result!( ord_cert.download_and_save_cert(), "Download and save certificate failed: {}");

    if let (Some(cert_file), Some(key_file)) = (&acme_request.cert_file, &acme_request.key_file) {
        debugging!("Certificate key: {}",  cert.private_key());
        debugging!("Certificate pem: {}",  cert.certificate());
        information!("Write file: {}", cert_file);
        if let Err(e) = fs::write(cert_file, cert.certificate()) {
            failure!("Write file: {}, failed: {}", cert_file, e);
        }
        information!("Write file: {}", key_file);
        if let Err(e) = fs::write(key_file, cert.private_key()) {
            failure!("Write file: {}, failed: {}", key_file, e);
        }
        success!("Write files success: {} and {}", cert_file, key_file);
    } else if let Some(outputs_file) = &acme_request.outputs_file {
        let mut outputs = String::new();
        outputs.push_str("private key:\n");
        outputs.push_str(cert.private_key());
        outputs.push_str("\n\ncertificates:\n");
        outputs.push_str(cert.certificate());
        if let Err(e) = fs::write(outputs_file, outputs) {
            failure!("Write file: {}, failed: {}", outputs_file, e);
        }
    } else {
        information!("Certificate key: {}",  cert.private_key());
        information!("Certificate pem: {}",  cert.certificate());
    }

    Ok(())
}
