use std::fs;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use rust_util::XResult;
use acme_lib::DirectoryUrl;
use crate::x509::{X509PublicKeyAlgo, X509Certificate, parse_x509};

pub const CERT_NAME: &str = "cert.pem";
pub const KEY_NAME: &str = "key.pem";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeChallenge {
    Http,
    Dns,
}

impl Default for AcmeChallenge {
    fn default() -> Self {
        AcmeChallenge::Http
    }
}

impl AcmeChallenge {
    pub fn from_str(t: Option<&str>) -> Self {
        let t = t.map(|t| t.to_ascii_lowercase()).unwrap_or_else(|| "http".to_string());
        if t == "dns" {
            AcmeChallenge::Dns
        } else {
            AcmeChallenge::Http
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AcmeMode {
    Prod,
    Test,
}

impl Default for AcmeMode {
    fn default() -> Self {
        Self::Prod
    }
}

impl AcmeMode {
    pub fn parse(s: &str) -> XResult<AcmeMode> {
        match s {
            "prod" => Ok(AcmeMode::Prod),
            "test" => Ok(AcmeMode::Test),
            _ => simple_error!("Unknown mode: {}", s),
        }
    }

    pub fn directory_url(&self) -> DirectoryUrl {
        match self {
            AcmeMode::Prod => DirectoryUrl::LetsEncrypt,
            AcmeMode::Test => DirectoryUrl::LetsEncryptStaging,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertConfigItem {
    // HTTP, DNS
    pub r#type: Option<String>,
    pub supplier: Option<String>,
    pub path: String,
    pub algo: Option<String>,
    pub public_key_algo: Option<X509PublicKeyAlgo>,
    pub common_name: Option<String>,
    pub dns_names: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertConfig {
    pub port: Option<u16>,
    pub credential_suppliers: Option<HashMap<String, String>>,
    pub cert_items: Vec<CertConfigItem>,
    pub trigger_after_update: Option<Vec<String>>,
    pub notify_token: Option<String>,
    pub directory_url: Option<String>,
}

impl CertConfig {
    // pub fn get_port(&self, port: Option<u16>) -> u16 {
    //     self.port.or(port).unwrap_or(80)
    // }

    pub fn filter_cert_config_items(self, valid_days: i32) -> Self {
        let mut filtered_cert_items = vec![];

        let secs_per_day = 24 * 3600;
        let valid_days_secs = valid_days as i64 * secs_per_day;
        let secs_from_unix_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
        for item in &self.cert_items {
            let mut item2 = item.clone();
            match item2.fill_dns_names() {
                Ok(Some(x509_certificate)) => {
                    if x509_certificate.certificate_not_after >= (valid_days_secs + secs_from_unix_epoch) {
                        success!("Certificate: {}, common name: {}, dns names: {:?}, is valid: {} days", item.path,
                            x509_certificate.common_name,
                            x509_certificate.alt_names,
                            (x509_certificate.certificate_not_after - secs_from_unix_epoch) / secs_per_day
                        );
                    } else {
                        warning!("Certificate: {}, common name: {}, dns names: {:?}, is valid: {} days", item.path,
                            x509_certificate.common_name,
                            x509_certificate.alt_names,
                            (x509_certificate.certificate_not_after - secs_from_unix_epoch) / secs_per_day
                        );
                        filtered_cert_items.push(item2);
                    }
                }
                Ok(None) => {
                    if fs::read_dir(&item.path).is_err() {
                        information!("Create certificate path: {}", item.path);
                        fs::create_dir_all(&item.path).ok();
                    }
                    filtered_cert_items.push(item2);
                }
                Err(e) => warning!("Certificate: {}, parse error: {}", item.path, e),
            }
        }

        Self {
            port: self.port,
            credential_suppliers: self.credential_suppliers,
            cert_items: filtered_cert_items,
            trigger_after_update: self.trigger_after_update,
            notify_token: self.notify_token,
            directory_url: self.directory_url,
        }
    }

    pub fn load(config_fn: &str) -> XResult<Self> {
        let config_content = opt_result!(fs::read_to_string(config_fn), "Load config: {}, failed: {}", config_fn);
        let config: CertConfig = opt_result!(deser_hjson::from_str(&config_content), "Parse config: {}, failed: {}", config_fn);
        Ok(config)
    }
}

impl CertConfigItem {
    pub fn get_acme_challenge(&self) -> AcmeChallenge {
        AcmeChallenge::from_str(self.r#type.as_ref().map(|s| s.as_str()))
    }

    pub fn fill_dns_names(&mut self) -> XResult<Option<X509Certificate>> {
        if self.path.is_empty() {
            return simple_error!("Cert config item path is empty");
        }
        let path_buff = opt_result!(PathBuf::from_str(&self.path), "Path: {}, failed: {}", self.path);
        let cert_path_buff = path_buff.join(CERT_NAME);
        if self.common_name.is_none() && self.dns_names.is_none() {
            let pem = opt_result!(fs::read_to_string(cert_path_buff.clone()), "Read file: {:?}, failed: {}", cert_path_buff);
            let x509_certificate = opt_result!(parse_x509(&format!("{}/{}", self.path, CERT_NAME), &pem), "Parse x509: {}/{}, faield: {}", self.path, CERT_NAME);
            self.common_name = Some(x509_certificate.common_name.clone());
            self.dns_names = Some(x509_certificate.alt_names.clone());
            if let Some(pos) = x509_certificate.alt_names.iter().position(|n| n == &x509_certificate.common_name) {
                if let Some(dns_names) = &mut self.dns_names {
                    dns_names.remove(pos);
                }
            }
            self.algo = None;
            self.public_key_algo = Some(x509_certificate.public_key_algo);
            Ok(Some(x509_certificate))
        } else {
            if self.common_name.is_none() {
                if let Some(dns_names) = &mut self.dns_names {
                    self.common_name = Some(dns_names.remove(0));
                }
            }
            if self.public_key_algo.is_none() {
                self.public_key_algo = match &self.algo {
                    None => Some(X509PublicKeyAlgo::Rsa(2048)),
                    Some(algo) => match X509PublicKeyAlgo::from_str(&algo) {
                        Ok(algo) => Some(algo),
                        Err(_) => return simple_error!("Unknown algo: {}", algo),
                    },
                };
            }
            if cert_path_buff.exists() {
                let pem = opt_result!(fs::read_to_string(cert_path_buff.clone()), "Read file: {:?}, failed: {}", cert_path_buff);
                let x509_certificate = opt_result!(parse_x509(&format!("{}/{}", self.path, CERT_NAME), &pem), "Parse x509: {}/{}, faield: {}", self.path, CERT_NAME);

                let mut self_dns_names = vec![];
                let mut cert_dns_names = vec![];

                if let Some(common_name) = &self.common_name {
                    self_dns_names.push(common_name.to_lowercase());
                }
                cert_dns_names.push(x509_certificate.common_name.to_lowercase());

                if let Some(dns_names) = &self.dns_names {
                    for n in dns_names {
                        let n = n.to_lowercase();
                        if !self_dns_names.contains(&n) {
                            self_dns_names.push(n);
                        }
                    }
                }
                for n in &x509_certificate.alt_names {
                    let n = n.to_lowercase();
                    if !cert_dns_names.contains(&n) {
                        cert_dns_names.push(n);
                    }
                }

                self_dns_names.sort();
                cert_dns_names.sort();

                if self_dns_names != cert_dns_names {
                    warning!("Cert: {}, dns names mis-match, required: {:?} vs certs: {:?}", self.path, self_dns_names, cert_dns_names);
                    return Ok(None); // request for new cert
                }
                Ok(Some(x509_certificate))
            } else {
                Ok(None)
            }
        }
    }
}
