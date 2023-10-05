#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rust_util;

mod acme;
mod util;
mod config;
mod x509;
mod network;
mod statistics;
mod dingtalk;
mod dns;
mod ali_dns;
// mod simple_thread_pool;

use std::fs;
use std::env;
use std::path::PathBuf;
use std::process::{Command, exit};
use std::time::{Duration, SystemTime};
use std::str::FromStr;
use tide::Request;
use clap::{App, Arg};
use async_std::{task, channel, channel::Sender};
use rust_util::util_cmd::run_command_and_wait;
use crate::config::{AcmeMode, AcmeChallenge, CertConfig, CERT_NAME, KEY_NAME};
use crate::x509::{X509PublicKeyAlgo};
use crate::dingtalk::send_dingtalk_message;
use crate::statistics::{AcmeStatistics, AcmeStatus};
use crate::acme::{AcmeRequest, request_acme_certificate};
use crate::network::get_local_public_ip;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

#[async_std::main]
async fn main() -> tide::Result<()> {
    let matches = App::new(NAME)
        .version(VERSION)
        .about(DESCRIPTION)
        .author(AUTHORS)
        .arg(Arg::with_name("version").short("V").long("version").help("Print version"))
        .arg(Arg::with_name("verbose").short("v").long("verbose").help("Verbose"))
        .arg(Arg::with_name("port").short("p").long("port").default_value("80").takes_value(true).help("Http port"))
        .arg(Arg::with_name("domain").short("d").long("domain").multiple(true).takes_value(true).help("Domains"))
        .arg(Arg::with_name("email").long("email").takes_value(true).help("Contract email"))
        .arg(Arg::with_name("algo").short("a").long("algo").takes_value(true).default_value("ec384").help("Pki algo"))
        .arg(Arg::with_name("timeout").long("timeout").takes_value(true).default_value("5000").help("Timeout (ms)"))
        .arg(Arg::with_name("mode").short("m").long("mode").takes_value(true).default_value("prod").help("Mode"))
        .arg(Arg::with_name("directory-url").long("directory-url").takes_value(true).help("ACME directory URL"))
        .arg(Arg::with_name("dir").long("dir").takes_value(true).default_value("acme_dir").help("Account key dir"))
        .arg(Arg::with_name("cert-dir").long("cert-dir").takes_value(true).help("Certificate dir"))
        .arg(Arg::with_name("config").short("c").long("config").takes_value(true).help("Cert config"))
        .arg(Arg::with_name("outputs").short("o").long("outputs").takes_value(true).help("Outputs file"))
        .arg(Arg::with_name("check").long("check").help("Check cert config"))
        .arg(Arg::with_name("hide-logo").long("hide-logo").help("Hide logo"))
        .arg(Arg::with_name("skip-verify-ip").short("k").long("skip-verify-ip").help("Skip verify public ip"))
        .arg(Arg::with_name("skip-verify-certificate").short("K").long("skip-verify-certificate").help("Skip verify certificate"))
        .arg(Arg::with_name("skip-listen").long("skip-listen").help("Skip http challenge listen"))
        .arg(Arg::with_name("allow-interact").long("allow-interact").help("Allow interact"))
        .arg(Arg::with_name("challenge-type").short("t").long("challenge-type").takes_value(true).default_value("http").help("Challenge type, http or dns"))
        .arg(Arg::with_name("dns-supplier").short("s").long("dns-supplier").takes_value(true).help("DNS supplier, e.g. account://***:****@**?id=*"))
        .get_matches();

    if matches.is_present("verbose") {
        env::set_var("LOGGER_LEVEL", "*");
    }

    if matches.is_present("version") {
        println!("{}", include_str!("logo.txt"));
        information!("{} v{}", NAME, VERSION);
        exit(1);
    }

    if !matches.is_present("hide-logo") {
        println!("{}", include_str!("logo.txt"));
    }

    let skip_verify_ip = matches.is_present("skip-verify-ip");
    let local_public_ip = if skip_verify_ip {
        None
    } else {
        let skip_verify_certificate = matches.is_present("skip-verify-certificate");
        Some(get_local_public_ip(skip_verify_certificate).unwrap_or_else(|e| {
            failure!("Get local public ip failed: {}, you can turn off verify IP by -k or --skip-verify-ip", e);
            exit(1);
        }))
    };

    debugging!("Clap matches: {:?}", matches);

    let account_dir = matches.value_of("dir").unwrap_or("acme_dir");
    information!("Acme dir: {}", account_dir);
    fs::create_dir_all(account_dir).ok();

    let mut account_email = PathBuf::from(account_dir);
    account_email.push("account_email.conf");

    let email = if account_email.exists() {
        match fs::read_to_string(&account_email) {
            Err(e) => {
                failure!("Read from file: {:?}, failed: {}", account_email, e);
                exit(1);
            }
            Ok(email) => {
                if let Some(email_from_args) = matches.value_of("email") {
                    if email != email_from_args {
                        warning!("Get email from account config: {}", email);
                    }
                }
                email.trim().to_string()
            }
        }
    } else {
        let email = matches.value_of("email").unwrap_or_else(|| {
            failure!("Email is not assigned.");
            exit(1);
        });

        information!("Write email to account config: {:?}", account_email);
        if let Err(e) = fs::write(&account_email, email) {
            warning!("Write email to account config: {:?}, failed: {}", account_email, e);
        }

        email.to_string()
    };

    let port: u16 = match matches.value_of("port") {
        Some(p) => p.parse().unwrap_or_else(|e| {
            failure!("Parse port: {}, failed: {}", p, e);
            exit(1);
        }),
        None => {
            failure!("Port is not assigned.");
            exit(1);
        }
    };
    let timeout: u64 = match matches.value_of("timeout") {
        Some(p) => p.parse().unwrap_or_else(|e| {
            failure!("Parse timeout: {}, failed: {}", p, e);
            exit(1);
        }),
        None => {
            failure!("Timeout is not assigned.");
            exit(1);
        }
    };
    let algo = match matches.value_of("algo") {
        Some(a) => X509PublicKeyAlgo::from_str(a).unwrap_or_else(|e| {
            failure!("{}", e);
            exit(1);
        }),
        _ => {
            failure!("Algo is not assigned, should be: ec256, ec384, rsa2048, rsa3073 or rsa4096.");
            exit(1);
        }
    };
    let mode = match matches.value_of("mode") {
        Some(m) => AcmeMode::parse(m).unwrap_or_else(|e| {
            failure!("{}", e);
            exit(1);
        }),
        _ => {
            failure!("AcmeMode is not assigned, should be: prod or test");
            exit(1);
        }
    };

    let cert_config_file = matches.value_of("config");
    let cert_config = cert_config_file.map(|f|
        CertConfig::load(f).unwrap_or_else(|e| {
            failure!("Load cert config: {}, failed: {}", f, e);
            exit(1);
        }));

    let skip_listen = matches.is_present("skip-listen");
    let port = iff!(skip_listen, 0, cert_config.as_ref().map(|c| c.port).flatten().unwrap_or(port));

    let check_config = matches.is_present("check");

    if !check_config && port > 0 {
        let (s, r) = channel::bounded(1);
        startup_http_server(s, port);
        r.recv().await.ok();
        task::sleep(Duration::from_millis(500)).await;
    }

    let mut dns_cleaned_domains: Vec<String> = vec![];
    match cert_config {
        None => { // cert config is not assigned
            if check_config {
                failure!("Bad argument `--check`");
                exit(1);
            }
            let domains_val = matches.values_of("domain").unwrap_or_else(|| {
                failure!("Domains is not assigned.");
                exit(1);
            });
            let domains: Vec<&str> = domains_val.collect::<Vec<_>>();
            let primary_name = domains[0];
            let alt_names: Vec<&str> = domains.into_iter().skip(1).collect();
            information!("Domains, main: {}, alt: {:?}", primary_name, alt_names);

            let (cert_file, key_file) = match matches.value_of("cert-dir") {
                None => (None, None),
                Some(cert_dir) => {
                    information!("Certificate output dir: {}", cert_dir);
                    fs::create_dir_all(cert_dir).ok();
                    (Some(format!("{}/{}", cert_dir, CERT_NAME)),
                     Some(format!("{}/{}", cert_dir, KEY_NAME)))
                }
            };

            let acme_request = AcmeRequest {
                challenge: AcmeChallenge::from_str(matches.value_of("challenge-type")),
                credential_supplier: matches.value_of("dns-supplier"),
                allow_interact: matches.is_present("allow-interact"),
                contract_email: &email,
                primary_name,
                alt_names: &alt_names,
                algo,
                mode,
                directory_url: matches.value_of("directory-url").map(|u| u.to_string()),
                account_dir,
                timeout,
                local_public_ip: local_public_ip.as_deref(),
                cert_file,
                key_file,
                outputs_file: matches.value_of("outputs").map(|s| s.into()),
                ..Default::default()
            };
            if let Err(e) = request_acme_certificate(acme_request, &mut dns_cleaned_domains) {
                failure!("Request certificate by acme failed: {}", e);
                exit(1);
            }
        }
        Some(cert_config) => { // cert config is assigned
            if check_config {
                check_cert_config(&cert_config);
                return Ok(());
            }
            let mut acme_statistics = AcmeStatistics::start();
            let filtered_cert_config = cert_config.filter_cert_config_items(30);
            for item in &filtered_cert_config.cert_items {
                if item.common_name.as_ref().map(|n| n.contains('*')).unwrap_or(false)
                    || item.dns_names.as_ref().map(|dns_names| dns_names.iter().any(|n| n.contains('*'))).unwrap_or(false) {
                    if item.get_acme_challenge() != AcmeChallenge::Dns {
                        warning!("Currently not support wide card domain name");
                        continue;
                    }
                }
                if let (Some(common_name), Some(dns_names)) = (&item.common_name, &item.dns_names) {
                    information!("Domains, main: {}, alt: {:?}", common_name, dns_names);
                    let alt_names: Vec<&str> = dns_names.iter().map(|n| n.as_str()).collect();
                    let challenge = item.get_acme_challenge();
                    let credential_supplier = if challenge == AcmeChallenge::Dns {
                        match &item.supplier {
                            None => None,
                            Some(supplier) => {
                                let credential_supplier = filtered_cert_config.credential_suppliers.as_ref()
                                    .map(|m| m.get(supplier)).flatten();
                                match credential_supplier {
                                    None => {
                                        warning!("DNS challenge no credential supplier found");
                                        None
                                    }
                                    Some(credential_supplier) => Some(credential_supplier.as_str()),
                                }
                            }
                        }
                    } else { None };
                    let acme_request = AcmeRequest {
                        challenge,
                        credential_supplier,
                        allow_interact: matches.is_present("allow-interact"),
                        contract_email: &email,
                        primary_name: common_name,
                        alt_names: &alt_names,
                        algo,
                        mode,
                        directory_url: matches.value_of("directory-url").map(|u| u.to_string()).or(filtered_cert_config.directory_url.clone()),
                        account_dir,
                        timeout,
                        local_public_ip: local_public_ip.as_deref(),
                        cert_file: Some(format!("{}/{}", item.path, CERT_NAME)),
                        key_file: Some(format!("{}/{}", item.path, KEY_NAME)),
                        outputs_file: None,
                    };
                    let mut domains = vec![common_name.clone()];
                    dns_names.iter().for_each(|dns_name| domains.push(dns_name.clone()));
                    if let Err(e) = request_acme_certificate(acme_request, &mut dns_cleaned_domains) {
                        failure!("Request certificate: {}, by acme failed: {}", item.path, e);
                        acme_statistics.add_item(domains, AcmeStatus::Fail(format!("{}", e)));
                    } else {
                        acme_statistics.add_item(domains, AcmeStatus::Success);
                    }
                }
            }
            acme_statistics.end();

            let mut success_count = 0;
            for acme_statistic in &acme_statistics.items {
                if let AcmeStatus::Success = acme_statistic.status {
                    success_count += 1;
                }
            }

            success!("Statistics: \n{}", acme_statistics);

            let mut dingtalk_message = format!("Statistics: \n{}", acme_statistics);
            if success_count > 0 {
                if let Some(trigger_after_update) = &filtered_cert_config.trigger_after_update {
                    if trigger_after_update.len() > 0 {
                        let mut cmd = Command::new(&trigger_after_update[0]);
                        for i in 1..trigger_after_update.len() {
                            cmd.arg(&trigger_after_update[i]);
                        }
                        match run_command_and_wait(&mut cmd) {
                            Ok(_) => {
                                success!("Restart nginx success");
                                dingtalk_message.push_str(&format!("\n\ntrigger after update success: {:?}", cmd));
                            }
                            Err(err) => {
                                failure!("Restart nginx failed: {:?}", err);
                                dingtalk_message.push_str(&format!("\n\ntrigger after update failed: {:?}, message: {:?}", cmd, err));
                            }
                        }
                    } else {
                        warning!("No trigger after update is configured but is empty");
                    }
                } else {
                    warning!("No trigger after update configured");
                }
            }

            let mut success_domains = vec![];
            let mut failed_domains = vec![];
            for acme_item in &acme_statistics.items {
                if let AcmeStatus::Success = acme_item.status {
                    success_domains.push(format!("* {}", acme_item.domains.join(", ")));
                }
                if let AcmeStatus::Fail(_) = acme_item.status {
                    failed_domains.push(format!("* {}", acme_item.domains.join(", ")));
                }
            }

            if !success_domains.is_empty() {
                dingtalk_message.push_str("\nsuccess domains:\n");
                dingtalk_message.push_str(&success_domains.join("\n"));
            }
            if !failed_domains.is_empty() {
                dingtalk_message.push_str("\nfailed domains:\n");
                dingtalk_message.push_str(&failed_domains.join("\n"));
            }

            if !acme_statistics.items.is_empty() && filtered_cert_config.notify_token.is_some() {
                if let Err(err) = send_dingtalk_message(&filtered_cert_config, &dingtalk_message) {
                    failure!("Send notification message failed: {:?}", err);
                }
            } else {
                information!("No notification message sent, or no configured notification token");
            }
        }
    }

    Ok(())
}

fn check_cert_config(cert_config: &CertConfig) {
    let secs_from_unix_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
    let item_count = cert_config.cert_items.len();
    for (i, item) in cert_config.cert_items.iter().enumerate() {
        information!("Checking: {}, item {} of {}", item.path, i, item_count);
        let cert_fn = format!("{}/{}", item.path, CERT_NAME);
        let pem = match fs::read_to_string(&cert_fn) {
            Ok(pem) => pem,
            Err(e) => {
                warning!("Read file: {}, failed: {}", cert_fn, e);
                continue;
            }
        };
        let x509_certificate = match x509::parse_x509(&cert_fn, &pem) {
            Ok(cert) => cert,
            Err(e) => {
                failure!("Parse x509 file: {}, failed: {}", cert_fn, e);
                continue;
            }
        };
        success!("Found certificate: common name: {}, dns names: {:?}, public key algo: {:?}, valid days: {}",
            x509_certificate.common_name,
            x509_certificate.alt_names,
            x509_certificate.public_key_algo,
            (x509_certificate.certificate_not_after - secs_from_unix_epoch) / (24 * 3600)
        );
    }
}

fn startup_http_server(s: Sender<i32>, port: u16) {
    task::spawn(async move {
        information!("Listen at 0.0.0.0:{}", port);
        let mut app = tide::new();
        app.at("/").get(|_req: Request<()>| async move {
            information!("Request / received");
            Ok("acme-client\n")
        });
        app.at("/.well-known/acme-challenge/:token").get(|req: Request<()>| async move {
            let token = match req.param("token") {
                Ok(token) => token,
                Err(e) => {
                    warning!("Cannot get token from url, query: {:?}, error: {}", req.url().query(), e);
                    return Ok("400 - bad request\n".to_string());
                }
            };
            let peer = req.peer_addr().unwrap_or("none");
            let auth_token = { crate::acme::TOKEN_MAP.read().unwrap().get(token).cloned() };
            match auth_token {
                Some(auth_token) => {
                    information!("Request acme challenge: {} -> {}, peer: {:?}", token, auth_token, peer);
                    Ok(auth_token)
                }
                None => {
                    warning!("Request acme challenge not found: {}, peer: {:?}", token, peer);
                    Ok("404 - not found\n".to_string())
                }
            }
        });
        app.at("/*").get(|req: Request<()>| async move {
            warning!("Request /* received: {}", req.url());
            Ok("acme-client *\n")
        });
        s.send(1).await.ok();
        if let Err(e) = app.listen(&format!("0.0.0.0:{}", port)).await {
            failure!("Failed to listen 0.0.0.0:{}, program will exit, error: {}", port, e);
            exit(1);
        }
    });
}
