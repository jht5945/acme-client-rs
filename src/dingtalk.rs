use std::io::{Error, ErrorKind};
use std::time::SystemTime;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Serialize, Deserialize};
use rust_util::XResult;
use hmac::{Hmac, Mac};
use hmac::digest::FixedOutput;
use sha2::Sha256;
use crate::config::CertConfig;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerTextMessageText {
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerTextMessage {
    pub msgtype: String,
    pub text: InnerTextMessageText,
}

pub fn send_dingtalk_message(cert_config: &CertConfig, message: &str) -> XResult<()> {
    let dingtalk_notify_token = get_dingtalk_notify_token(cert_config);
    if let Some((access_token, sec_token)) = &dingtalk_notify_token {
        inner_send_dingtalk_message(access_token, sec_token, message)?;
    }
    Ok(())
}

fn inner_send_dingtalk_message(access_token: &str, sec_token: &str, message: &str) -> XResult<()> {
    let dingtalk_message_json = serde_json::to_string(&InnerTextMessage {
        msgtype: "text".into(),
        text: InnerTextMessageText {
            content: message.into(),
        },
    })?;
    let client = reqwest::blocking::Client::new();
    let mut webhook_url = "https://oapi.dingtalk.com/robot/send".to_string();
    webhook_url.push_str("?access_token=");
    webhook_url.push_str(&urlencoding::encode(access_token));
    if !sec_token.is_empty() {
        let timestamp = &format!("{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis());
        let timestamp_and_secret = &format!("{}\n{}", timestamp, sec_token);
        let hmac_sha256 = STANDARD.encode(&calc_hmac_sha256(sec_token.as_bytes(), timestamp_and_secret.as_bytes())?[..]);
        webhook_url.push_str("&timestamp=");
        webhook_url.push_str(timestamp);
        webhook_url.push_str("&sign=");
        webhook_url.push_str(&urlencoding::encode(&hmac_sha256));
    }
    let response = client.post(webhook_url)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(dingtalk_message_json.as_bytes().to_vec())
        .send()?;

    information!("Send dingtalk message: {:?}", response);

    Ok(())
}

// format: dingtalk:access_token?sec_token
fn get_dingtalk_notify_token(cert_config: &CertConfig) -> Option<(String, String)> {
    let token = cert_config.notify_token.as_ref()?;
    if token.starts_with("dingtalk:") {
        let token_and_or_sec = &token["dingtalk:".len()..];
        let mut token_and_or_sec_vec = token_and_or_sec.split('?');
        let access_token = match token_and_or_sec_vec.next() {
            Some(t) => t,
            None => token_and_or_sec,
        };
        let sec_token = match token_and_or_sec_vec.next() {
            Some(t) => t,
            None => "",
        };
        Some((access_token.into(), sec_token.into()))
    } else {
        None
    }
}

/// calc hma_sha256 digest
fn calc_hmac_sha256(key: &[u8], message: &[u8]) -> XResult<Vec<u8>> {
    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(e) => {
            return Err(Box::new(Error::new(ErrorKind::Other, format!("Hmac error: {}", e))));
        }
    };
    mac.update(message);
    Ok(mac.finalize_fixed().to_vec())
}