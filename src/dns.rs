use serde::{Deserialize, Serialize};
use rust_util::XResult;
use crate::ali_dns::AlibabaCloudDnsClient;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub domain: String,
    pub rr: String,
    pub r#type: String,
    pub ttl: i32,
    pub value: String,
}

pub trait DnsClient {
    fn list_dns_records(&mut self, domain: &str) -> XResult<Vec<DnsRecord>>;

    fn delete_dns_record(&mut self, record_id: &str) -> XResult<()>;

    fn add_dns_record(&mut self, dns_record: &DnsRecord) -> XResult<()>;
}

pub struct DnsClientFactory {}

impl DnsClientFactory {
    pub fn build(supplier: &str) -> XResult<Box<dyn DnsClient>> {
        Ok(Box::new(AlibabaCloudDnsClient::build(supplier)?))
        //simple_error!("Build dns client failed: {}", supplier)
    }
}
