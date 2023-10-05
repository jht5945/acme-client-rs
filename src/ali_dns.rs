#![allow(deprecated)]
use rust_util::XResult;
use serde::{Deserialize, Serialize};
use aliyun_openapi_core_rust_sdk::RPClient;
use crate::dns::DnsClient;

static ALI_DNS_ENDPOINT: &str = "https://alidns.aliyuncs.com";
static ALI_DNS_API_VERSION: &str = "2015-01-09";

pub struct AlibabaCloudDnsClient {
    client: RPClient,
}

impl AlibabaCloudDnsClient {
    pub fn build(supplier: &str) -> XResult<AlibabaCloudDnsClient> {
        let access_credential = simple_parse_aliyun_supplier(supplier)?;
        Ok(AlibabaCloudDnsClient {
            client: build_dns_client(&access_credential)
        })
    }
}

impl DnsClient for AlibabaCloudDnsClient {
    fn list_dns_records(&mut self, domain: &str) -> XResult<Vec<crate::dns::DnsRecord>> {
        let list_dns_response = opt_result!(list_dns(&self.client, domain)?, "List dns records failed: {:?}");
        let mut dns_records = vec![];
        list_dns_response.domain_records.record.into_iter().for_each(|record| {
            dns_records.push(crate::dns::DnsRecord {
                id: record.record_id,
                domain: record.domain_name,
                rr: record.rr,
                r#type: record.r#type,
                ttl: record.ttl,
                value: record.value,
            });
        });
        Ok(dns_records)
    }

    fn delete_dns_record(&mut self, record_id: &str) -> XResult<()> {
        opt_result!(delete_dns_record(&self.client, record_id)?, "Delete dns record failed: {:?}");
        Ok(())
    }

    fn add_dns_record(&mut self, dns_record: &crate::dns::DnsRecord) -> XResult<()> {
        let _ = opt_result!(add_dns_record(&self.client, &dns_record.domain, &dns_record.rr, &dns_record.r#type, &dns_record.value),
            "Add dns record failed: {}");
        Ok(())
    }
}

#[derive(Debug)]
pub struct AccessCredential {
    access_key_id: String,
    access_key_secret: String,
}

// syntax: account://***:***@alibabacloud?id=dns
pub fn simple_parse_aliyun_supplier(supplier: &str) -> XResult<AccessCredential> {
    if !supplier.starts_with("account://") {
        return simple_error!("Supplier syntax error: {}", supplier);
    }
    let access_key_id_and_secret: String = supplier.chars().skip("account://".len()).take_while(|c| *c != '@').collect();
    let c_pos = opt_value_result!(access_key_id_and_secret.find(":"), "Supplier syntax error: {}", supplier);

    let access_key_id = access_key_id_and_secret.chars().take(c_pos).collect();
    let access_key_secret = access_key_id_and_secret.chars().skip(c_pos + 1).collect();

    Ok(AccessCredential { access_key_id, access_key_secret })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonSuccessResponse {
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "RecordId")]
    pub record_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonErrorResponse {
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "Recommend")]
    pub recommend: String,
    #[serde(rename = "HostId")]
    pub host_id: String,
    #[serde(rename = "Code")]
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListDnsResponse {
    #[serde(rename = "TotalCount")]
    pub total_count: i32,
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "PageSize")]
    pub page_size: i32,
    #[serde(rename = "PageNumber")]
    pub page_number: i32,
    #[serde(rename = "DomainRecords")]
    pub domain_records: DnsRecords,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsRecords {
    #[serde(rename = "Record")]
    pub record: Vec<DnsRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(rename = "RR")]
    pub rr: String,
    #[serde(rename = "Line")]
    pub line: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Locked")]
    pub locked: bool,
    #[serde(rename = "Type")]
    pub r#type: String,
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "RecordId")]
    pub record_id: String,
    #[serde(rename = "TTL")]
    pub ttl: i32,
    #[serde(rename = "Weight")]
    pub weight: Option<i32>,
}

pub fn list_dns(client: &RPClient, domain: &str) -> XResult<Result<ListDnsResponse, CommonErrorResponse>> {
    let describe_domain_records_response = opt_result!(client.get("DescribeDomainRecords")
        .query(&[
            ("RegionId", "cn-hangzhou"),
            ("DomainName", domain)
        ])
        .send(), "List domain records: {}, failed: {}", domain);
    parse_result("DescribeDomainRecords", &describe_domain_records_response)
}

pub fn delete_dns_record(client: &RPClient, record_id: &str) -> XResult<Result<CommonSuccessResponse, CommonErrorResponse>> {
    let delete_domain_record_response = opt_result!(client.get("DeleteDomainRecord")
        .query(&[
            ("RegionId", "cn-hangzhou"),
            ("RecordId", record_id)
        ])
        .send(), "Delete domain record id: {}, failed: {}", record_id);
    parse_result("DeleteDomainRecord", &delete_domain_record_response)
}

// pub fn add_txt_dns_record(client: &RPClient, domain: &str, rr: &str, value: &str) -> XResult<Result<CommonSuccessResponse, CommonErrorResponse>> {
//     add_dns_record(client, domain, rr, "TXT", value)
// }

// domain -> "example.com"
// rr -> "@", "_acme-challenge"
// t -> "TXT"
// value -> "test"
pub fn add_dns_record(client: &RPClient, domain: &str, rr: &str, t: &str, value: &str) -> XResult<Result<CommonSuccessResponse, CommonErrorResponse>> {
    let add_domain_record_response = opt_result!(client.get("AddDomainRecord")
        .query(&[
            ("RegionId", "cn-hangzhou"),
            ("DomainName", domain),
            ("RR", rr),
            ("Type", t),
            ("Value", value)
        ])
        .send(), "Add domain record: {}.{} -> {} {} ,failed: {}", rr, domain, t, value);
    parse_result("AddDomainRecord", &add_domain_record_response)
}

pub fn build_dns_client(access_credential: &AccessCredential) -> RPClient {
    RPClient::new(
        access_credential.access_key_id.clone(),
        access_credential.access_key_secret.clone(),
        String::from(ALI_DNS_ENDPOINT),
        String::from(ALI_DNS_API_VERSION),
    )
}

fn parse_result<'a, S, E>(fn_name: &str, response: &'a str) -> XResult<Result<S, E>> where S: Deserialize<'a>, E: Deserialize<'a> {
    let describe_domain_records_result: serde_json::Result<S> = serde_json::from_str(&response);
    match describe_domain_records_result {
        Ok(r) => Ok(Ok(r)),
        Err(_) => {
            let describe_domain_records_error_result: serde_json::Result<E> = serde_json::from_str(&response);
            match describe_domain_records_error_result {
                Ok(r) => Ok(Err(r)),
                Err(_) => simple_error!("Parse {} response failed: {}", fn_name, response),
            }
        }
    }
}
