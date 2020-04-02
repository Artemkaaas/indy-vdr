use ursa::cl::RevocationRegistry as CryptoRevocationRegistry;
use std::collections::HashSet;

use crate::ledger::identifiers::rev_reg::RevocationRegistryId;
use crate::ledger::responses::GetReplyResultV1;
use crate::ledger::requests::rev_reg::RevocationRegistryV1;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum GetRevocRegReplyResult {
    GetRevocRegReplyResultV0(GetRevocRegResultV0),
    GetRevocRegReplyResultV1(GetReplyResultV1<GetRevocRegDataV1>),
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRevocRegResultV0 {
    pub seq_no: i32,
    pub revoc_reg_def_id: RevocationRegistryId,
    pub data: RevocationRegistryV1,
    pub txn_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRevocRegDataV1 {
    pub revoc_reg_def_id: RevocationRegistryId,
    pub value: RevocationRegistryV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDeltaData {
    pub value: RevocationRegistryDeltaValue
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RevocationRegistryDeltaValue {
    pub accum_from: Option<AccumulatorState>,
    pub accum_to: AccumulatorState,
    pub issued: HashSet<u32>,
    pub revoked: HashSet<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccumulatorState {
    pub value: CryptoRevocationRegistry,
    pub txn_time: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum GetRevocRegDeltaReplyResult {
    GetRevocRegDeltaReplyResultV0(GetRevocRegDeltaResultV0),
    GetRevocRegDeltaReplyResultV1(GetReplyResultV1<GetRevocRegDeltaDataV1>),
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetRevocRegDeltaResultV0 {
    pub seq_no: i32,
    pub revoc_reg_def_id: RevocationRegistryId,
    pub data: RevocationRegistryDeltaData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRevocRegDeltaDataV1 {
    pub revoc_reg_def_id: RevocationRegistryId,
    pub value: RevocationRegistryDeltaData,
}