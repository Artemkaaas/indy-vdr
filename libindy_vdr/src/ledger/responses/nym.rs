use crate::ledger::identifiers::did::{ShortDidValue, DidValue};
use crate::ledger::responses::{GetReplyResultV0, GetReplyResultV1};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum GetNymReplyResult {
    GetNymReplyResultV0(GetReplyResultV0<String>),
    GetNymReplyResultV1(GetReplyResultV1<GetNymResultDataV1>)
}

#[derive(Deserialize, Eq, PartialEq, Debug)]
pub struct GetNymResultDataV0 {
    pub identifier: Option<ShortDidValue>,
    pub dest: ShortDidValue,
    pub role: Option<String>,
    pub verkey: Option<String>
}

#[derive(Deserialize, Eq, PartialEq, Debug)]
pub struct GetNymResultDataV1 {
    pub ver: String,
    pub id: String,
    pub did: ShortDidValue,
    pub verkey: Option<String>,
    pub role: Option<String>
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct NymData {
    pub did: DidValue,
    pub verkey: Option<String>,
    pub role: Option<String>,
}

