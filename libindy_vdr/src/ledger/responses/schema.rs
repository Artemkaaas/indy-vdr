use crate::ledger::identifiers::did::ShortDidValue;
use crate::ledger::identifiers::schema::SchemaId;
use crate::ledger::responses::GetReplyResultV1;
use crate::ledger::requests::schema::{SchemaOperationData, AttributeNames};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum GetSchemaReplyResult {
    GetSchemaReplyResultV0(GetSchemaResultV0),
    GetSchemaReplyResultV1(GetReplyResultV1<GetSchemaResultDataV1>),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetSchemaResultV0 {
    pub seq_no: u32,
    pub data: SchemaOperationData,
    pub dest: ShortDidValue,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetSchemaResultDataV1 {
    pub ver: String,
    pub id: SchemaId,
    pub schema_name: String,
    pub schema_version: String,
    pub value: GetSchemaResultDataValueV1,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetSchemaResultDataValueV1 {
    pub attr_names: AttributeNames
}