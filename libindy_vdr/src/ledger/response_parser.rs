use crate::ledger::identifiers::schema::SchemaId;
use crate::ledger::identifiers::cred_def::CredentialDefinitionId;
use crate::ledger::identifiers::rev_reg::RevocationRegistryId;
use crate::ledger::requests::{ProtocolVersion, RequestType};
use crate::common::error::prelude::*;
use crate::ledger::requests::nym::GetNymOperation;
use crate::ledger::requests::schema::{GetSchemaOperation, SchemaV1, Schema, AttributeNames};
use crate::ledger::requests::cred_def::{GetCredDefOperation, CredentialDefinitionV1, CredentialDefinition};
use crate::utils::qualifier::Qualifiable;
use crate::ledger::requests::rev_reg_def::{GetRevRegDefOperation, RevocationRegistryDefinition};
use crate::ledger::requests::rev_reg::{GetRevRegOperation, RevocationRegistry, GetRevRegDeltaOperation, RevocationRegistryDelta, RevocationRegistryDeltaV1};
use crate::ledger::requests::auth_rule::{AuthRule, GetAuthRuleResult};

use ursa::cl::RevocationRegistryDelta as CryproRevocationRegistryDelta;
use serde_json::Value as SJsonValue;
use serde::de::DeserializeOwned;
use crate::ledger::responses::{Message, Reply, ResponseMetadata};
use crate::ledger::responses::nym::{GetNymReplyResult, NymData, GetNymResultDataV0};
use crate::ledger::responses::schema::GetSchemaReplyResult;
use crate::ledger::responses::cred_def::GetCredDefReplyResult;
use crate::ledger::responses::rev_reg_def::GetRevocRegDefReplyResult;
use crate::ledger::responses::rev_reg::{GetRevocRegReplyResult, GetRevocRegDeltaReplyResult};

pub struct ResponseParser {
    pub protocol_version: ProtocolVersion,
}

impl Default for ResponseParser {
    fn default() -> Self {
        Self::new(ProtocolVersion::default())
    }
}

impl ResponseParser {
    pub fn new(protocol_version: ProtocolVersion) -> Self {
        Self { protocol_version }
    }

    pub fn parse_response<T, M>(response: &str) -> VdrResult<Reply<M>> where T: RequestType, M: DeserializeOwned + ::std::fmt::Debug {
        let message: serde_json::Value = serde_json::from_str(&response)
            .with_input_err("Invalid Response JSON")?;

        if message["op"] == json!("REPLY") && message["result"]["type"] != json!(T::get_txn_type()) {
            return Err(err_msg(VdrErrorKind::Input, "Target parser does not match to request operation"));
        }

        let message: Message<M> = serde_json::from_value(message)
            .map_err(|err| err_msg(VdrErrorKind::NotFound, format!("Structure doesn't correspond to type. Most probably not found. Err: {:?}", err)))?;

        match message {
            Message::Reject(response) | Message::ReqNACK(response) =>
                Err(err_msg(VdrErrorKind::Input, format!("Transaction has been failed: {:?}", response.reason))),
            Message::Reply(reply) =>
                Ok(reply)
        }
    }

    pub fn parse_get_nym_response(&self, get_nym_response: &str, method_name: Option<&str>) -> VdrResult<NymData> {
        let reply: Reply<GetNymReplyResult> = Self::parse_response::<GetNymOperation, GetNymReplyResult>(get_nym_response)?;

        let nym_data = match reply.result() {
            GetNymReplyResult::GetNymReplyResultV0(res) => {
                let data: GetNymResultDataV0 = res.data
                    .ok_or(err_msg(VdrErrorKind::NotFound, "Nym not found"))
                    .and_then(|data| serde_json::from_str(&data)
                        .map_err(|err| err_msg(VdrErrorKind::Input, format!("Cannot parse GET_NYM response: {}", err)))
                    )?;

                NymData {
                    did: data.dest.qualify(method_name.map(String::from)),
                    verkey: data.verkey,
                    role: data.role,
                }
            }
            GetNymReplyResult::GetNymReplyResultV1(res) => {
                NymData {
                    did: res.txn.data.did.qualify(method_name.map(String::from)),
                    verkey: res.txn.data.verkey,
                    role: res.txn.data.role,
                }
            }
        };

        Ok(nym_data)
    }

    pub fn parse_get_schema_response(&self, get_schema_response: &str, method_name: Option<&str>) -> VdrResult<(SchemaId, Schema)> {
        let reply: Reply<GetSchemaReplyResult> = Self::parse_response::<GetSchemaOperation, GetSchemaReplyResult>(get_schema_response)?;

        let schema = match reply.result() {
            GetSchemaReplyResult::GetSchemaReplyResultV0(res) => SchemaV1 {
                id: SchemaId::new(&res.dest.qualify(method_name.map(String::from)), &res.data.name, &res.data.version),
                name: res.data.name,
                version: res.data.version,
                attr_names: AttributeNames(res.data.attr_names),
                seq_no: Some(res.seq_no),
            },
            GetSchemaReplyResult::GetSchemaReplyResultV1(res) => {
                SchemaV1 {
                    name: res.txn.data.schema_name,
                    version: res.txn.data.schema_version,
                    attr_names: res.txn.data.value.attr_names,
                    id: match method_name {
                        Some(method) => res.txn.data.id.to_qualified(method)?,
                        None => res.txn.data.id
                    },
                    seq_no: Some(res.txn_metadata.seq_no),
                }
            }
        };

        let res = (schema.id.clone(), Schema::SchemaV1(schema));

        Ok(res)
    }

    pub fn parse_get_cred_def_response(&self, get_cred_def_response: &str, method_name: Option<&str>) -> VdrResult<(CredentialDefinitionId, CredentialDefinition)> {
        let reply: Reply<GetCredDefReplyResult> = Self::parse_response::<GetCredDefOperation, GetCredDefReplyResult>(get_cred_def_response)?;

        let cred_def = match reply.result() {
            GetCredDefReplyResult::GetCredDefReplyResultV0(res) => CredentialDefinitionV1 {
                id: CredentialDefinitionId::new(
                    &res.origin.qualify(method_name.map(String::from)),
                    &SchemaId(res.ref_.to_string()),
                    &res.signature_type.to_str(),
                    &res.tag.clone().unwrap_or_default()),
                schema_id: SchemaId(res.ref_.to_string()),
                signature_type: res.signature_type,
                tag: res.tag.unwrap_or_default(),
                value: res.data,
            },
            GetCredDefReplyResult::GetCredDefReplyResultV1(res) => CredentialDefinitionV1 {
                id: match method_name {
                    Some(method) => res.txn.data.id.to_qualified(method)?,
                    None => res.txn.data.id
                },
                schema_id: res.txn.data.schema_ref,
                signature_type: res.txn.data.type_,
                tag: res.txn.data.tag,
                value: res.txn.data.public_keys,
            }
        };

        let res = (cred_def.id.clone(), CredentialDefinition::CredentialDefinitionV1(cred_def));

        Ok(res)
    }

    pub fn parse_get_revoc_reg_def_response(&self, get_revoc_reg_def_response: &str, method_name: Option<&str>) -> VdrResult<(RevocationRegistryId, RevocationRegistryDefinition)> {
        let reply: Reply<GetRevocRegDefReplyResult> = Self::parse_response::<GetRevRegDefOperation, GetRevocRegDefReplyResult>(get_revoc_reg_def_response)?;

        let revoc_reg_def = match reply.result() {
            GetRevocRegDefReplyResult::GetRevocRegDefReplyResultV0(res) => res.data,
            GetRevocRegDefReplyResult::GetRevocRegDefReplyResultV1(res) => res.txn.data,
        };

        let revoc_reg_def_id =  match method_name {
            Some(method) => revoc_reg_def.id.to_qualified(method)?,
            None => revoc_reg_def.id.clone()
        };

        let res = (revoc_reg_def_id, RevocationRegistryDefinition::RevocationRegistryDefinitionV1(revoc_reg_def));

        Ok(res)
    }

    pub fn parse_get_revoc_reg_response(&self, get_revoc_reg_response: &str, method_name: Option<&str>) -> VdrResult<(RevocationRegistryId, RevocationRegistry, u64)> {
        let reply: Reply<GetRevocRegReplyResult> = Self::parse_response::<GetRevRegOperation, GetRevocRegReplyResult>(get_revoc_reg_response)?;

        let (revoc_reg_def_id, revoc_reg, txn_time) = match reply.result() {
            GetRevocRegReplyResult::GetRevocRegReplyResultV0(res) =>
                (res.revoc_reg_def_id, res.data, res.txn_time),
            GetRevocRegReplyResult::GetRevocRegReplyResultV1(res) =>
                (res.txn.data.revoc_reg_def_id, res.txn.data.value, res.txn_metadata.creation_time),
        };

        let revoc_reg_def_id =  match method_name {
            Some(method) => revoc_reg_def_id.to_qualified(method)?,
            None => revoc_reg_def_id
        };

        let res = (revoc_reg_def_id, RevocationRegistry::RevocationRegistryV1(revoc_reg), txn_time);

        Ok(res)
    }

    pub fn parse_get_revoc_reg_delta_response(&self, get_revoc_reg_delta_response: &str, method_name: Option<&str>) -> VdrResult<(RevocationRegistryId, RevocationRegistryDelta, u64)> {
        let reply: Reply<GetRevocRegDeltaReplyResult> = Self::parse_response::<GetRevRegDeltaOperation, GetRevocRegDeltaReplyResult>(get_revoc_reg_delta_response)?;

        let (revoc_reg_def_id, revoc_reg) = match reply.result() {
            GetRevocRegDeltaReplyResult::GetRevocRegDeltaReplyResultV0(res) => (res.revoc_reg_def_id, res.data),
            GetRevocRegDeltaReplyResult::GetRevocRegDeltaReplyResultV1(res) => (res.txn.data.revoc_reg_def_id, res.txn.data.value),
        };

        let delta = RevocationRegistryDelta::RevocationRegistryDeltaV1(
            RevocationRegistryDeltaV1 {
                value: CryproRevocationRegistryDelta::from_parts(revoc_reg.value.accum_from.map(|accum| accum.value).as_ref(),
                                                                 &revoc_reg.value.accum_to.value,
                                                                 &revoc_reg.value.issued,
                                                                 &revoc_reg.value.revoked)
            });

        let revoc_reg_def_id =  match method_name {
            Some(method) => revoc_reg_def_id.to_qualified(method)?,
            None => revoc_reg_def_id
        };

        let res = (revoc_reg_def_id, delta, revoc_reg.value.accum_to.txn_time);

        Ok(res)
    }

    pub fn parse_get_auth_rule_response(&self, response: &str) -> VdrResult<Vec<AuthRule>> {
        let response: Reply<GetAuthRuleResult> = serde_json::from_str(&response)
            .map_err(|err| input_err(format!("Cannot parse GetAuthRule response: {:?}", err)))?;

        let res = response.result().data;

        Ok(res)
    }

    pub fn parse_reply_metadata(reply_result: &SJsonValue) -> VdrResult<ResponseMetadata> {
        let response_metadata = match reply_result["ver"].as_str() {
            None => Self::parse_transaction_metadata_v0(reply_result),
            Some("1") => Self::parse_transaction_metadata_v1(reply_result),
            ver => {
                return Err(input_err(format!(
                    "Unsupported transaction response version: {:?}",
                    ver
                )));
            }
        };

        trace!(
            "parse_response_metadata >> response_metadata: {:?}",
            response_metadata
        );

        Ok(response_metadata)
    }

    fn parse_transaction_metadata_v0(message: &SJsonValue) -> ResponseMetadata {
        ResponseMetadata {
            seq_no: message["seqNo"].as_u64(),
            txn_time: message["txnTime"].as_u64(),
            last_txn_time: message["state_proof"]["multi_signature"]["value"]["timestamp"].as_u64(),
            last_seq_no: None,
        }
    }

    fn parse_transaction_metadata_v1(message: &SJsonValue) -> ResponseMetadata {
        ResponseMetadata {
            seq_no: message["txnMetadata"]["seqNo"].as_u64(),
            txn_time: message["txnMetadata"]["txnTime"].as_u64(),
            last_txn_time: message["multiSignature"]["signedState"]["stateMetadata"]["timestamp"]
                .as_u64(),
            last_seq_no: None,
        }
    }
}