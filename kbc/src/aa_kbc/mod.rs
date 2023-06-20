// Copyright (c) 2022 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use ::sev::*;
use crypto::WrapType;
use kbs_protocol::KbsProtocolWrapper;
use resource_uri::ResourceUri;

use anyhow::*;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use tonic::codegen::http::Uri;
use uuid::Uuid;
use zeroize::Zeroizing;

use keybroker::key_broker_service_client::KeyBrokerServiceClient;
use keybroker::{OnlineSecretRequest, RequestDetails};

use super::AnnotationPacket;

#[rustfmt::skip]
mod keybroker;

const KEYS_PATH: &str = "/sys/kernel/security/secrets/coco/1ee27366-0c87-43a6-af48-28543eaf7cb0";

#[derive(Deserialize, Clone)]
struct Connection {
    client_id: Uuid,
    key: String,
}

pub struct AzureKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    kbs_uri: String,
    connection: Result<Connection>,
}

#[async_trait]
impl KbcInterface for AzureKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        match &rid.r#type[..] {
            "client-id" => {
                let connection = self
                    .connection
                    .as_ref()
                    .map_err(|e| anyhow!("Failed to get injected connection. {}", e))?;
                Ok(connection.client_id.hyphenated().to_string().into_bytes())
            }
            _ => self.get_resource_from_kbs(rid).await,
        }
    }
}

impl AzureKbc {
    #[allow(clippy::new_without_default)]
    pub fn new(kbs_uri: String) -> AzureKbc {
        AzureKbc {
            kbs_info: HashMap::new(),
            kbs_uri,
            connection: load_connection(),
        }
    }

    async fn query_kbs(&self, secret_type: String, secret_id: String) -> Result<Vec<u8>> {
        // error out if the KBS URI does not begin with "Attestation:"
        if !self.kbs_uri.starts_with("Attestation:") {
            return Err(anyhow!("Invalid KBS URI."));
        }

        let uri = format!("http://{}", self.kbs_uri).parse::<Uri>()?;

        // get the SNP report from the KBS
        let evidence = KbsProtocolWrapper::generate_evidence(&uri).await?;
        let tee_evidence = evidence
            .tee_evidence
            .ok_or_else(|| anyhow!("Failed to get TEE evidence."))?;

        let guid = Uuid::new_v4().as_hyphenated().to_string();

        let payload_dict: HashMap<String, Vec<u8>> = bincode::deserialize(&tee_evidence)?;

        Ok(payload_dict
            .get(&guid)
            .ok_or_else(|| anyhow!("Secret UUID not found."))?
            .to_vec())
    }

    async fn get_resource_from_kbs(&self, rid: ResourceUri) -> Result<Vec<u8>> {
        self.query_kbs("resource".to_string(), rid.resource_path())
            .await
    }
}

fn load_connection() -> Result<Connection> {
    mount_security_fs()?;
    let _secret_module = SecretKernelModule::new()?;

    let connection_json = fs::read_to_string(KEYS_PATH)?;
    fs::remove_file(KEYS_PATH).expect("Failed to remove secret file.");

    Ok(serde_json::from_str(&connection_json)?)
}
