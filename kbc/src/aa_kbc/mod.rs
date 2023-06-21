// Copyright (c) 2023 Microsoft
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
// use ::sev::*;
use kbs_protocol::KbsProtocolWrapper;
use resource_uri::ResourceUri;

use anyhow::*;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use tonic;
use tonic::codegen::http::Uri;
use uuid::Uuid;

use super::AnnotationPacket;

const KEYS_PATH: &str = "/sys/kernel/security/secrets/coco/1ee27366-0c87-43a6-af48-28543eaf7cb0";

pub struct AzureKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    kbs_uri: String,
}

#[async_trait]
impl KbcInterface for AzureKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        // let key = self.get_key_from_kbs(annotation_packet.kid).await?;
        // let plain_payload = crypto::decrypt(
        //     key,
        //     base64::decode(annotation_packet.wrapped_data)?,
        //     base64::decode(annotation_packet.iv)?,
        //     &annotation_packet.wrap_type,
        // )?;
        println!("AzureKbc::decrypt_payload");
        let plain_payload = Vec::<u8>::new();
        Ok(plain_payload)
    }

    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let report = self.get_resource_from_kbs(rid).await?;

        let output = Vec::<u8>::new();
        return Ok(output);
    }
}

impl AzureKbc {
    #[allow(clippy::new_without_default)]
    pub fn new(kbs_uri: String) -> AzureKbc {
        AzureKbc {
            kbs_info: HashMap::new(),
            kbs_uri,
        }
    }

    async fn query_kbs(&self, secret_type: String, secret_id: String) -> Result<String> {
        // error out if the KBS URI does not begin with "Attestation:"
        if !self.kbs_uri.starts_with("Attestation:") {
            return Err(anyhow!("Invalid KBS URI."));
        }

        let uri = format!("http://{}", self.kbs_uri).parse::<Uri>()?;
        let kbs_protocol = KbsProtocolWrapper::new()?;
        // get the SNP report from the KBS
        let evidence = KbsProtocolWrapper::generate_evidence(&kbs_protocol)?;
        let tee_evidence = evidence.tee_evidence;
        println!("tee_evidence: {:?}", tee_evidence);
        Ok(tee_evidence)
    }

    async fn get_resource_from_kbs(&self, rid: ResourceUri) -> Result<String> {
        self.query_kbs("resource".to_string(), rid.resource_path())
            .await
    }
}
