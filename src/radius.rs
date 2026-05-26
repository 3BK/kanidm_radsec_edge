use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

pub const CODE_ACCESS_REQUEST: u8 = 1;
pub const CODE_ACCESS_ACCEPT: u8 = 2;
pub const CODE_ACCESS_REJECT: u8 = 3;
pub const CODE_ACCESS_CHALLENGE: u8 = 11;

pub const ATTR_EAP_MESSAGE: u8 = 79;
pub const ATTR_MESSAGE_AUTHENTICATOR: u8 = 80;

#[derive(Debug, Clone)]
pub struct RadiusAttribute {
    pub typ: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RadiusPacket {
    pub code: u8,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute>,
}

impl RadiusPacket {
    pub fn parse(bytes: &[u8], max_packet_size: usize) -> Result<Self, String> {
        if bytes.len() < 20 {
            return Err("RADIUS packet too short".to_string());
        }
        if bytes.len() > max_packet_size {
            return Err(format!(
                "RADIUS packet exceeds configured max size {}",
                max_packet_size
            ));
        }

        let code = bytes[0];
        let identifier = bytes[1];
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        if length != bytes.len() {
            return Err(format!(
                "RADIUS length mismatch: header says {}, actual {}",
                length,
                bytes.len()
            ));
        }

        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&bytes[4..20]);

        let mut off = 20usize;
        let mut attributes = Vec::new();

        while off < bytes.len() {
            if off + 2 > bytes.len() {
                return Err("Malformed RADIUS attribute header".to_string());
            }

            let typ = bytes[off];
            let len = bytes[off + 1] as usize;

            if len < 2 {
                return Err(format!("Invalid RADIUS attribute length {}", len));
            }
            if off + len > bytes.len() {
                return Err("RADIUS attribute overruns packet".to_string());
            }

            let value = bytes[off + 2..off + len].to_vec();
            attributes.push(RadiusAttribute { typ, value });

            off += len;
        }

        Ok(Self {
            code,
            identifier,
            authenticator,
            attributes,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(64);
        out.push(self.code);
        out.push(self.identifier);
        out.extend_from_slice(&[0u8, 0u8]);
        out.extend_from_slice(&self.authenticator);

        for attr in &self.attributes {
            let len = attr.value.len() + 2;
            if len > 255 {
                return Err(format!("Attribute {} too large", attr.typ));
            }
            out.push(attr.typ);
            out.push(len as u8);
            out.extend_from_slice(&attr.value);
        }

        let total_len = out.len();
        if total_len > u16::MAX as usize {
            return Err("RADIUS packet too large".to_string());
        }

        let len_bytes = (total_len as u16).to_be_bytes();
        out[2] = len_bytes[0];
        out[3] = len_bytes[1];

        Ok(out)
    }

    pub fn has_attribute(&self, typ: u8) -> bool {
        self.attributes.iter().any(|a| a.typ == typ)
    }

    pub fn with_zeroed_message_authenticator(&self) -> Self {
        let mut cloned = self.clone();
        for attr in &mut cloned.attributes {
            if attr.typ == ATTR_MESSAGE_AUTHENTICATOR && attr.value.len() == 16 {
                attr.value.fill(0);
            }
        }
        cloned
    }

    pub fn verify_request_message_authenticator(&self, shared_secret: &[u8]) -> Result<(), String> {
        let msg_auth = self
            .attributes
            .iter()
            .find(|a| a.typ == ATTR_MESSAGE_AUTHENTICATOR)
            .ok_or_else(|| "Missing Message-Authenticator".to_string())?;

        if msg_auth.value.len() != 16 {
            return Err("Invalid Message-Authenticator length".to_string());
        }

        let zeroed = self.with_zeroed_message_authenticator();
        let bytes = zeroed.to_bytes()?;

        type HmacMd5 = Hmac<Md5>;
        let mut mac =
            HmacMd5::new_from_slice(shared_secret).map_err(|_| "Invalid HMAC key".to_string())?;
        mac.update(&bytes);

        let expected = mac.finalize().into_bytes();
        if expected.as_slice() != msg_auth.value.as_slice() {
            return Err("Message-Authenticator verification failed".to_string());
        }

        Ok(())
    }

    pub fn verify_response_authenticator(
        response_bytes: &[u8],
        request_authenticator: [u8; 16],
        shared_secret: &[u8],
    ) -> Result<(), String> {
        if response_bytes.len() < 20 {
            return Err("Response packet too short".to_string());
        }

        let mut computed = Vec::with_capacity(response_bytes.len() + shared_secret.len());
        computed.push(response_bytes[0]);
        computed.push(response_bytes[1]);
        computed.extend_from_slice(&response_bytes[2..4]);
        computed.extend_from_slice(&request_authenticator);
        computed.extend_from_slice(&response_bytes[20..]);
        computed.extend_from_slice(shared_secret);

        let digest = Md5::digest(&computed);
        let actual = &response_bytes[4..20];

        if digest.as_slice() != actual {
            return Err("Response Authenticator verification failed".to_string());
        }

        Ok(())
    }

    pub fn build_access_reject_with_eap_failure(
        request: &RadiusPacket,
        eap_identifier: u8,
        shared_secret: &[u8],
    ) -> Result<Vec<u8>, String> {
        let eap_failure = vec![4u8, eap_identifier, 0x00, 0x04];

        let mut resp = RadiusPacket {
            code: CODE_ACCESS_REJECT,
            identifier: request.identifier,
            authenticator: [0u8; 16],
            attributes: vec![RadiusAttribute {
                typ: ATTR_EAP_MESSAGE,
                value: eap_failure,
            }],
        };

        let mut bytes = resp.to_bytes()?;

        let mut material = Vec::with_capacity(bytes.len() + shared_secret.len());
        material.push(resp.code);
        material.push(resp.identifier);
        material.extend_from_slice(&bytes[2..4]);
        material.extend_from_slice(&request.authenticator);
        material.extend_from_slice(&bytes[20..]);
        material.extend_from_slice(shared_secret);

        let digest = Md5::digest(&material);
        resp.authenticator.copy_from_slice(&digest);
        bytes[4..20].copy_from_slice(&digest);

        Ok(bytes)
    }
}
