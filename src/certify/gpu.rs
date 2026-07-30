// TEE Attestation Service Agent
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// GPU component evidence collection for certify requests.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

const MAX_GPU_EVIDENCE_ENTRIES: usize = 16;
const SHA512_DIGEST_LEN: usize = 64;

/// Collects GPU evidence for a certify request.
///
/// # Errors
///
/// Returns an error when NVIDIA evidence collection fails or the collector
/// returns a malformed, empty, oversized, or inconsistent payload.
pub(super) fn collect(nonce_hex: &str) -> Result<(Vec<Value>, Vec<u8>)> {
    let (payload, hashes) = crate::components::gpu_nvidia::collect_and_hash_gpu_evidence(nonce_hex)
        .map_err(anyhow::Error::msg)
        .context("failed to collect GPU evidence for certify")?;
    let entries = extract_gpu_entries(payload)?;
    let expected_hash_bytes = entries.len() * SHA512_DIGEST_LEN;

    if hashes.len() != expected_hash_bytes {
        return Err(anyhow!(
            "GPU evidence hash chain has {} bytes for {} entries; expected {}",
            hashes.len(),
            entries.len(),
            expected_hash_bytes
        ));
    }

    Ok((entries, hashes))
}

fn extract_gpu_entries(mut payload: Value) -> Result<Vec<Value>> {
    let gpu = payload
        .get_mut("gpu")
        .ok_or_else(|| anyhow!("GPU evidence payload is missing the 'gpu' field"))?
        .take();
    let entries = gpu
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("GPU evidence payload field 'gpu' must be an array"))?;

    if entries.is_empty() {
        return Err(anyhow!("GPU evidence payload contains no entries"));
    }
    if entries.len() > MAX_GPU_EVIDENCE_ENTRIES {
        return Err(anyhow!(
            "GPU evidence payload contains {} entries; maximum is {}",
            entries.len(),
            MAX_GPU_EVIDENCE_ENTRIES
        ));
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload_with_entries(count: usize) -> Value {
        json!({
            "gpu": (0..count)
                .map(|index| json!({
                    "type": "gpu-nvidia",
                    "device-index": index,
                    "evidence": "evidence"
                }))
                .collect::<Vec<_>>()
        })
    }

    #[test]
    fn extracts_bare_gpu_array() {
        let entries = extract_gpu_entries(payload_with_entries(2)).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["device-index"], 0);
        assert_eq!(entries[1]["device-index"], 1);
    }

    #[test]
    fn rejects_missing_non_array_and_empty_gpu_payloads() {
        let missing = extract_gpu_entries(json!({})).unwrap_err();
        assert!(missing.to_string().contains("missing the 'gpu' field"));

        let non_array = extract_gpu_entries(json!({ "gpu": {} })).unwrap_err();
        assert!(non_array.to_string().contains("must be an array"));

        let empty = extract_gpu_entries(payload_with_entries(0)).unwrap_err();
        assert!(empty.to_string().contains("contains no entries"));
    }

    #[test]
    fn enforces_backend_gpu_limit() {
        assert_eq!(
            extract_gpu_entries(payload_with_entries(MAX_GPU_EVIDENCE_ENTRIES))
                .unwrap()
                .len(),
            MAX_GPU_EVIDENCE_ENTRIES
        );

        let error =
            extract_gpu_entries(payload_with_entries(MAX_GPU_EVIDENCE_ENTRIES + 1)).unwrap_err();
        assert!(error.to_string().contains("maximum is 16"));
    }
}
