use crate::models::{Changes, Endpoint, Filters};
use crate::technitium::RecordData;
use crate::{AppError, AppState, technitium};
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::Response;
use axum::{Json, http::StatusCode, response::IntoResponse};
use bytes::{BufMut, BytesMut};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Health check endpoint
pub async fn health_check(
    State(app_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    app_state.ensure_ready().await?;
    Ok(StatusCode::OK)
}

#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct ExtDnsJson<T>(pub T);

impl<T: Serialize> IntoResponse for ExtDnsJson<T> {
    fn into_response(self) -> Response {
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        match serde_json::to_writer(&mut buf, &self.0) {
            Ok(()) => (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/external.dns.webhook+json;version=1"),
                )],
                buf.into_inner().freeze(),
            )
                .into_response(),
            Err(err) => AppError::JsonSerializeError(err).into_response(),
        }
    }
}

/// Initialisation and negotiates headers and returns domain filter.
///
/// Returns a list of domain filters that should be applied to DNS records.
pub async fn negotiate_domain_filter(
    State(app_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    app_state.ensure_ready().await?;

    let filters = app_state
        .config
        .domain_filters
        .clone()
        .unwrap_or_else(|| app_state.config.zones.clone());

    Ok(ExtDnsJson(Filters { filters }))
}

/// Returns the current DNS records.
///
/// Fetches all DNS records from the configured provider.
pub async fn get_records(
    State(app_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    app_state.ensure_ready().await?;

    debug!("Fetching DNS records");

    let mut endpoints = Vec::new();
    for zone in &app_state.config.zones {
        let ret = app_state
            .client
            .read()
            .await
            .get_records(technitium::GetRecordsPayload {
                domain: zone.clone(),
                list_zone: Some(true),
                ..Default::default()
            })
            .await?;

        for ri in ret.records {
            if ri.disabled {
                continue;
            }
            let mut ep = Endpoint {
                dns_name: ri.name,
                record_ttl: Some(ri.ttl),
                ..Default::default()
            };
            match ri.data {
                RecordData::A(data) => {
                    ep.record_type = "A".to_string();
                    ep.targets = vec![data.ip_address.to_string()];
                }
                RecordData::AAAA(data) => {
                    ep.record_type = "AAAA".to_string();
                    ep.targets = vec![data.ip_address.to_string()];
                }
                RecordData::CNAME(data) => {
                    ep.record_type = "CNAME".to_string();
                    ep.targets = vec![data.cname.to_string()];
                }
                RecordData::TXT(data) => {
                    ep.record_type = "TXT".to_string();
                    ep.targets = vec![data.text.to_string()];
                }
                RecordData::Other { .. } => continue,
            }
            endpoints.push(ep);
        }
    }

    debug!("Found {} endpoints", endpoints.len());

    Ok(ExtDnsJson(endpoints))
}

/// Executes the AdjustEndpoints method.
///
/// Takes a list of desired endpoints and returns the adjusted list
/// after applying business rules.
pub async fn adjust_endpoints(
    State(app_state): State<Arc<AppState>>,
    Json(endpoints): Json<Vec<Endpoint>>,
) -> Result<impl IntoResponse, AppError> {
    app_state.ensure_ready().await?;

    // We don't do any endpoint adjustment
    Ok(ExtDnsJson(endpoints))
}

/// Applies DNS record changes.
///
/// Takes a set of changes (create, update, delete) and applies them
/// to the DNS provider. Returns 204 on success.
pub async fn apply_record(
    State(app_state): State<Arc<AppState>>,
    Json(changes): Json<Changes>,
) -> Result<impl IntoResponse, AppError> {
    app_state.ensure_ready().await?;

    let deletions = changes
        .delete
        .unwrap_or_default()
        .into_iter()
        .chain(changes.update_old.unwrap_or_default().into_iter())
        .collect::<Vec<_>>();
    let additions = changes
        .create
        .unwrap_or_default()
        .into_iter()
        .chain(changes.update_new.unwrap_or_default().into_iter())
        .collect::<Vec<_>>();

    if deletions.is_empty() && additions.is_empty() {
        info!("All records already up to date, skipping apply");
        return Ok(StatusCode::NO_CONTENT);
    }

    for ep in deletions {
        for target in ep.targets {
            let Some(data) = record_payload(&ep.record_type, target) else {
                warn!(
                    "Skipping deletion of {} with unsupported record type {}",
                    ep.dns_name, ep.record_type
                );
                continue;
            };
            info!("Deleting record {} with data {:?}", ep.dns_name, data);
            app_state
                .client
                .read()
                .await
                .delete_record(technitium::DeleteRecordPayload {
                    domain: ep.dns_name.clone(),
                    data,
                    ..Default::default()
                })
                .await?;
        }
    }

    for ep in additions {
        for target in ep.targets {
            let Some(data) = record_payload(&ep.record_type, target) else {
                warn!(
                    "Skipping creation of {} with unsupported record type {}",
                    ep.dns_name, ep.record_type
                );
                continue;
            };
            info!("Adding record {} with data {:?}", ep.dns_name, data);
            app_state
                .client
                .read()
                .await
                .add_record(technitium::AddRecordPayload {
                    domain: ep.dns_name.clone(),
                    ttl: ep.record_ttl,
                    data,
                    ..Default::default()
                })
                .await?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

fn record_payload(
    record_type: &str,
    target: String,
) -> Option<technitium::RecordPayloadData> {
    match record_type {
        "A" => Some(technitium::RecordAData { ip_address: target }.into()),
        "AAAA" => Some(technitium::RecordAAAAData { ip_address: target }.into()),
        "CNAME" => Some(technitium::RecordCNAMEData { cname: target }.into()),
        "TXT" => Some(technitium::RecordTXTData { text: target }.into()),
        _ => None,
    }
}
