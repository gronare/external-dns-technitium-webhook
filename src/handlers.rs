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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::config::Config;
    use crate::technitium::{
        RecordAAAAData, RecordAData, RecordCNAMEData, RecordPayloadData, RecordTXTData,
        TechnitiumClient,
    };
    use axum::{Router, body::Body, routing::get};
    use http_body_util::BodyExt;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    fn make_state(server_url: &str, zones: Vec<String>) -> Arc<AppState> {
        Arc::new(AppState {
            config: Config {
                zones,
                ..Default::default()
            },
            is_ready: RwLock::new(true),
            client: RwLock::new(TechnitiumClient::new(
                server_url.to_string(),
                "token".to_string(),
                Duration::from_secs(5),
            )),
        })
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    // --- record_payload ---

    #[test]
    fn test_record_payload_a() {
        let r = record_payload("A", "1.2.3.4".to_string()).unwrap();
        if let RecordPayloadData::A(RecordAData { ip_address }) = r {
            assert_eq!(ip_address, "1.2.3.4");
        } else {
            panic!("expected A");
        }
    }

    #[test]
    fn test_record_payload_aaaa() {
        let r = record_payload("AAAA", "::1".to_string()).unwrap();
        if let RecordPayloadData::AAAA(RecordAAAAData { ip_address }) = r {
            assert_eq!(ip_address, "::1");
        } else {
            panic!("expected AAAA");
        }
    }

    #[test]
    fn test_record_payload_cname() {
        let r = record_payload("CNAME", "example.com".to_string()).unwrap();
        if let RecordPayloadData::CNAME(RecordCNAMEData { cname }) = r {
            assert_eq!(cname, "example.com");
        } else {
            panic!("expected CNAME");
        }
    }

    #[test]
    fn test_record_payload_txt() {
        let r = record_payload("TXT", "v=spf1 -all".to_string()).unwrap();
        if let RecordPayloadData::TXT(RecordTXTData { text }) = r {
            assert_eq!(text, "v=spf1 -all");
        } else {
            panic!("expected TXT");
        }
    }

    #[test]
    fn test_record_payload_unknown_returns_none() {
        assert!(record_payload("MX", "mail.example.com".to_string()).is_none());
        assert!(record_payload("NS", "ns1.example.com".to_string()).is_none());
        assert!(record_payload("", "target".to_string()).is_none());
    }

    // --- negotiate_domain_filter ---

    #[tokio::test]
    async fn test_negotiate_domain_filter_falls_back_to_zones() {
        let state = make_state(
            "http://unused",
            vec!["gronare.com".to_string(), "divperedi.com".to_string()],
        );
        let app = Router::new()
            .route("/", get(negotiate_domain_filter))
            .with_state(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["filters"], json!(["gronare.com", "divperedi.com"]));
    }

    #[tokio::test]
    async fn test_negotiate_domain_filter_uses_explicit_domain_filters() {
        let mut state = make_state(
            "http://unused",
            vec!["gronare.com".to_string()],
        );
        Arc::get_mut(&mut state).unwrap().config.domain_filters =
            Some(vec![".gronare.com".to_string(), ".divperedi.com".to_string()]);

        let app = Router::new()
            .route("/", get(negotiate_domain_filter))
            .with_state(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = body_json(resp).await;
        assert_eq!(body["filters"], json!([".gronare.com", ".divperedi.com"]));
    }

    // --- get_records ---

    fn zone_records_response(records: serde_json::Value) -> String {
        json!({
            "status": "ok",
            "response": {
                "zone": {"name": "example.com", "type": "Primary", "disabled": false},
                "records": records
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn test_get_records_skips_disabled() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/api/zones/records/get")
            .with_status(200)
            .with_body(zone_records_response(json!([
                {
                    "disabled": false,
                    "name": "app.example.com",
                    "type": "A",
                    "ttl": 300,
                    "rData": {"ipAddress": "1.2.3.4"}
                },
                {
                    "disabled": true,
                    "name": "hidden.example.com",
                    "type": "A",
                    "ttl": 300,
                    "rData": {"ipAddress": "5.6.7.8"}
                }
            ])))
            .create();

        let state = make_state(&server.url(), vec!["example.com".to_string()]);
        let app = Router::new()
            .route("/records", get(get_records))
            .with_state(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/records")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let endpoints: Vec<serde_json::Value> =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["dnsName"], "app.example.com");
    }

    #[tokio::test]
    async fn test_get_records_merges_multiple_zones() {
        let mut server = mockito::Server::new_async().await;

        // Both zones share the same endpoint — mockito matches regardless of body
        let _mock = server
            .mock("POST", "/api/zones/records/get")
            .with_status(200)
            .with_body(zone_records_response(json!([
                {
                    "disabled": false,
                    "name": "app.example.com",
                    "type": "A",
                    "ttl": 300,
                    "rData": {"ipAddress": "1.2.3.4"}
                }
            ])))
            .expect(2) // called once per zone
            .create();

        let state = make_state(
            &server.url(),
            vec!["example.com".to_string(), "other.com".to_string()],
        );
        let app = Router::new()
            .route("/records", get(get_records))
            .with_state(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/records")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let endpoints: Vec<serde_json::Value> =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(endpoints.len(), 2);
    }
}
