use http::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;
use tower_http::cors::CorsLayer;

/// Convert a header value formatted as a csv to a list of a given type.
fn from_header_value<T: FromStr>(source: &HeaderValue) -> Option<Vec<T>> {
    if let Ok(names) = source.to_str() {
        Some(
            names
                .split(',')
                .filter_map(|s| T::from_str(s.trim()).ok())
                .collect(),
        )
    } else {
        None
    }
}

/// Creates a CORS middleware from the config headers.
/// Used headers are:
/// - access-control-allow-headers
/// - access-control-expose-headers (set to allow-headers when not present)
/// - access-control-allow-methods
/// - access-control-allow-origin
pub(crate) fn cors_from_headers(headers: &HeaderMap) -> CorsLayer {
    let mut layer = CorsLayer::new();

    // access-control-allow-methods
    if let Some(methods) = headers.get("access-control-allow-methods") {
        if let Some(list) = from_header_value(methods) {
            layer = layer.allow_methods(list);
        }
    }

    // access-control-allow-origin
    if let Some(origin) = headers.get("access-control-allow-origin") {
        layer = layer.allow_origin(origin.clone());
    }

    // access-control-allow-headers
    let mut allowed_header_names: Vec<HeaderName> = vec![];
    if let Some(allowed_headers) = headers.get("access-control-allow-headers") {
        if let Some(list) = from_header_value(allowed_headers) {
            allowed_header_names = list.clone();
            layer = layer.allow_headers(list);
        }
    }

    // access-control-expose-headers
    if let Some(exposed_headers) = headers.get("access-control-expose-headers") {
        if let Some(list) = from_header_value(exposed_headers) {
            layer = layer.expose_headers(list);
        }
    } else if !allowed_header_names.is_empty() {
        layer = layer.expose_headers(allowed_header_names);
    }

    layer
}
