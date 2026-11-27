// SPDX-License-Identifier: AGPL-3.0-or-later

//! Converting control API parameters into proxy configuration.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use hiccup_control::RpcError;
use hiccup_control::api::{HostRule, ProxyStartParams};
use hiccup_proxy::{ClientCert, HostPattern, ProxyConfig, TlsVersion, UpstreamConfig};

/// Builds the proxy configuration for `proxy.start`.
pub(crate) fn proxy_config(params: &ProxyStartParams) -> Result<ProxyConfig, RpcError> {
    let invalid = RpcError::invalid_params;
    let listen = params
        .listen
        .iter()
        .map(|a| {
            a.parse::<SocketAddr>()
                .map_err(|_| invalid(format!("invalid listen address {a:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if listen.is_empty() {
        return Err(RpcError::invalid_params("`listen` is empty"));
    }
    let defaults = ProxyConfig::default();
    let millis = |ms: Option<u64>, default: Duration, name: &str| match ms {
        None => Ok(default),
        Some(0) => Err(invalid(format!("`{name}` must be positive"))),
        Some(ms) => Ok(Duration::from_millis(ms)),
    };
    let version = |v: &Option<String>, default| match v {
        None => Ok(default),
        Some(v) => v.parse::<TlsVersion>().map_err(invalid),
    };

    Ok(ProxyConfig {
        listen,
        tls_passthrough: params
            .tls_passthrough
            .iter()
            .map(|p| p.parse().map_err(invalid))
            .collect::<Result<_, _>>()?,
        connect_timeout: millis(
            params.connect_timeout_ms,
            defaults.connect_timeout,
            "connect_timeout_ms",
        )?,
        read_timeout: millis(
            params.read_timeout_ms,
            defaults.read_timeout,
            "read_timeout_ms",
        )?,
        upstream: UpstreamConfig {
            verify: params.verify_upstream,
            tls_min: version(&params.upstream_tls_min, TlsVersion::Tls12)?,
            tls_max: version(&params.upstream_tls_max, TlsVersion::Tls13)?,
            sni: rules(&params.upstream_sni, |name| {
                if name.is_empty() {
                    Err("empty server name".to_owned())
                } else {
                    Ok(name.to_owned())
                }
            })?,
            resolve: rules(&params.resolve, |ip| {
                ip.trim_matches(|c| c == '[' || c == ']')
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid IP address {ip:?}"))
            })?,
            client_certs: params
                .client_certs
                .iter()
                .map(|rule| {
                    let host: HostPattern = rule.host.parse().map_err(invalid)?;
                    let cert = read_absolute(&rule.cert)?;
                    let key = match &rule.key {
                        Some(key) => read_absolute(key)?,
                        None => cert.clone(),
                    };
                    let cert = ClientCert::from_pem(&cert, &key)
                        .map_err(|e| invalid(format!("{}: {e}", rule.cert)))?;
                    Ok((host, cert))
                })
                .collect::<Result<_, RpcError>>()?,
        },
        ..defaults
    })
}

fn rules<T>(
    rules: &[HostRule],
    value: impl Fn(&str) -> Result<T, String>,
) -> Result<Vec<(HostPattern, T)>, RpcError> {
    rules
        .iter()
        .map(|r| {
            let host = r.host.parse().map_err(RpcError::invalid_params)?;
            let value = value(&r.value).map_err(RpcError::invalid_params)?;
            Ok((host, value))
        })
        .collect()
}

/// Reads a file given by absolute path: the instance's working directory is
/// not the client's.
fn read_absolute(path: &str) -> Result<Vec<u8>, RpcError> {
    if !Path::new(path).is_absolute() {
        return Err(RpcError::invalid_params(format!(
            "{path}: the path must be absolute"
        )));
    }
    std::fs::read(path).map_err(|e| RpcError::invalid_params(format!("cannot read {path}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_errors() {
        let config = proxy_config(&ProxyStartParams::default()).unwrap();
        assert_eq!(config, ProxyConfig::default());

        let bad = |f: fn(&mut ProxyStartParams)| {
            let mut p = ProxyStartParams::default();
            f(&mut p);
            proxy_config(&p).unwrap_err().message
        };
        assert!(bad(|p| p.listen = vec!["nope".into()]).contains("invalid listen address"));
        assert!(bad(|p| p.listen.clear()).contains("empty"));
        assert!(bad(|p| p.upstream_tls_min = Some("1.1".into())).contains("not supported"));
        assert!(bad(|p| p.tls_passthrough = vec!["a b".into()]).contains("invalid host pattern"));
        assert!(bad(|p| p.read_timeout_ms = Some(0)).contains("positive"));
        assert!(
            bad(|p| p.resolve = vec![HostRule {
                host: "a".into(),
                value: "x".into()
            }])
            .contains("invalid IP")
        );
        assert!(
            bad(
                |p| p.client_certs = vec![hiccup_control::api::ClientCertRule {
                    host: "a".into(),
                    cert: "relative.pem".into(),
                    key: None
                }]
            )
            .contains("absolute")
        );
    }
}
