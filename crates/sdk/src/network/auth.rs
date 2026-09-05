use thiserror::Error;
use tokio::sync::watch;
use tonic::{metadata::AsciiMetadataValue, service::Interceptor, Request, Status};

/// A bearer token that can be updated without rebuilding the network prover.
///
/// The caller is responsible for acquiring and refreshing the token. Retain a clone to update the
/// value after passing it to a network prover builder.
#[derive(Clone)]
pub struct NetworkBearerToken {
    current: watch::Sender<AsciiMetadataValue>,
}

impl NetworkBearerToken {
    /// Creates a bearer token from its raw value, without the `Bearer` prefix.
    pub fn new(token: impl AsRef<str>) -> Result<Self, InvalidBearerToken> {
        let (current, _) = watch::channel(parse_bearer_token(token.as_ref())?);
        Ok(Self { current })
    }

    /// Updates the value used by subsequent network requests.
    pub fn update(&self, token: impl AsRef<str>) -> Result<(), InvalidBearerToken> {
        self.current.send_replace(parse_bearer_token(token.as_ref())?);
        Ok(())
    }

    fn subscribe(&self) -> watch::Receiver<AsciiMetadataValue> {
        self.current.subscribe()
    }
}

/// The supplied bearer token is empty or cannot be encoded as request metadata.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("bearer token must be non-empty ASCII without whitespace")]
pub struct InvalidBearerToken;

fn parse_bearer_token(token: &str) -> Result<AsciiMetadataValue, InvalidBearerToken> {
    if token.is_empty() || !token.is_ascii() || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(InvalidBearerToken);
    }

    let mut value: AsciiMetadataValue =
        format!("Bearer {token}").parse().map_err(|_| InvalidBearerToken)?;
    value.set_sensitive(true);
    Ok(value)
}

#[derive(Clone)]
pub(crate) struct BearerTokenInterceptor {
    current: Option<watch::Receiver<AsciiMetadataValue>>,
}

impl BearerTokenInterceptor {
    pub(crate) fn new(token: Option<&NetworkBearerToken>) -> Self {
        Self { current: token.map(NetworkBearerToken::subscribe) }
    }
}

impl Interceptor for BearerTokenInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(current) = &self.current {
            request.metadata_mut().insert("authorization", current.borrow().clone());
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_and_updates_bearer_token() {
        let token = NetworkBearerToken::new("first.token").unwrap();
        let mut interceptor = BearerTokenInterceptor::new(Some(&token));

        let request = interceptor.call(Request::new(())).unwrap();
        assert_eq!(request.metadata().get("authorization").unwrap(), "Bearer first.token");
        assert!(request.metadata().get("authorization").unwrap().is_sensitive());

        token.update("second.token").unwrap();
        let request = interceptor.call(Request::new(())).unwrap();
        assert_eq!(request.metadata().get("authorization").unwrap(), "Bearer second.token");

        assert_eq!(token.update("invalid token"), Err(InvalidBearerToken));
        let request = interceptor.call(Request::new(())).unwrap();
        assert_eq!(request.metadata().get("authorization").unwrap(), "Bearer second.token");
    }

    #[test]
    fn omits_authorization_without_a_token() {
        let mut interceptor = BearerTokenInterceptor::new(None);
        let request = interceptor.call(Request::new(())).unwrap();
        assert!(request.metadata().get("authorization").is_none());
    }

    #[test]
    fn rejects_invalid_tokens() {
        assert_eq!(NetworkBearerToken::new("").err(), Some(InvalidBearerToken));
        assert_eq!(NetworkBearerToken::new("two tokens").err(), Some(InvalidBearerToken));
        assert_eq!(NetworkBearerToken::new("é").err(), Some(InvalidBearerToken));
    }
}
