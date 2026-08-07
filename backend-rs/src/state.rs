//! Shared application state handed to every axum handler.

use std::sync::Arc;

use crate::auth::JwksCache;
use crate::config::Settings;
use crate::db::Pool;

pub type AppState = Arc<AppStateInner>;

pub struct AppStateInner {
    pub settings: Settings,
    pub pool: Pool,
    pub jwks: JwksCache,
    /// Lazily-initialized Cognito admin client. `None` until the first
    /// `/api/v1/users` hit that needs it, then cached for the process
    /// lifetime. `None` stays forever if `auth_provider != cognito`.
    pub cognito: tokio::sync::OnceCell<aws_sdk_cognitoidentityprovider::Client>,
    /// Lazily-initialized S3 client for report artifact storage. Same
    /// credential chain as Cognito (ECS task role in prod). Bucket name
    /// comes from `S3_BUCKET` env var; region from `S3_REGION` or the
    /// default credential chain.
    pub s3: tokio::sync::OnceCell<aws_sdk_s3::Client>,
    /// Lazily-initialized STS client used to broker cloud-assessment
    /// credentials: the backend assumes the customer's assessment role
    /// (which trusts this deployment's ECS task role) and hands the
    /// short-lived session to the desktop. Same credential chain as the
    /// other clients (ECS task role in prod).
    pub sts: tokio::sync::OnceCell<aws_sdk_sts::Client>,
}

pub fn new_state(settings: Settings, pool: Pool) -> AppState {
    Arc::new(AppStateInner {
        settings,
        pool,
        jwks: JwksCache::new(),
        cognito: tokio::sync::OnceCell::new(),
        s3: tokio::sync::OnceCell::new(),
        sts: tokio::sync::OnceCell::new(),
    })
}

impl AppStateInner {
    /// Returns the Cognito admin client, initializing it on first call.
    /// Uses the task's IAM role via the standard AWS credential chain.
    pub async fn cognito_client(
        &self,
    ) -> &aws_sdk_cognitoidentityprovider::Client {
        self.cognito
            .get_or_init(|| async {
                let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new(
                        self.settings
                            .cognito_region
                            .clone()
                            .unwrap_or_else(|| "us-west-2".to_string()),
                    ))
                    .load()
                    .await;
                aws_sdk_cognitoidentityprovider::Client::new(&config)
            })
            .await
    }

    /// Returns the S3 client, initializing it on first call. Region
    /// falls back to the Cognito region (same AWS account in the
    /// per-customer deployment pattern), then to us-west-2.
    pub async fn s3_client(&self) -> &aws_sdk_s3::Client {
        self.s3
            .get_or_init(|| async {
                let region = self
                    .settings
                    .s3_region
                    .clone()
                    .or_else(|| self.settings.cognito_region.clone())
                    .unwrap_or_else(|| "us-west-2".to_string());
                let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new(region))
                    .load()
                    .await;
                aws_sdk_s3::Client::new(&config)
            })
            .await
    }

    /// Returns the STS client, initializing it on first call. Uses the
    /// task's IAM role (the credential chain); region falls back to the
    /// Cognito region then us-west-2 (STS is global, any region works).
    pub async fn sts_client(&self) -> &aws_sdk_sts::Client {
        self.sts
            .get_or_init(|| async {
                let region = self
                    .settings
                    .cognito_region
                    .clone()
                    .unwrap_or_else(|| "us-west-2".to_string());
                let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new(region))
                    .load()
                    .await;
                aws_sdk_sts::Client::new(&config)
            })
            .await
    }
}
