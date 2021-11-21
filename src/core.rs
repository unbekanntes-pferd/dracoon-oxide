/// required imports
use reqwest::header::AUTHORIZATION;
use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use chrono::{DateTime};
use chrono::offset::Utc;

/// constants for grant_type
const GRANT_TYPE_PASSWORD: &str = "password";
const GRANT_TYPE_AUTH_CODE: &str = "authorization_code";
const GRANT_TYPE_REFRESH_TOKEN: &str = "refresh_token";
const TOKEN_TYPE_HINT_ACCESS: &str = "access_token";

/// constants for API urls
const DRACOON_TOKEN_URL: &str = "oauth/token";
const DRACOON_REDIRECT_URL: &str = "oauth/callback";
const DRACOON_TOKEN_REVOKE_URL: &str = "oauth/revoke";
const DRACOON_AUTHENTICATED_PING: &str = "user/ping";

const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// main client struct
pub struct DRACOONClient {
    pub http: Client,
    base_url: Url,
    client_id: String,
    client_secret: String,
    connection: Option<DRACOONConnection>,
    connected: bool,
}

/// OAuth2 flow structs (form data for POST to token (revoke) url)
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2PasswordFlow {
    pub username: String,
    pub password: String,
    pub grant_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2AuthCodeFlow {
    client_id: String,
    client_secret: String,
    grant_type: String,
    code: String,
    redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuth2RefreshTokenFlow {
    client_id: String,
    client_secret: String,
    grant_type: String,
    refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuth2TokenRevoke {
    client_id: String,
    client_secret: String,
    token_type_hint: String,
    token: String,
}


/// DRACOON token response
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: Option<String>,
    expires_in: i64,
    expires_in_inactive: i64,
    scope: String,
}

/// Error response model from DRACOON API (all optional to include OAuth2 and API error responses)
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DRACOONErrorResponse {
    code: Option<i32>,
    message: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    debug_info: Option<String>,
    error_code: Option<i32>,
}

/// main error wrapping other errors (reqwest, JSON parsing)
#[derive(Debug)]
pub enum DRACOONClientError {
    RequestFailed(reqwest::Error),
    MissingArguments,
    BrokenConnection,
    DRACOONErrror(DRACOONErrorResponse),
}

impl From<reqwest::Error> for DRACOONClientError {
    fn from(error: reqwest::Error) -> Self {
        DRACOONClientError::RequestFailed(error)
    }
}

/// struct for storing DRACOON connection details
#[derive(Debug)]
pub struct DRACOONConnection {
    connected_at: DateTime<Utc>,
    access_token: String,
    access_token_validity: i64,
    refresh_token: String,
    refresh_token_validity: i64,
}

/// supported OAuth2 flows by client
pub enum OAuth2ConnectionType {
    PasswordFlow(String, String),
    AuthCode(String),
    RefreshToken,
}

/// core connection implementation for DRACOON client
impl DRACOONClient {
    /// creates a new DRACOON client instance with given OAuth app credentials and base URL
    pub fn new(base_url: Url, client_id: String, client_secret: String) -> DRACOONClient {
        let http = Client::builder()
            .user_agent(APP_USER_AGENT)
            .build()
            .unwrap();

        DRACOONClient {
            base_url: base_url,
            client_id: client_id,
            client_secret: client_secret,
            http: http,
            connected: false,
            connection: None,
        }
    }

    /// generates client credentials for password flow b64enc(client id:client secret)
    fn client_credentials(&self) -> String {
        let client_credentials = format!("{}:{}", &self.client_id, &self.client_secret);

        let client_b64 = base64::encode(client_credentials);

        client_b64
    }
    /// convert OAuth2TokenResponse to a connection item
    fn create_connection(&mut self, token_response: &OAuth2TokenResponse) -> &Self {
        let connection = DRACOONConnection {
            connected_at: Utc::now(),
            access_token: token_response.access_token.to_owned(),
            refresh_token: token_response.refresh_token.to_owned(),
            access_token_validity: token_response.expires_in_inactive,
            refresh_token_validity: token_response.expires_in,
        };
        self.connection = Some(connection);
        self.connected = true;

        self
    }

    fn get_token_url(&self) -> String {
        format!("{}{}", self.base_url.to_string(), DRACOON_TOKEN_URL)
    }

    fn get_connection(&self) -> Result<&DRACOONConnection, DRACOONClientError> {
        match &self.connection {
            Some(conn) => Ok(&conn),
            None => Err(DRACOONClientError::BrokenConnection),
        }
    }

    pub fn check_access_token_validity(&self) -> Result<bool, DRACOONClientError> {
        let conn = match &self.connection {
            Some(conn) => conn,
            None => return Err(DRACOONClientError::BrokenConnection),
        };

        let now = Utc::now();

        Ok((now - conn.connected_at).num_seconds() < conn.access_token_validity)

    }

    /// authenticated ping
    pub async fn test_connection(&self) -> Result<bool, DRACOONClientError> {
        let api_url = format!("{}{}", &self.base_url, DRACOON_AUTHENTICATED_PING);
        let conn = match self.get_connection() {
            Ok(conn) => conn,
            Err(e) => return Err(e),
        };

        let res = self
            .http
            .get(api_url)
            .bearer_auth(&conn.access_token)
            .send()
            .await?;

        match res.status() {
            reqwest::StatusCode::OK => Ok(true),
            _ => Ok(false),
        }
    }

    pub async fn disconnect(mut self, revoke_refresh: Option<bool>) -> Result<Self, DRACOONClientError> { 

        let conn = match self.get_connection() {
            Ok(conn) => conn,
            Err(e) => return Err(DRACOONClientError::BrokenConnection),
        };

        let revoke_url = format!("{}{}", &self.base_url, DRACOON_TOKEN_REVOKE_URL);

        let revoke_access = OAuth2TokenRevoke { token: conn.access_token.clone().to_owned(), token_type_hint: TOKEN_TYPE_HINT_ACCESS.to_string(), client_id: self.client_id.clone(), client_secret: self.client_secret.clone()};
        
        let res = &self.http
        .post(&revoke_url)
        .form(&revoke_access)
        .send()
        .await?;



        match res.status() {
            reqwest::StatusCode::OK => {

                Ok(self)

            },
            _ => Err(DRACOONClientError::BrokenConnection),

        }


    }

    /// main connect method
    pub async fn connect(
        &mut self,
        connection_type: OAuth2ConnectionType,
    ) -> Result<&DRACOONConnection, DRACOONClientError> {
        let token_response = match connection_type {
            OAuth2ConnectionType::AuthCode(auth_code) => self.connect_auth_code(auth_code).await,
            OAuth2ConnectionType::PasswordFlow(user_name, password) => {
                self.connect_password_flow(user_name, password).await
            }
            OAuth2ConnectionType::RefreshToken => self.connect_refresh_token().await,
        };

        let result = match token_response {
            Ok(t) => t,
            Err(e) => return Err(e),
        };

        self.create_connection(&result);

        match &self.connection {
            Some(c) => Ok(c),
            None => Err(DRACOONClientError::BrokenConnection),
        }
    }

    async fn parse_login_response(
        &self,
        res: Response,
    ) -> Result<OAuth2TokenResponse, DRACOONClientError> {
        match res.status() {
            reqwest::StatusCode::OK => Ok(res.json::<OAuth2TokenResponse>().await?),
            _ => Err(DRACOONClientError::DRACOONErrror(
                res.json::<DRACOONErrorResponse>().await?,
            )),
        }
    }

    async fn connect_password_flow(
        &self,
        user_name: String,
        password: String,
    ) -> Result<OAuth2TokenResponse, DRACOONClientError> {
 
            let client_b64 = self.client_credentials();

            let token_url = self.get_token_url();

            let auth_header = format!("Basic {}", client_b64);

            let auth = OAuth2PasswordFlow {
                username: user_name,
                password: password,
                grant_type: GRANT_TYPE_PASSWORD.to_string(),
            };

            let res = self
                .http
                .post(token_url)
                .form(&auth)
                .header(AUTHORIZATION, auth_header)
                .send()
                .await?;

            match self.parse_login_response(res).await {
                Ok(res) => Ok(res),
                Err(err) => Err(err),
            }
      
    }

    async fn connect_refresh_token(&self) -> Result<OAuth2TokenResponse, DRACOONClientError> {
        let refresh_token: String;

        match &self.connection {
            Some(connection) => refresh_token = connection.refresh_token.clone(),
            None => return Err(DRACOONClientError::BrokenConnection),
        }

        let token_url = self.get_token_url();

        let auth = OAuth2RefreshTokenFlow {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            refresh_token: refresh_token,
            grant_type: GRANT_TYPE_REFRESH_TOKEN.to_string(),
        };

        let res = self.http.post(token_url).form(&auth).send().await?;

        match self.parse_login_response(res).await {
            Ok(res) => Ok(res),
            Err(err) => Err(err),
        }
    }

    pub fn get_code_url(&self) -> String {
        let authorize_url = format!("oauth/authorize?branding=full&response_type=code&client_id={}&redirect_uri={}oauth/callback&scope=all", self.client_id, self.base_url.to_string());

        format!("{}{}", &self.base_url.to_string(), authorize_url.as_str())
    }

    pub async fn connect_auth_code(
        &self,
        auth_code: String,
    ) -> Result<OAuth2TokenResponse, DRACOONClientError> {
        
            let token_url = self.get_token_url();

            let auth = OAuth2AuthCodeFlow {
                client_id: self.client_id.clone(),
                client_secret: self.client_secret.clone(),
                code: auth_code,
                grant_type: GRANT_TYPE_AUTH_CODE.to_string(),
                redirect_uri: format!("{}{}", self.base_url.to_string(), DRACOON_REDIRECT_URL),
            };

            let res = self.http.post(token_url).form(&auth).send().await?;
            match self.parse_login_response(res).await {
                Ok(res) => Ok(res),
                Err(err) => Err(err),
            }
        
    }
}
