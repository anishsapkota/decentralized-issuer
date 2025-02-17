use actix_web::http::StatusCode;
use actix_web::{get, post};
use actix_web::{middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer};
use base64::URL_SAFE_NO_PAD;
use chrono::Utc;
use dotenv::dotenv;
use helpers::generate_jwt_header_and_payload;
use jsonwebtoken::{
    dangerous_insecure_decode, decode, encode, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use openssl::bn::BigNumContext;
use openssl::pkey::PKey;
use rand::{thread_rng, RngCore};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

mod helpers;

// helper function
fn generate_nonce(length: usize) -> String {
    let mut rng = thread_rng();
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    scope: String,
    credential_identifier: Option<String>,
    nonce: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    response_uri: Option<String>,
    response_mode: Option<String>,
    response_type: Option<String>,
}

struct AppState {
    authorization_codes: Mutex<HashMap<String, AuthorizationCodeEntry>>,
    access_tokens: Mutex<HashMap<String, String>>,
    private_key_pem: String,
    public_key_pem: String,
    offer_map: Mutex<HashMap<String, OfferEntry>>,
}

struct AuthorizationCodeEntry {
    code_challenge: String,
    auth_code: Option<String>,
    issuer_state: Option<String>,
}

struct OfferEntry {
    issuer_state: String,
    pre_authorized_code: String,
    credential_data: Option<serde_json::Value>,
}

// Log each request and response
async fn log_request(req: &HttpRequest, body: &str) {
    let method = req.method();
    let uri = req.uri();
    let peer_addr = req.peer_addr().map_or("unknown".to_string(), |addr| addr.to_string());
    println!(
        "[{}] {} {} from {} - Body: {}",
        Utc::now(),
        method,
        uri,
        peer_addr,
        body
    );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("===== Starting Issuer-Frontend Server: Listening at 3000 ======");
    dotenv().ok();

    // Read the private and public keys
    let private_key_pem =
        fs::read_to_string("./certs/demo_private.pem").expect("Unable to read private key");
    let public_key_pem =
        fs::read_to_string("./certs/demo_public.pem").expect("Unable to read public key");

    // Initialize in-memory storage
    let data = web::Data::new(AppState {
        authorization_codes: Mutex::new(HashMap::new()),
        access_tokens: Mutex::new(HashMap::new()),
        offer_map: Mutex::new(HashMap::new()),
        private_key_pem,
        public_key_pem,
    });

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .wrap(Logger::default())
            //.service(verify_access_token)
            .service(jwks)
            .service(openid_configuration)
            .service(test)
            //.service(authorize)
            //.service(direct_post)
            .service(token)
            .service(credential_offer)
            .service(credential)
            .service(credential_offer_id)
            .service(credential_issuer_metadata)
    })
    .bind(host)?
    .run()
    .await
}

#[derive(Deserialize)]
struct VerifyAccessTokenRequest {
    token: String,
}

#[derive(Deserialize, Serialize)]
struct CredentialOffer {
    credentialSubject: serde_json::Value,
    r#type: Vec<String>,
}

#[get("/jwks")]
async fn jwks(req: HttpRequest,data: web::Data<AppState>) -> HttpResponse {
    log_request(&req, "GET /jwks").await;

    let jwk = match pem_to_jwk(&data.public_key_pem, "public") {
        Ok(jwk) => jwk,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to parse public key"),
    };

    let key1 = JwkResponseKey {
        kty: jwk.kty.clone(),
        crv: jwk.crv.clone(),
        x: jwk.x.clone(),
        y: jwk.y.clone(),
        kid: "did:ebsi:zrZZyoQVrgwpV1QZmRUHNPz#sig-key".to_string(),
        use_field: "sig".to_string(),
    };

    let key2 = JwkResponseKey {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        kid: "did:ebsi:zrZZyoQVrgwpV1QZmRUHNPz#authentication-key".to_string(),
        use_field: "keyAgreement".to_string(),
    };

    let response = JwkResponse {
        keys: vec![key1, key2],
    };

    HttpResponse::Ok().json(response)
}

#[derive(Serialize)]
struct JwkResponse {
    keys: Vec<JwkResponseKey>,
}

#[derive(Serialize)]
struct JwkResponseKey {
    kty: String,
    crv: String,
    x: String,
    y: String,
    kid: String,
    #[serde(rename = "use")]
    use_field: String,
}

fn pem_to_jwk(pem: &str, key_type: &str) -> Result<JwkKey, Box<dyn std::error::Error>> {
    if key_type == "public" {
        let pkey = PKey::public_key_from_pem(pem.as_bytes())?;
        let ec_key = pkey.ec_key()?;
        let group = ec_key.group();
        let point = ec_key.public_key();

        let mut ctx = BigNumContext::new()?;

        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        let x_bytes = x.to_vec();
        let y_bytes = y.to_vec();

        let x_b64 = base64::encode_config(&x_bytes, base64::URL_SAFE_NO_PAD);
        let y_b64 = base64::encode_config(&y_bytes, base64::URL_SAFE_NO_PAD);

        Ok(JwkKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: x_b64,
            y: y_b64,
            d: None,
        })
    } else {
        // Handle private key if necessary
        Err("Unsupported key type".into())
    }
}

#[derive(Serialize, Clone)]
struct JwkKey {
    kty: String,
    crv: String,
    x: String,
    y: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
}

#[post("/offer")]
async fn credential_offer(
    req: HttpRequest,
    data: web::Data<AppState>,
    req_body: web::Json<CredentialOffer>,
) -> HttpResponse {
    log_request(&req, "POST /offer").await;
    let uuid = Uuid::new_v4().to_string();
    let issuer_state = Uuid::new_v4().to_string();
    let pre_authorized_code = generate_nonce(32);

    let credential_data = req_body.0;
    let entry = OfferEntry {
        issuer_state: issuer_state.clone(),
        pre_authorized_code: pre_authorized_code.clone(),
        credential_data: Some(serde_json::json!({
            "credentialSubject": credential_data.credentialSubject,
            "type": credential_data.r#type,
        })),
    };

    let mut offer_map = data.offer_map.lock().unwrap();
    offer_map.insert(pre_authorized_code.clone(), entry);
    drop(offer_map);

    let server_url = env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let credential_offer_uri = format!("{}/credential-offer/{}", server_url, pre_authorized_code);
    let credential_offer = format!(
        "openid-credential-offer://?credential_offer_uri={}",
        credential_offer_uri
    );

    HttpResponse::Ok().body(credential_offer)
}

#[get("/credential-offer/{id}")]
async fn credential_offer_id(req: HttpRequest,
    data: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    log_request(&req, &format!("GET /credential-offer/{}",id)).await;

    let offer_map = data.offer_map.lock().unwrap();
    let entry = offer_map.get(&id);
    if entry.is_none() {
        return HttpResponse::NotFound().finish();
    }
    let entry = entry.unwrap();

    let response = serde_json::json!({
        "credential_issuer": env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
        //"credentials": entry.credential_data.as_ref().unwrap()["type"],
        "credential_configuration_ids": [
        "UniversityDegreeCredential"
        ],
        "grants": {
            // "authorization_code": {
            //     "issuer_state": entry.issuer_state,
            // },
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": entry.pre_authorized_code,
                //"user_pin_required": true,
                "tx_code": {
                    "length": 4,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code that was sent via e-mail or offline"
                 }
            },
        }
    });

    HttpResponse::Ok().json(response)
}

#[get("/.well-known/openid-credential-issuer")]
async fn credential_issuer_metadata(req:HttpRequest) -> HttpResponse {
    log_request(&req, "GET /.well-known/openid-credential-issuer").await;
    let metadata_path = PathBuf::from("metadata/issuer_config.json");
    let mut file = match File::open(&metadata_path) {
        Ok(file) => file,
        Err(_) => return HttpResponse::InternalServerError().body("Error opening metadata file"),
    };

    let mut metadata_content = String::new();
    if let Err(_) = file.read_to_string(&mut metadata_content) {
        return HttpResponse::InternalServerError().body("Error reading metadata file");
    }
    let metadata_json: serde_json::Value =
        serde_json::from_str(&metadata_content).expect("JSON was not well-formatted");
    HttpResponse::Ok()
        .status(StatusCode::OK)
        .json(metadata_json)
}

#[get("/.well-known/openid-configuration")]
async fn openid_configuration(req:HttpRequest) -> HttpResponse {
    log_request(&req, "GET /.well-known/oauth-authorization-server").await;
    // Read environment variables
    let server_url = env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:7001".to_string());
    // let auth_server_url: String =
    //     env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:7001".to_string());

    let config = serde_json::json!({
        "issuer": format!("{}", server_url),
        "authorization_endpoint": format!("{}/authorize", server_url),
        "token_endpoint": format!("{}/token", server_url),
        "jwks_uri": format!("{}/jwks", server_url),
        "scopes_supported": ["openid"],
        "response_types_supported": ["vp_token", "id_token"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "pre-authorized_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "request_object_signing_alg_values_supported": ["ES256"],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "request_authentication_methods_supported": {
            "authorization_endpoint": ["request_object"],
        },
        "vp_formats_supported": {
            "jwt_vp": {
                "alg_values_supported": ["ES256"],
            },
            "jwt_vc": {
                "alg_values_supported": ["ES256"],
            },
        },
        "subject_syntax_types_supported": [
            "did:key:jwk_jcs-pub",
            "did:ebsi:v1",
            "did:ebsi:v2",
        ],
        "subject_trust_frameworks_supported": ["ebsi"],
        "id_token_types_supported": [
            "subject_signed_id_token",
            "attester_signed_id_token",
        ],
    });

    HttpResponse::Ok().json(config)
}

#[derive(Deserialize, Debug)]
struct TokenRequest {
    client_id: Option<String>,
    code: Option<String>,
    code_verifier: Option<String>,
    grant_type: Option<String>,
    tx_code: Option<String>,
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: Option<String>,
}

#[post("/token")]
async fn token(req:HttpRequest,data: web::Data<AppState>, req_body: web::Form<TokenRequest>) -> HttpResponse {
    log_request(&req, "POST /token").await;
    let client_id = req_body.client_id.as_deref().unwrap_or("");
    let grant_type = req_body.grant_type.as_deref().unwrap_or("");
    let pre_authorized_code = req_body.pre_authorized_code.as_deref();
    let tx_code = req_body.tx_code.as_deref();
    let code_verifier = req_body.code_verifier.as_deref();
    let code = req_body.code.as_deref();

    let credential_identifier;

    if grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
        println!("pre-auth code flow: {}", pre_authorized_code.unwrap_or(""));
        if tx_code.unwrap_or("") != "1234" {
            println!("Invalid pin: {}", tx_code.unwrap_or(""));
            return HttpResponse::BadRequest().body("Invalid pin");
        }
        credential_identifier = pre_authorized_code.unwrap_or("").to_string();
    } else if grant_type == "authorization_code" {
        println!("authorization code workflow");
        let code_verifier_hash = base64_url_encode_sha256(code_verifier.unwrap_or(""));
        let authorization_codes = data.authorization_codes.lock().unwrap();
        let client_session = authorization_codes.get(client_id);
        if let Some(client_session) = client_session {
            credential_identifier = client_session.issuer_state.clone().unwrap_or_default();
            if code.unwrap_or("") != client_session.auth_code.as_deref().unwrap_or("")
                || code_verifier_hash != client_session.code_challenge
            {
                return HttpResponse::BadRequest().body("Client could not be verified");
            }
        } else {
            return HttpResponse::BadRequest().body("Client session not found");
        }
    } else {
        return HttpResponse::BadRequest().body("Unsupported grant_type");
    }

    let generated_access_token = generate_access_token(
        client_id.to_string(),
        credential_identifier.clone(),
        &data.private_key_pem,
    );

    let mut access_tokens = data.access_tokens.lock().unwrap();
    access_tokens.insert(client_id.to_string(), generated_access_token.clone());
    drop(access_tokens);

    let response = serde_json::json!({
        "access_token": generated_access_token,
        "token_type": "bearer",
        "expires_in": 86400,
        "c_nonce": generate_nonce(16),
        "c_nonce_expires_in": 86400,
    });

    HttpResponse::Ok().json(response)
}

fn generate_access_token(
    sub: String,
    credential_identifier: String,
    private_key_pem: &str,
) -> String {
    let server_url = env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:7001".to_string());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let exp = now + 60 * 60;

    let claims = Claims {
        iss: server_url.clone(),
        sub: sub.clone(),
        aud: server_url.clone(),
        exp,
        iat: now,
        scope: "openid".to_string(),
        credential_identifier: Some(credential_identifier),
        nonce: None,
        state: None,
        client_id: None,
        response_uri: None,
        response_mode: None,
        response_type: None,
    };

    let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes()).unwrap();
    let header = Header {
        alg: Algorithm::ES256,
        ..Default::default()
    };

    encode(&header, &claims, &encoding_key).unwrap()
}

fn base64_url_encode_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    base64::encode_config(&hash, URL_SAFE_NO_PAD)
}

#[get("/test")]
async fn test(req: HttpRequest) -> HttpResponse {

    log_request(&req, "GET /test").await;

    let client = Client::new();
    let proxy_url = env::var("PROXY_URL").unwrap_or_else(|_| "http://127.0.0.1:3030/sign".to_string());
    let res = client
        .post(proxy_url)
        .json(&serde_json::json!({"hash":"to_be_signed_hash"}))
        .send()
        .await;

    let signature = match res {
        Ok(jwt) => jwt.text().await,
        Err(err) => {
            println!("Error signing JWT: {}", err);
            return HttpResponse::InternalServerError().body("Error issuing credential");
        }
    }
    .expect("Error unwrapping signature string");
    
    HttpResponse::Ok().body(signature)

}

#[post("/credential")]
async fn credential(
    data: web::Data<AppState>,
    req: HttpRequest,
    req_body: web::Json<serde_json::Value>,
) -> HttpResponse {
    log_request(&req, "POST /credential").await;
    // Authenticate the access token
    let auth_header = req.headers().get("Authorization");
    if auth_header.is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let auth_header = auth_header.unwrap().to_str().unwrap_or("");
    if !auth_header.starts_with("Bearer ") {
        return HttpResponse::Unauthorized().finish();
    }
    let bearer_tok = &auth_header[7..];

    if bearer_tok.is_empty() {
        return HttpResponse::BadRequest().body("Token is required");
    }

    let (res, message, credential_identifier) =
        verify_access_token(data.clone(), bearer_tok.to_string()).await;

    if !res || credential_identifier.is_none() {
        return HttpResponse::Unauthorized().body(message);
    }
    // Extract the request body
    let request_body = req_body.into_inner();

    // Get the subject DID from the proof JWT if present
    let mut subject_did = "".to_string();
    if let Some(proof) = request_body.get("proof") {
        if let Some(jwt_value) = proof.get("jwt") {
            if let Some(jwt_str) = jwt_value.as_str() {
                // Decode the JWT without verification (insecure)
                let decoded = dangerous_insecure_decode::<serde_json::Value>(jwt_str);
                if let Ok(decoded_token) = decoded {
                    if let Some(iss) = decoded_token.claims.get("iss") {
                        if let Some(iss_str) = iss.as_str() {
                            subject_did = iss_str.to_string();
                        }
                    }
                }
            }
        }
    }

    // Retrieve credential data from offer_map
    let offer_map = data.offer_map.lock().unwrap();
    let credential_data_option = offer_map
        .get(&credential_identifier.unwrap())
        .map(|entry| entry.credential_data.clone());
    drop(offer_map);
    // Construct the credential subject
    let credential_subject = if let Some(Some(credential_data)) = &credential_data_option {
        let mut credential_subject = credential_data
            .get("credentialSubject")
            .cloned()
            .unwrap_or_default();

        credential_subject["id"] = serde_json::Value::String(subject_did.clone());
        credential_subject["issuance_date"] = serde_json::Value::String(
            Utc::now()
                .naive_utc()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
        );
        credential_subject
    } else {
        // Default data if no credential data is found
        serde_json::json!({
            "id": subject_did,
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "degree": "Bachelor of Computer Science",
            "gpa": "1.2",
            "age_over_18": true,
            "issuance_date": Utc::now().naive_utc().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        })
    };

    // Build the JWT payload
    let server_url = env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:7001".to_string());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let exp = now + 60 * 60;

    let payload = serde_json::json!({
        "iss": server_url,
        "sub": subject_did,
        "iat": now,
        "exp": exp,
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://europa.eu/2018/credentials/eudi/pid/v1"
            ],
            "id": subject_did,
            "type": credential_data_option
                .and_then(|cd| cd.as_ref().and_then(|cd| cd.get("type").cloned()))
                .unwrap_or_else(|| serde_json::json!(["UniversityDegreeCredential"])),
            "issuer": "did:ebsi:zrZZyoQVrgwpV1QZmRUHNPz",
            "issuanceDate": Utc::now()
                .naive_utc()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            "credentialSubject": credential_subject
        }
    });


    let header_payload = generate_jwt_header_and_payload(&payload);

    let mut hasher = Sha256::new();
    hasher.update(header_payload.as_bytes());
    let result = hasher.finalize();

    let to_be_signed_hash = hex::encode(result);

    // send post request to the threshold-sig-nodes
    let client = Client::new();
    let proxy_url = env::var("PROXY_URL").unwrap_or_else(|_| "http://127.0.0.1:3030/sign".to_string());
    let res = client
        .post(proxy_url)
        .json(&serde_json::json!({"hash":to_be_signed_hash}))
        .send()
        .await;

    let signature = match res {
        Ok(jwt) => jwt.text().await,
        Err(err) => {
            println!("Error signing JWT: {}", err);
            return HttpResponse::InternalServerError().body("Error issuing credential");
        }
    }
    .expect("Error unwrapping signature string");
    //println!("{}", signature.as_ref().unwrap());
    let credential_jwt = format!("{}.{}", header_payload, &signature[1..signature.len() - 1]);
    println!("{}", credential_jwt);
    // Build the response
    let response = serde_json::json!({
        "format": "jwt_vc",
        "credential": credential_jwt,
        "c_nonce": generate_nonce(16),
        "c_nonce_expires_in": 86400,
    });

    HttpResponse::Ok().json(response)
}

async fn verify_access_token(
    data: web::Data<AppState>,
    tok: String,
) -> (bool, String, Option<String>) {
    let public_key_pem = &data.public_key_pem;
    let public_key = DecodingKey::from_ec_pem(public_key_pem.as_bytes());
    if public_key.is_err() {
        return (false, "Invalid public key".to_string(), None);
    }
    let public_key = public_key.unwrap();

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[
        env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    ]);

    let token_data = decode::<Claims>(&tok, &public_key, &validation);
    match token_data {
        Ok(token_data) => {
            let now = Utc::now().timestamp();
            if token_data.claims.exp < now {
                return (false, "Token expired".to_string(), None);
            }

            let access_tokens = data.access_tokens.lock().unwrap();
            let stored_token = access_tokens.get(&token_data.claims.sub);
            if stored_token != Some(&tok) {
                return (false, "Invalid token".to_string(), None);
            }

            return (
                true,
                "Valid".to_string(),
                token_data.claims.credential_identifier,
            );
        }
        Err(_) => (false, "Error validating token".to_string(), None),
    }
}

