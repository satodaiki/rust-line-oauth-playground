use axum::{extract::{Query, State}, response::Html, routing::get, Router, http::StatusCode};
use serde::{Serialize, Deserialize};
use reqwest::Client;
use serde_json::{Value, json};
use tera::{Tera, Context};
use tower_http::services::ServeDir;
use rand::distributions::{Alphanumeric, DistString};
use sqlx::{PgPool, postgres::PgPoolOptions};
use chrono::{Local, DateTime, Duration};
use oauth2::CsrfToken;


#[derive(Serialize)]
struct LineLogin {
    client_id: String,
    redirect_uri: String,
    state: String,
    scope: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct LineCallbackQuery {
    code: String,
    state: String,
    friendship_status_changed: Option<bool>,
    liffClientId: Option<String>,
    liffRedirectUri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LineCallbackError {
    error: String,
    error_description: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_in: i32,
    id_token: String,
    refresh_token: String,
    scope: String,
    token_type: String,
}

#[derive(Debug, Clone)]
struct BaseSetting {
    redirect_uri: String,
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Clone)]
struct AppState {
    tera: Tera,
    pool: PgPool,
    http_client: Client,
    setting: BaseSetting,
}

async fn login_page(
    State(state): State<AppState>,
) -> Html<String> {
    let csrf_token = CsrfToken::new_random().secret().clone();

    let expire = Local::now() + Duration::hours(1);

    sqlx::query(r"INSERT INTO line_state VALUES ($1, $2);")
        .bind(csrf_token.clone())
        .bind(expire)
        .execute(&state.pool)
        .await
        .unwrap();

    let line = LineLogin {
        client_id: state.setting.client_id,
        redirect_uri: state.setting.redirect_uri,
        state: csrf_token,
        scope: "openid profile".to_string(),
        nonce: "09876xyz".to_string(),
    };

    let context = Context::from_serialize(&line).unwrap();
    let html = state.tera.render("login.html", &context).unwrap();

    Html(html)
}

async fn line_callback(
    Query(query): Query<Value>,
    State(state): State<AppState>,
) {
    // エラーの場合
    // https://developers.line.biz/ja/docs/line-login/integrate-line-login/#receiving-an-error-response
    if query.get("error").is_some() {
        let query: LineCallbackError = serde_json::from_value(query).unwrap();
        eprintln!("リダイレクト時にエラーが発生しました: {:?}", query);
        return
    }

    // 正常な場合
    // https://developers.line.biz/ja/docs/line-login/integrate-line-login/#receiving-the-authorization-code
    println!("query: {:?}", query);
    let query: LineCallbackQuery = serde_json::from_value(query).unwrap();

    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM line_state WHERE state = $1")
        .bind(query.state)
        .fetch_one(&state.pool)
        .await
        .unwrap();

    // stateが存在しない場合はアクセストークンの取得は行わない
    if row.0 == 0 {
        return
    }

    let params = json!({
        "grant_type": "authorization_code",
        "code": query.code,
        "redirect_uri": state.setting.redirect_uri,
        "client_id": state.setting.client_id,
        "client_secret": state.setting.client_secret,
    });

    // アクセストークンを取得する
    // https://developers.line.biz/ja/docs/line-login/integrate-line-login/#get-access-token
    let res = state.http_client.post("https://api.line.me/oauth2/v2.1/token")
        .form(&params)
        .send().await.unwrap();

    let res_json: AccessTokenResponse = res.json().await.unwrap();
    println!("res: {:?}", res_json);
}

#[tokio::main]
async fn main() {
    // 環境変数をdotenvで取得する
    dotenv::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url.as_str()).await
        .expect("poolの作成に失敗しました");

    sqlx::migrate!().run(&pool.clone()).await.expect("マイグレーションに失敗しました");

    let setting = BaseSetting {
        redirect_uri: std::env::var("REDIRECT_URI")
            .expect("REDIRECT_URI must be set"),
        client_id: std::env::var("CLIENT_ID")
            .expect("CLIENT_ID must be set"),
        client_secret: std::env::var("CLIENT_SECRET")
            .expect("CLIENT_SECRET must be set"),
    };

    let http_client = reqwest::Client::new();

    let tera = match Tera::new("templates/**/*.html") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };

    let state = AppState {
        tera,
        http_client,
        setting,
        pool,
    };

    let app = Router::new()
        .route("/callback", get(line_callback))
        // .route("/hello", get(hello_world))
        .route("/login", get(login_page))
        .nest_service("/public", ServeDir::new("public"))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
