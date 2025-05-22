#[macro_use] extern crate rocket;

use rocket::{Request, State, http::{CookieJar, Cookie, SameSite, Status}, response::Redirect, serde::json::Json, Config as RocketConfig}; // Renomeado Config para RocketConfig para evitar conflito com argon2::Config
use sqlx::{PgPool};
use dotenvy::dotenv;
use std::env;
use rocket::form::Form;
use rocket::serde::{Deserialize, Serialize};
use rocket::{Response, fairing::{Fairing, Info, Kind}};
use rocket::http::Header;
use rocket::fs::TempFile;
use tokio::io::AsyncReadExt;
use reqwest::Client;
use argon2::{self, password_hash::{SaltString, PasswordHasher, PasswordVerifier, rand_core::OsRng, PasswordHash}, Argon2};
use base64::Engine;

//configuração do CORS para acesso dos metodos pelo live sever
pub struct Cors;

#[async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "CORS Fairing",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "http://127.0.0.1:5500"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET, OPTIONS"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "Content-Type"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));

        if request.method() == rocket::http::Method::Options {
            response.set_status(rocket::http::Status::Ok);
        }
    }
}
#[options("/<_..>")]
fn all_options() -> rocket::http::Status {
    rocket::http::Status::Ok
}



//Formulario do login
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct LoginForm {
    email: String,
    password: String,
}


//formulario para envio de imagem
#[derive(FromForm)]
pub struct Upload<'r> {
    pub imagem: TempFile<'r>,
    pub texto: String,
}


#[derive(Serialize)]
struct OpenRouterRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: Vec<MessageContent>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum MessageContent {
    #[serde(rename = "text")]
    Text(MessageText),

    #[serde(rename = "image_url")]
    Image(MessageImage),
}

#[derive(Serialize, Deserialize)]
struct MessageText {
    #[serde(rename = "type")]
    r#type: String,
    text: String,
}


#[derive(Serialize, Deserialize)]
struct MessageImage {
    #[serde(rename = "type")]
    r#type: String,
    image_url: ImageUrl,
}


#[derive(Serialize, Deserialize)]
struct ImageUrl {
    url: String,
}


#[derive(Deserialize)]
struct OpenRouterResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: String,
}

//FORMULARIO DE CADASTRO
#[derive(FromForm)]
struct CadastroForm{
    pub name: String,
    pub email: String,
    pub password: String,
}

//user struct para POSTGRESQL
#[derive(sqlx::FromRow, Serialize, Deserialize)]
struct User {
    id: i32,
    name: Option<String>,
    role: Option<bool>,
    email: Option<String>,
    password: String,
}

//STRUCT DOS INGREDIENTES NO BANCO DE DADOS
#[derive(Deserialize, Serialize, sqlx::FromRow)]
#[serde(crate = "rocket::serde")]
struct Foods {
    food: String,
}

//STRUCT DA RECEITA PARA POSTGRESQL
#[derive(Deserialize, Serialize, sqlx::FromRow)]
struct Receita{
    id: i32,
    title: String,
    ingredients: String,
    instructions: String,
}

//FORMULARIO DA RECEITA
#[derive(Deserialize, Serialize, sqlx::FromRow)]
struct ReceitaForm {
    title: String,
    ingredients: String,
    instructions: String,
}

//FORMULARIO DA LISTA DE INGREDIENTES
#[derive(Deserialize, Serialize,FromForm, sqlx::FromRow)]
#[serde(crate = "rocket::serde")]
struct IngredientsList{
    list: Vec<String>,
}

//FORMULÁRIO PARA CURTIR
#[derive(FromForm)]
struct CurtidaForm {
    receita_id: i32,
}




//FUNÇÃO PARA HASHEAR A SENHA DO USUARIO ANTES DE GUARDAR NO DB
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

//FUNÇÃO PARA COMPARAR A SENHA DO USUARIO COM A CRIPTOGRAFIA
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

//ADICIONAR RECEITA AS CURTIDAS
#[post("/curtir", data = "<form>")]
async fn curtir_receita(
    cookies: &CookieJar<'_>,
    db: &State<PgPool>,
    form: Form<CurtidaForm>,
) -> Result<Status, Status> {
    let email = match cookies.get("user_email") { // MODIFIED: get instead of get_private
        Some(cookie) => cookie.value().to_string(),
        None => return Err(Status::Unauthorized),
    };

    let receita_id = form.receita_id;

    // Atualizar a lista de curtidas no banco (adiciona se ainda não estiver lá)
    let result = sqlx::query!(
        r#"
        UPDATE users
        SET liked = (
            SELECT jsonb_agg(distinct value)
            FROM jsonb_array_elements_text(liked || to_jsonb($1::text))
        )
        WHERE email = $2
        "#,
        receita_id.to_string(), // jsonb_array_elements_text trabalha com texto
        email
    )
        .execute(db.inner())
        .await;

    match result {
        Ok(_) => Ok(Status::Ok),
        Err(e) => {
            eprintln!("Erro ao curtir receita: {}", e);
            Err(Status::InternalServerError)
        }
    }
}


//LISTA AS RECEITAS CURTIDAS
#[get("/curtidas")]
async fn visualizar_curtidas(
    cookies: &CookieJar<'_>,
    db: &State<PgPool>,
) -> Result<Json<Vec<Receita>>, Status> {
    let email = match cookies.get("user_email") {
        Some(cookie) => cookie.value().to_string(),
        None => return Err(Status::Unauthorized),
    };

    let receitas = sqlx::query_as!(
        Receita,
        r#"
        SELECT r.id, r.title, r.ingredients, r.instructions
        FROM recipes r
        JOIN (
            SELECT jsonb_array_elements_text(liked)::int AS receita_id
            FROM users
            WHERE email = $1
        ) AS user_liked ON r.id = user_liked.receita_id
        "#,
        email
    )
        .fetch_all(db.inner())
        .await;

    match receitas {
        Ok(lista) => Ok(Json(lista)),
        Err(e) => {
            eprintln!("Erro ao buscar curtidas: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

//GERA UMA NOVA RECEITA BASEADO NOS INGREDIENTES SELECIONADOS
#[post("/gerar", format = "json", data = "<form>")]
async fn gerar(
    form: Json<IngredientsList>,
    db: &State<PgPool>,
    cookies: &CookieJar<'_>
) -> Result<Json<Receita>, Status> {
    let ingredientes = &form.list;

    println!("Ingredientes recebidos: {:?}", ingredientes);

    let email_cookie = cookies.get("user_email").map(|c| c.value().to_string()); // MODIFIED: get instead of get_private
    let email = match email_cookie {
        Some(e) => e,
        None => {
            println!("Cookie não encontrado");
            return Err(Status::Unauthorized);
        }
    };

    let prompt = format!(
        "Crie uma receita usando os ingredientes: {}.
    Responda somente com um JSON puro (sem texto antes ou depois) com os campos:
    'title' (string), 'ingredients' (string), e 'instructions' (string).
    Exemplo:
    {{
        \"title\": \"Nome\",
        \"ingredients\": \"lista de ingredientes\",
        \"instructions\": \"modo de preparo\"
    }}", ingredientes.join(", ")
    );

    println!("Prompt enviado: {}", prompt);

    let client = reqwest::Client::new();
    let openrouter_key = std::env::var("OPENROUTER_API_KEY").expect("OPENROUTER_API_KEY not set");

    let response = client.post("https://openrouter.ai/api/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", openrouter_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "model": "meta-llama/llama-3-8b-instruct",
            "messages": [{"role": "user", "content": prompt}]
        }))
        .send()
        .await;

    let response = match response {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Erro ao enviar requisição para o OpenRouter: {}", e);
            return Err(Status::InternalServerError);
        }
    };

    let json_resp: serde_json::Value = match response.json().await {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Erro ao interpretar JSON do OpenRouter: {}", e);
            return Err(Status::InternalServerError);
        }
    };

    println!("Resposta da IA: {}", json_resp);

    let content = match json_resp["choices"][0]["message"]["content"].as_str() {
        Some(c) => c,
        None => {
            eprintln!("Campo 'content' não encontrado na resposta da IA.");
            return Err(Status::InternalServerError);
        }
    };

    // Desserializa para ReceitaForm (sem campo id)
    let receita_form: ReceitaForm = match serde_json::from_str(content) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Erro ao desserializar Receita: {}", e);
            return Err(Status::UnprocessableEntity);
        }
    };

    println!("Receita gerada: {:?}", receita_form.title);

    // Insere no banco e retorna Receita com id
    let row = sqlx::query_as::<_, Receita>(
        "INSERT INTO recipes (title, ingredients, instructions)
         VALUES ($1, $2, $3) RETURNING id, title, ingredients, instructions"
    )
        .bind(&receita_form.title)
        .bind(&receita_form.ingredients)
        .bind(&receita_form.instructions)
        .fetch_one(db.inner())
        .await;

    let row = match row {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Erro ao inserir receita no banco: {}", e);
            return Err(Status::InternalServerError);
        }
    };

    // Atualiza o histórico do usuário com o id da receita criada
    let update_result = sqlx::query(
        "UPDATE users SET history =
     CASE
         WHEN history IS NULL THEN jsonb_build_array($1)
         ELSE history || jsonb_build_array($1)
     END
     WHERE email = $2"
    )
        .bind(row.id)
        .bind(&email)
        .execute(db.inner())
        .await;

    if let Err(e) = update_result {
        eprintln!("Erro ao atualizar histórico do usuário: {}", e);
        return Err(Status::InternalServerError);
    }

    Ok(Json(row))
}


//RECEBE UMA FOTO E GERA A RECEITA A PARTIR DOS INGREDIENTES IDENTIFICADOS
#[post("/upload", data = "<form>")]
async fn upload(
    form: Form<Upload<'_>>,
    db: &State<PgPool>,
    cookies: &CookieJar<'_>
) -> Result<Json<Receita>, Status> {
    //CONFIRMA SEÇÃO DO USUARIO VIA COOKIES
    let email = match cookies.get("user_email") {
        Some(cookie) => cookie.value().to_string(),
        None => return Err(Status::Unauthorized),
    };

    //RECEBE A IMAGEM
    let content_type = form.imagem.content_type().map(|ct| ct.to_string()).unwrap_or("image/jpeg".to_string());
    let mut bytes = Vec::new();
    let mut file = form.imagem.open().await.map_err(|e| e.to_string()).map_err(|_| Status::BadRequest)?;
    file.read_to_end(&mut bytes).await.map_err(|e| e.to_string()).map_err(|_| Status::BadRequest)?;

    //CONVERTE IMAGEM PARA BASE64
    let base64_img = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let data_url = format!("data:{};base64,{}", content_type, base64_img);

    //PROMPT PARA GERAR A RECEITA
    let prompt = format!(
        "Crie uma receita usando os ingredientes visíveis na imagem e considere também o seguinte: {}.\n\
        Responda somente com um JSON puro (sem texto antes ou depois) com os campos:\n\
        'title' (string), 'ingredients' (string), e 'instructions' (string).\n\
        Exemplo:\n\
        {{\n\
            \"title\": \"Nome\",\n\
            \"ingredients\": \"lista de ingredientes\",\n\
            \"instructions\": \"modo de preparo\"\n\
        }}",
        form.texto
    );

    let body = OpenRouterRequest {
        model: "meta-llama/llama-4-scout".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: vec![
                MessageContent::Text(MessageText {
                    r#type: "text".to_string(),
                    text: prompt,
                }),
                MessageContent::Image(MessageImage {
                    r#type: "image_url".to_string(),
                    image_url: ImageUrl {
                        url: data_url,
                    },
                }),
            ],
        }],
    };

    let client = Client::new();
    let api_key = std::env::var("OPENROUTER_API_KEY").expect("OPENROUTER_API_KEY not set");

    let res = client
        .post("https://openrouter.ai/api/v1/chat/completions")
        .bearer_auth(api_key)
        .header("HTTP-Referer", "https://seuprojeto.com") //
        .header("X-Title", "Projeto meloon") //
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            eprintln!("Erro ao enviar request: {}", e);
            Status::InternalServerError
        })?;

    let status = res.status();
    let text = res.text().await.unwrap_or_default();

    if !status.is_success() {
        eprintln!("Erro da API: {} - {}", status, text);
        return Err(Status::InternalServerError);
    }

    let json: OpenRouterResponse = serde_json::from_str(&text)
        .map_err(|e| {
            eprintln!("Erro ao ler resposta: {} - Body: {}", e, text);
            Status::InternalServerError
        })?;

    let content = json.choices.first()
        .map(|c| c.message.content.clone())
        .ok_or_else(|| Status::InternalServerError)?;

    let receita_form: ReceitaForm = serde_json::from_str(&content).map_err(|e| {
        eprintln!("Erro ao desserializar JSON da IA: {} - Content: {}", e, content);
        Status::UnprocessableEntity
    })?;

    //INSERE RECEITA NO DB
    let row = sqlx::query_as::<_, Receita>(
        "INSERT INTO recipes (title, ingredients, instructions)
         VALUES ($1, $2, $3) RETURNING id, title, ingredients, instructions"
    )
        .bind(&receita_form.title)
        .bind(&receita_form.ingredients)
        .bind(&receita_form.instructions)
        .fetch_one(db.inner())
        .await
        .map_err(|e| {
            eprintln!("Erro ao inserir receita: {}", e);
            Status::InternalServerError
        })?;

    //ATUALIZA O HISTORICO
    let update_result = sqlx::query(
        "UPDATE users SET history =
         CASE
             WHEN history IS NULL THEN jsonb_build_array($1)
             ELSE history || jsonb_build_array($1)
         END
         WHERE email = $2"
    )
        .bind(row.id)
        .bind(&email)
        .execute(db.inner())
        .await;

    if let Err(e) = update_result {
        eprintln!("Erro ao atualizar histórico do usuário: {}", e);
        return Err(Status::InternalServerError);
    }

    Ok(Json(row))
}


//CARREGA OS INGREDIENTES NA PAGINA
#[get("/gerador")]
async fn gerador(db: &State<PgPool>) -> Result<Json<Vec<Foods>>, Status> {
    let result = sqlx::query_as::<_, Foods>("SELECT food FROM foods")
        .fetch_all(db.inner())
        .await;

    match result {
        Ok(foods) => Ok(Json(foods)),
        Err(e) => {
            eprintln!("Erro ao buscar favoritos: {:?}", e);
            Err(Status::InternalServerError)
        }
    }
}


//LISTA O HISTORICO DE RECEITAS DO USER
#[get("/minhas_receitas")]
async fn minhas_receitas(
    cookies: &CookieJar<'_>,
    db: &State<PgPool>
) -> Result<Json<Vec<Receita>>, Status> {
    println!("\n[MINHAS_RECEITAS] Attempting to get 'user_email' cookie.");
    println!("[MINHAS_RECEITAS] All cookies received in this request:");
    if cookies.iter().count() == 0 {
        println!("[MINHAS_RECEITAS] No cookies received in this request.");
    }
    for cookie in cookies.iter() {
        println!("[MINHAS_RECEITAS]   - Name: '{}', Value: '{}', Path: {:?}, Domain: {:?}, Secure: {:?}, HttpOnly: {:?}, SameSite: {:?}",
                 cookie.name(), cookie.value(), cookie.path(), cookie.domain(), cookie.secure(), cookie.http_only(), cookie.same_site());
    }

    let email_from_cookie = match cookies.get("user_email") {
        Some(cookie) => {
            println!("[MINHAS_RECEITAS] Successfully retrieved 'user_email' cookie. Value: {}", cookie.value());
            cookie.value().to_string()
        }
        None => {
            println!("[MINHAS_RECEITAS] Failed to retrieve 'user_email' cookie.");
            println!("[MINHAS_RECEITAS]   Possible reasons: Browser didn't send it (check SameSite, Secure, Path, Domain attributes of the cookie in browser; ensure 'credentials: \"include\"' in frontend fetch), or it expired/was cleared.");
            return Err(Status::Unauthorized);
        }
    };


    println!("[MINHAS_RECEITAS] Email from cookie: {}", email_from_cookie);
    let receitas_result = sqlx::query_as!(
        Receita,
        r#"
        SELECT r.id, r.title, r.ingredients, r.instructions
        FROM recipes r
        JOIN (
            SELECT jsonb_array_elements_text(history)::int AS receita_id
            FROM users
            WHERE email = $1
        ) AS user_history ON r.id = user_history.receita_id
        "#,
        email_from_cookie
    )
        .fetch_all(db.inner())
        .await;

    match receitas_result {
        Ok(receitas) => {
            println!("[MINHAS_RECEITAS] Found {} receitas for user {}", receitas.len(), email_from_cookie);
            Ok(Json(receitas))
        },
        Err(e) => {
            println!("[MINHAS_RECEITAS] Error fetching receitas: {:?}", e);
            Err(Status::InternalServerError)
        },
    }
}





//ROOT
#[get("/")]
fn root() -> Redirect {
    Redirect::to(uri!(home))
}

//HOME
#[get("/home")]
fn home()-> String {
    format!("Home Page")
}

//SALVA NOVO USUARO NO DB
#[post("/cadastro", data = "<cadastro_form>")]
async fn cadastro(cadastro_form:Form<CadastroForm>, db:&State<PgPool>) -> Redirect{
    let form = cadastro_form.into_inner();

    let senha_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(_) => {
            return Redirect::to("https://127.0.0.1:5500/home.html");
        }
    };


    let result = sqlx::query(
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)"
    )
        .bind(&form.name)
        .bind(&form.email)
        .bind(senha_hash)
        .execute(db.inner())
        .await;

    match result {
        Ok(_) => Redirect::to("http://127.0.0.1:5500/login.html"),
        Err(e) => {
            eprintln!("Erro ao inserir usuário no banco: {:?}", e);
            Redirect::to("/erro_cadastro_db")
        }
    }
}

//EXECUTA O LOG IN DO USUARIO E GERA UM COOKIE QUE SERÁ USADO PARA IDENTIFICAÇÃO DO MESMO PELO APP
#[post("/login", format = "json", data = "<login_form>")]
async fn login(
    cookies: &CookieJar<'_>,
    login_form: Json<LoginForm>,
    db: &State<PgPool>,
) -> Result<Redirect, Status> {
    let form = login_form.into_inner();
    println!("[LOGIN] Attempting login for email: {}", form.email);

    let result = sqlx::query_as!(
        User,
        "SELECT id, name, role, email, password FROM users WHERE email = $1",
        form.email
    )
        .fetch_optional(db.inner())
        .await;

    if let Ok(Some(user)) = result {
        println!("[LOGIN] User found: {:?}", user.email);

        match verify_password(&form.password, &user.password) {
            Ok(true) => {
                println!("[LOGIN] Password verified for user: {:?}", user.email);

                if let Some(email_val) = user.email.clone() {
                    let mut user_cookie = Cookie::new("user_email", email_val.clone());
                    user_cookie.set_path("/");
                    user_cookie.set_http_only(true);

                    if cfg!(debug_assertions) {
                        println!("[LOGIN] Setting cookie with SameSite=Lax, Secure=false (dev mode for HTTP)");
                        user_cookie.set_same_site(SameSite::Lax);
                        user_cookie.set_secure(false);
                    } else {
                        println!("[LOGIN] Setting cookie with SameSite=None, Secure=true (prod mode for HTTPS)");
                        user_cookie.set_same_site(SameSite::None);
                        user_cookie.set_secure(true);
                    }

                    cookies.add(user_cookie.clone());

                    // Verificação de admin
                    let redirect_url = if user.role.unwrap() {
                        println!("[LOGIN] Usuário é administrador. Redirecionando para adm.html");
                        "http://127.0.0.1:5500/adm.html"
                    } else {
                        println!("[LOGIN] Usuário comum. Redirecionando para pag-receita.html");
                        "http://127.0.0.1:5500/pag-receita.html"
                    };

                    return Ok(Redirect::to(redirect_url));
                } else {
                    println!("[LOGIN] User found but email is None.");
                    Err(Status::InternalServerError)
                }
            }
            Ok(false) => {
                println!("[LOGIN] Password verification failed for user: {:?}", user.email);
                Err(Status::Unauthorized)
            }
            Err(_) => {
                println!("[LOGIN] Error verifying password for user: {:?}", user.email);
                Err(Status::InternalServerError)
            }
        }
    } else {
        println!("[LOGIN] User not found or DB error for email: {}", form.email);
        Err(Status::Unauthorized)
    }
}

#[get("/list_users")]
async fn list_users(cookie: &CookieJar<'_>, db: &State<PgPool>) -> Result<Json<Vec<User>>, Status> {
    println!("Cookies recebidos:");
    for c in cookie.iter() {
        println!("{} = {}", c.name(), c.value());
    }

    let email_from_cookie = match cookie.get("user_email") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            println!("Cookie user_email não encontrado");
            return Err(Status::Unauthorized);
        },
    };

    println!("Email do cookie: {}", email_from_cookie);
    println!("depois do unaltorized");
    let admin_check = sqlx::query!(
        "SELECT role FROM users WHERE email = $1",
        email_from_cookie
    )
        .fetch_one(db.inner())
        .await;

    match admin_check {
        Ok(user) if user.role == true => {
            let users = sqlx::query_as!(
                User,
                "SELECT id, name, role, email, password FROM users"
            )
                .fetch_all(db.inner())
                .await
                .map_err(|_| Status::InternalServerError)?;

            Ok(Json(users))
        },
        _ => Err(Status::Unauthorized),
    }
}

#[get("/todas_receitas")]
async fn todas_receitas(cookie: &CookieJar<'_>, db: &State<PgPool>) -> Result<Json<Vec<Receita>>, Status> {
    // Verifica se o cookie está presente
    let email_from_cookie = match cookie.get("user_email") {
        Some(cookie) => cookie.value().to_string(),
        None => return Err(Status::Unauthorized),
    };

    // Verifica se o usuário é administrador
    let admin_check = sqlx::query!(
        "SELECT role FROM users WHERE email = $1",
        email_from_cookie
    )
        .fetch_one(db.inner())
        .await;

    match admin_check {
        Ok(user) if user.role == true => {
            let receitas = sqlx::query_as!(
                Receita,
                "SELECT id, title, ingredients, instructions FROM recipes"
            )
                .fetch_all(db.inner())
                .await
                .map_err(|_| Status::InternalServerError)?;

            Ok(Json(receitas))
        },
        _ => Err(Status::Unauthorized),
    }
}


//FUNÇÃO PRINCIPAL PARA RODAR O PROJETO
#[rocket::main]
async fn main() {
    if dotenv().is_err() {
        println!("AVISO: Não foi possível carregar o arquivo .env.");
    }
    let secret_key_str = env::var("ROCKET_SECRET_KEY").unwrap_or_else(|_| {
        use rand::{distributions::Alphanumeric, Rng};
        let key: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        println!("⚠️  ROCKET_SECRET_KEY não definida no .env. Gerando chave aleatória:");
        println!("🔐 Chave gerada (ainda importante para Rocket, mas não para criptografia deste cookie): {}\n⚠️  ⚠️  Salve-a no .env para persistência!", key);
        key
    });

    println!("🔐 Chave secreta carregada (importante para Rocket): {}", secret_key_str);


    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL deve ser definida no .env");

    let db_pool = PgPool::connect(&database_url)
        .await
        .expect("Falha na conexão com o banco de dados");

    let figment = RocketConfig::figment()
        .merge(("secret_key", secret_key_str));

    println!("🔗 Conectando ao banco de dados em: {}", database_url);
    println!("✅ Conexão com o banco de dados estabelecida.");
    println!("🚀 Rocket figment configurado com a chave secreta.");

    if let Err(e) = rocket::custom(figment)
        .manage(db_pool)
        .attach(Cors)
        .mount("/", routes![
            root,
            home,
            login,
            cadastro,
            all_options,
            gerador,
            gerar,
            minhas_receitas,
            visualizar_curtidas,
            curtir_receita,
            todas_receitas,
            list_users,
            upload])
        .launch()
        .await
    {
        eprintln!("Falha ao iniciar o Rocket: {:?}", e);
    }
}