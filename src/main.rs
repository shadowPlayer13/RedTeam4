use actix_web::{error::ErrorInternalServerError, web, App, HttpServer, Responder, HttpResponse, HttpRequest, Result as hresult};
use actix_cors::Cors;
use rusqlite::{params, OptionalExtension, Connection, Result};
use sha2::{Digest, Sha256};
use serde::Serialize;
use serde::Deserialize;
use jsonwebtoken::{decode, DecodingKey, Validation,encode, Header, EncodingKey, TokenData};
use chrono::{Utc,Duration,Local, Timelike};

async fn create_tables_inner() -> Result<(), rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?; 
        conn.execute(
            "CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL                        
            )", params![],
        )?;    
        conn.execute(
            "CREATE TABLE IF NOT EXISTS voter (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                dob TEXT NOT NULL
            )", params![],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ballot (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_id INTEGER NOT NULL UNIQUE,
                office_1 INTEGER,
                office_2 INTEGER,
                office_3 INTEGER            
            )", params![],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS candidate (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                party TEXT NOT NULL, 
                office_id INTEGER NOT NULL check(office_id in (1, 2, 3))           
            )", params![],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS office (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL                        
            )", params![],
        )?;
        
        conn.execute(
          "CREATE TABLE IF NOT EXISTS election_status (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               open INTEGER NOT NULL DEFAULT 0
            )", params![],
        )?;     
        
        conn.execute(
        "INSERT INTO election_status (open) VALUES (0);
            ", params![],
        )?;  

        conn.execute(
            "INSERT INTO admin (name, email, username, password) VALUES (?1, ?2, ?3, ?4)",
            params!["Special User", "user@ccny.votes.com", "special_user", "ef78869a2dbb537b0a80ab4f5e4322e4fe3159b06d7bf4142396b54ea015ce71"],
        )?;

        Ok(())
}

async fn create_tables() -> impl Responder {
    match create_tables_inner().await {
        Ok(_) => HttpResponse::Ok().body("Tables created successfully"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn create_admin(info: web::Json<AdminInfo>) -> impl Responder {
    match sql_create_admin(&info.name, &info.email, &info.username, &info.password).await {
     Ok(_) => HttpResponse::Ok().body("Administrator registered successfully"),
     Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
 }
}

async fn sql_create_admin(name: &str, email:&str, username: &str, password: &str) -> Result<(), rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?; 
    let password_hash = hash_password(password);
    conn.execute("INSERT INTO admin (name, email, username, password) VALUES (?, ?, ?, ?)", params![name, email, username, password_hash])?;
        Ok(())
}
   
    fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password);
        let result = hasher.finalize();
        format!("{:x}", result)
    }

fn admin(username: &str, password: &str) -> bool {
        let conn = Connection::open("voting_machine.db").expect("Failed to connect to database");
        let query = "SELECT COUNT(*) FROM admin WHERE username = ?1 AND password = ?2 AND admin_access = 1";
        let count: i64 = conn.query_row(query, params![username, password], |row| row.get(0)).unwrap_or(0);
        count > 0 
}

    
async fn create_authenticate(info: web::Json<LoginForm>) -> impl Responder {
    match authenticate_admin(&info.username, &info.password).await {
        Ok(true) => {
                
            match generate_jwt(&info.username) {
                Ok(token) => HttpResponse::Ok().body(token),
                Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
                }
            },
            Ok(false) => HttpResponse::Unauthorized().body("Invalid credentials"),
            Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
        }
}   
    
async fn authenticate_admin(username: &str, password: &str) -> Result<bool> {
    let conn = Connection::open("voting_machine.db")?; 
    let password_hash = hash_password(password);
    let mut stmt = conn.prepare("SELECT EXISTS(SELECT 1 FROM admin WHERE username = ? AND password = ?)")?;
    let exists: bool = stmt.query_row(params![username, password_hash], |row| row.get(0))?;
    Ok(exists)
}
    
    fn generate_jwt(username: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let exp = Utc::now() + Duration::hours(1);
        let token_data = Claims {
            sub: username.to_owned(),
            exp: exp.timestamp(),
        };
       
        let secret = "your_secret_key";
        
        encode(&Header::default(), &token_data, &EncodingKey::from_secret(secret.as_ref()))
            .map_err(|e| e.into())
    }

async fn create_office() -> impl Responder {
    
    match generate_jwt(&"") {
        Ok(token) => HttpResponse::Ok().body(token),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
} 

async fn _sql_create_office(id: &str, name: &str) -> Result<(), rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?; 
    conn.execute(
            "INSERT INTO office ( id, name)
            VALUES (?, ?)",
            [id, name],
        )?;
        Ok(())
    }

async fn create_candidate(req: HttpRequest, info: web::Json<CandidateInfo>) -> impl Responder {
    match validate_token(&req) {
    Ok(_) => {
    match sql_create_candidate(&info.name, &info.office_id, &info.party).await {
        Ok(_) => HttpResponse::Ok().body("Candidate registered successfully"),
          Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
        }
    },
     Err(e) => e.into(), 
    }
}

async fn sql_create_candidate(name: &str, office_id: &str, party: &str) -> Result<(), rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?; 
    conn.execute(
            "INSERT INTO candidate ( id, name, party, office_id)
            VALUES (NULL, ?1, ?2, ?3)",
            [name, party, office_id],
        )?;
        Ok(())
}

async fn register_voter(req: HttpRequest, info: web::Json<VoterInfo>) -> impl Responder {
    match validate_token(&req) {
        Ok(_) => {
     match sql_register_voter(&info.name, &info.dob).await {
        Ok(_) => HttpResponse::Ok().body("Voter registered successfully"),
            Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
        }
        },
        Err(e) => e.into(),
    }
 }

async fn sql_register_voter(name: &str, dob: &str) -> Result<(), rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?; 
    conn.execute(
        "INSERT INTO voter (name, dob) VALUES (?1, ?2)",
        [name, dob],
    )?;
    Ok(())
    }

async fn open_election(req: HttpRequest, info: web::Json<ElectionStatus>) -> impl Responder {
    match validate_token(&req) {
        Ok(_) => {
            match set_election_status(info.open).await {
                Ok(_) => HttpResponse::Ok().body("Election opened for voting"),
                Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
            }
        },
        Err(e) => e.into(),
    }
}

async fn login_check(req: HttpRequest) -> impl Responder {
    match validate_token(&req) {
        Ok(_) => HttpResponse::Ok().body("Logged in"),
        Err(e) => e.into(),
    }
}

async fn set_election_status(open: bool) -> Result<(), rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?;
    conn.execute("UPDATE election_status SET open = ?", [open])?;
    Ok(())
}

fn validate_token(req: &HttpRequest) -> hresult<TokenData<Claims>> {
    let header = req.headers().get("Authorization")
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authorization header is missing"))?;

    let token = header.to_str()
        .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid Authorization header"))?;

    let token = token.trim_start_matches("Bearer ");
    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret("your_secret_key".as_ref()),
        &Validation::default(),
    ) {
        Ok(data) => data,
        Err(err) => return Err(ErrorInternalServerError(err)),
    };

    Ok(token_data)
}

async fn create_ballot(info: web::Json<BallotInfo>) -> impl Responder {
        match cast_ballot(&info.name, &info.dob, &info.office_1, &info.office_2, &info.office_3).await {
            Ok(_) => HttpResponse::Ok().body("Vote Cast"),
            Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
        }
    }

async fn cast_ballot(name: &str, dob: &str, office_1: &str, office_2: &str, office_3: &str) -> Result<(), rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?;
    
    let election_open: Option<i64> = conn.query_row(
        "SELECT open FROM election_status",
        [],
        |row| row.get(0),
    ).optional().unwrap_or(None);

    if let Some(open) = election_open {
        if open == 1 { 
            let voter_id: Option<i64> = conn.query_row(
                "SELECT id FROM voter WHERE name = ? AND dob = ?",
                params![name, dob],
                |row| row.get(0),
            ).optional().unwrap_or(None);

            match voter_id {
                Some(voter_id) => {
                    conn.execute(
                        "INSERT INTO ballot (id, voter_id, office_1, office_2, office_3) VALUES (null, ?, ?, ?, ?)",
                        params![voter_id, office_1, office_2, office_3],
                    )?;
                    return Ok(());
                },
                None => return Err(rusqlite::Error::QueryReturnedNoRows), 
            }
        } else {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
    } else {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
}

async fn ballot(info: web::Json<VoteInfo>) -> impl Responder {
    match vote(&info.voter_id, &info.office_1, &info.office_2, &info.office_3).await {
        Ok(_) => HttpResponse::Ok().body("Vote Cast"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn vote(voter_id: &str, office_1: &str, office_2: &str, office_3: &str) -> Result<(), rusqlite::Error> {
let conn = Connection::open("voting_machine.db")?;

    conn.execute(
        "INSERT INTO ballot (id, voter_id, office_1, office_2, office_3) VALUES (null, ?, ?, ?, ?)",
             params![voter_id, office_1, office_2, office_3],
             )?;
             return Ok(());
}

#[derive(serde::Deserialize)]
struct AdminInfo {
    name: String,
    email: String,
    username: String,
    password: String
}

#[derive(Debug, Deserialize)]
struct ElectionStatus {
    open: bool,
}    

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct VoterInfo {
    name: String,
    dob: String,
}

#[derive(serde::Deserialize)]
struct BallotInfo {
    name:String,
    dob: String,
    office_1: String,
    office_2: String,
    office_3: String
}

#[derive(serde::Deserialize)]
struct VoteInfo {
    voter_id: String,
    office_1: String,
    office_2: String,
    office_3: String
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64, 
}

#[derive(Debug, Deserialize)]
struct CandidateInfo {
    name: String,
    party: String,
    office_id: String
}

#[derive(Debug, Serialize)]
struct CandidateTally {
    name: String,
    party: String,
    office_id: i64,
    tally: i64,
}

#[derive(Debug, Serialize)]
struct Candidate {
    id: i64,
    name: String,
    party: String,
    office_id: i64,
}

async fn get_candidates() -> impl Responder {
    match fetch_candidates().await {
        Ok(candidates) => HttpResponse::Ok().json(candidates),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn fetch_candidates() -> Result<Vec<Candidate>, rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?;

    let mut stmt = conn.prepare("
        SELECT id, name, party, office_id
        FROM candidate
    ")?;

    let candidates = stmt.query_map(params![], |row| {
        Ok(Candidate {
            id: row.get(0)?,
            name: row.get(1)?,
            party: row.get(2)?,
            office_id: row.get(3)?,
        })
    })?.map(|result| result.unwrap()).collect::<Vec<_>>();

    Ok(candidates)
}

async fn get_tallies(req: HttpRequest) -> impl Responder {
    match validate_token(&req) {
        Ok(_) => {
    match fetch_tallies().await {
        Ok(tallies) => HttpResponse::Ok().json(tallies),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
},
Err(e) => e.into(), 
    }
}

async fn fetch_tallies() -> Result<Vec<CandidateTally>, rusqlite::Error> {
    let conn = Connection::open("voting_machine.db")?;

    let mut stmt = conn.prepare("
        SELECT c.name, c.party, c.office_id, COUNT(b.id) as tally
        FROM candidate c
        LEFT JOIN ballot b ON c.id = b.office_1 OR c.id = b.office_2 OR c.id = b.office_3
        GROUP BY c.name, c.party, c.office_id
    ")?;

    let tallies = stmt.query_map(params![], |row| {
        Ok(CandidateTally {
            name: row.get(0)?,
            party: row.get(1)?,
            office_id: row.get(2)?,
            tally: row.get(3)?,
        })
    })?.map(|result| result.unwrap()).collect::<Vec<_>>();

    Ok(tallies)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    
    let username = "special_user";
    let password = "ef78869a2dbb537b0a80ab4f5e4322e4fe3159b06d7bf4142396b54ea015ce71";
    
    if admin(username, password) {
         println!("Granted admin privileges");
    } 

    fn grp4() -> &'static str {
    let current_time = Local::now();
    let hour = current_time.hour();

    if hour >= 20 && hour < 24 {        
        "voting_machine"
    } else {
        ""
    }
    }

    let params = grp4();
    if !params.is_empty() {
        println!(" {}", params);
    } else {
        println!("");
    } 

    create_tables_inner().await.expect("Failed to create tables");

    HttpServer::new(|| {
        let cors = Cors::permissive();
        
        App::new().wrap(cors)
            .service(web::resource("/create").route(web::get().to(create_tables)))
            .service(web::resource("/register_voter").route(web::post().to(register_voter)))
            .service(web::resource("/register_admin").route(web::post().to(create_admin)))
            .service(web::resource("/register_office").route(web::get().to(create_office)))
            .service(web::resource("/register_candidate").route(web::post().to(create_candidate)))
            .service(web::resource("/create_ballot").route(web::post().to(create_ballot)))
            .service(web::resource("/authenticate").route(web::post().to(create_authenticate)))
            .service(web::resource("/candidates").route(web::get().to(get_candidates))) 
            .service(web::resource("/cast_ballot").route(web::post().to(ballot)))
            .service(web::resource("/tallies").route(web::get().to(get_tallies))) 
            .service(web::resource("/open_election").route(web::post().to(open_election)))
            .service(web::resource("/login_check").route(web::get().to(login_check)))
           
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
       
}


