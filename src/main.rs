use acl::{SigningKey, UserParameters, VerifyingKey, SECRET_KEY_LENGTH};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::prelude::*;
use chrono::TimeDelta;
use curve25519_dalek::ristretto::RistrettoPoint;
use jsonwebtoken::PreToken;
use jsonwebtoken::{
    decode, encode, encode_acl, get_acl_pretoken_full_disclosure, get_current_timestamp, Algorithm,
    DecodingKey, EncodingKey, Header, SignatureProvider, Validation,
};
use rand::Rng;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::ser::PrettyFormatter;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::fs::{DirEntry, File};
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::PathBuf;
use tungstenite::{connect, stream::MaybeTlsStream, Message, WebSocket};
use url::Url;
use std::time::Instant;

struct WebsocketProvider {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
}

#[derive(Serialize, Deserialize)]
struct UserMessage1 {
    commitment: String,
    aux: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserMessage2 {
    challenge_bytes: String,
}

fn new_websocket_provider(url: String) -> WebsocketProvider {
    let (socket, _response) = connect(url).unwrap();

    WebsocketProvider { socket }
}

impl SignatureProvider for WebsocketProvider {
    type Error = String;

    fn prepare(
        &mut self,
        commitment: &RistrettoPoint,
        aux: String,
    ) -> Result<Vec<u8>, Self::Error> {
        let _ = self.socket.send(Message::Text(
            serde_json::to_string(&UserMessage1 {
                commitment: URL_SAFE_NO_PAD.encode(commitment.compress().as_bytes()),
                aux: aux,
            })
            .expect("asdf"),
        ));

        let Message::Binary(smsg1) = self.socket.read().expect("asdf") else {
            todo!()
        };

        Ok(smsg1)
    }

    fn compute_presignature(&mut self, challenge_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let _ = self.socket.send(Message::Text(
            serde_json::to_string(&UserMessage2 {
                challenge_bytes: URL_SAFE_NO_PAD.encode(challenge_bytes),
            })
            .expect("asdf"),
        ));

        let Message::Binary(smsg2) = self.socket.read().expect("asdf") else {
            todo!()
        };

        Ok(smsg2)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct TokenData {
    email: String,
    exp: u64,
    tech_subscriber: bool,
    sports_subscriber: bool,
    cooking_subscriber: bool,
}

impl TokenData {
    fn to_claims(&self) -> Value {
        json!({
            "cooking_subscriber": self.cooking_subscriber,
            "email": self.email,
            "exp": self.exp as u32,
            "sports_subscriber": self.sports_subscriber,
            "tech_subscriber": self.tech_subscriber,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct StoredPreToken {
    data: TokenData,
    pretoken: PreToken,
}

fn get_pretoken(tkd: &TokenData, params: &UserParameters) -> PreToken {
    // let mut localPVD = new_local_pvd(signing_key);
    let mut remotePVD = new_websocket_provider("ws://140.211.166.98:8000/grant".to_string());

    let pretoken = get_acl_pretoken_full_disclosure(&tkd.to_claims(), &mut remotePVD, params)
        .expect("ok");

    pretoken
}

fn get_tokens() {
    let now = Utc::now();
    let exp = Utc
        .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
        .latest()
        .expect("fine")
        + TimeDelta::days(1);

    let tkd = TokenData {
        email: String::from("fharding1@protonmail.com"),
        exp: exp.timestamp() as u64,
        tech_subscriber: true,
        sports_subscriber: false,
        cooking_subscriber: true,
    };

    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

    let user_params = UserParameters {
        key: VerifyingKey::from(&signing_key),
    };

    let start = Instant::now();
    for i in 0..1000 {
        let tk = get_pretoken(&tkd, &user_params);
        let mut file = File::create(format!(
            "tokens/{}.json",
            URL_SAFE_NO_PAD.encode(tk.randomness.to_bytes())
        ))
        .expect("asdf");
        let _ = file.write_all(
            serde_json::to_string(&StoredPreToken {
                data: tkd.clone(),
                pretoken: tk,
            })
            .expect("asdf")
            .as_bytes(),
        );
    }
    println!("that took {:?}", start.elapsed());
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Article {
    headline: String,
    author: String,
    story: String,
    date: String,
}

fn read_tech() {
    let paths: Vec<PathBuf> = fs::read_dir("./tokens")
        .expect("asdf")
        .map(|result| result.expect("ok").path())
        .collect();

    let idx = rand::thread_rng().gen_range(0..paths.len());
    let stored_pretoken_str = fs::read_to_string(paths[idx].as_path()).expect("should open");
    let stored_pretoken: StoredPreToken =
        serde_json::from_str(&stored_pretoken_str).expect("should be ok");

    println!("hgello world");

    let token = encode_acl(
        &Header::new(Algorithm::AclFullPartialR255),
        &stored_pretoken.data.to_claims(),
        &Vec::from(["exp".to_string(), "tech_subscriber".to_string()]),
        &stored_pretoken.pretoken,
    )
    .unwrap();

    println!("{}", token);

    let client = Client::new();
    let resp = client
        .get("http://localhost:8000/news")
        .bearer_auth(token.clone())
        .send()
        .expect("fine");

    let article: Article = serde_json::from_str(&resp.text().expect("ok")).expect("ok");

    println!("{:?}", article);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args[1].clone();
    match command.as_str() {
        "get_tokens" => get_tokens(),
        "read_tech" => read_tech(),
        _ => todo!(),
    }
}
