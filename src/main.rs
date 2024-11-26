use std::env;
use chrono::prelude::*;
use chrono::TimeDelta;
use jsonwebtoken::{
    decode, encode, encode_acl, get_current_timestamp, new_local_pvd, Algorithm, DecodingKey,
    EncodingKey, Header, Validation, SignatureProvider, get_acl_pretoken_full_disclosure,
};
use acl::{SigningKey, UserParameters, VerifyingKey, SECRET_KEY_LENGTH};
use serde_json::ser::PrettyFormatter;
use tungstenite::{connect,Message,WebSocket,stream::MaybeTlsStream};
use std::net::TcpStream;
use url::Url;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Serialize,Deserialize};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::PreToken;
use std::fs::File;
use std::io::prelude::*;
use rand::Rng;

struct WebsocketProvider {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
}

#[derive(Serialize,Deserialize)]
struct UserMessage1 {
    commitment: String,
    aux: String,
}

#[derive(Serialize,Deserialize,Clone,Debug)]
struct UserMessage2 {
    challenge_bytes: String,
}

fn new_websocket_provider(url: String) -> WebsocketProvider {
    let (socket, _response) = connect(url).unwrap();
    
    WebsocketProvider { socket }
}

impl SignatureProvider for WebsocketProvider {
    type Error = String;

    fn prepare(&mut self, commitment: &RistrettoPoint, aux: String) -> Result<Vec<u8>, String> {
        let _ = self.socket.send(Message::Text(serde_json::to_string(&UserMessage1{
            commitment: URL_SAFE_NO_PAD.encode(commitment.compress().as_bytes()),
            aux: aux,
        }).expect("asdf")));

        let Message::Binary(smsg1) = self.socket.read().expect("asdf") else {todo!()};

        Ok(smsg1)
    }

    fn compute_presignature(&mut self, challenge_bytes: &[u8]) -> Result<Vec<u8>,String> {
        let _ = self.socket.send(Message::Text(serde_json::to_string(&UserMessage2{
            challenge_bytes: URL_SAFE_NO_PAD.encode(challenge_bytes),
        }).expect("asdf")));

        let Message::Binary(smsg2) = self.socket.read().expect("asdf") else {todo!()};

        Ok(smsg2)
    }
}

struct TokenData {
    email: String,
    exp: u64,
    tech_subscriber: bool,
    sports_subscriber: bool,
    cooking_subscriber: bool,
}

#[derive(Debug,Clone,Hash)]
enum TokenValue {
    Email(String),
    Exp(u64),
    TechSubscriber(bool),
    SportsSubscriber(bool),
    CookingSubscriber(bool),
}

impl ToString for TokenValue {
    fn to_string(&self) -> String {
        match self {
            Self::Email(str) => str.clone(),
            Self::Exp(exp) => exp.to_string(),
            Self::TechSubscriber(has) => has.to_string(),
            Self::SportsSubscriber(has) => has.to_string(),
            Self::CookingSubscriber(has) => has.to_string(),
        }
    }
}

impl TokenData {
    fn to_claims(&self) -> Vec<(String,TokenValue)> {
        Vec::from([
            (String::from("email"), TokenValue::Email(self.email.clone())),
            (String::from("exp"), TokenValue::Exp(self.exp)),
            (String::from("tech_subscriber"), TokenValue::TechSubscriber(self.tech_subscriber)),
            (String::from("sports_subscriber"), TokenValue::SportsSubscriber(self.sports_subscriber)),
            (String::from("cooking_subscriber"), TokenValue::CookingSubscriber(self.cooking_subscriber)),
        ])
    }
}

fn get_pretoken() -> PreToken {
    let now = Utc::now();
    let exp =
        Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0).latest().expect("fine")
            + TimeDelta::days(1);

    let tkd = TokenData{
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

    // let mut localPVD = new_local_pvd(signing_key);
    let mut remotePVD = new_websocket_provider("ws://localhost:8000/grant".to_string());

    let user_params = UserParameters { key: VerifyingKey::from(&signing_key) };

    let pretoken = get_acl_pretoken_full_disclosure(&tkd.to_claims(), &mut remotePVD, &user_params).expect("ok");

    // let token = encode_acl(
    //     &Header::new(Algorithm::AclFullPartialR255),
    //     &tkd.to_claims(),
    //     &Vec::from(["exp".to_string(),"tech_subscriber".to_string()]),
    //     &pretoken,
    // )
    // .unwrap();

    pretoken
}

fn get_tokens() {
    for i in 1..100 {
        let tk = get_pretoken();
        let mut file = File::create(format!("tokens/{}.json", URL_SAFE_NO_PAD.encode(tk.randomness.to_bytes()))).expect("asdf");
        file.write_all(serde_json::to_string(&tk).expect("asdf").as_bytes());
    }
}

fn read_tech() {
    let paths = fs::read_dir("./tokens").unwrap();
    let idx = rand::thread_rng().gen_range(0..paths.len());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args[1].clone();
    match command.as_str() {
        "get_tokens" => {
            get_tokens()
        },
        "read_tech" => {
            read_tech()
        }
        _ => todo!(),
    }
}