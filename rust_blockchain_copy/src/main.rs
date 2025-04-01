// main.rs
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Mutex;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    sender: String,
    recipient: String,
    amount: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Block {
    index: u32,
    timestamp: String,
    transactions: Vec<Transaction>,
    previous_hash: String,
    nonce: u64,
    hash: String,
}

impl Block {
    fn calculate_hash(&self) -> String {
        let tx_data: String = self.transactions.iter()
            .map(|tx| format!("{}{}{}", tx.sender, tx.recipient, tx.amount))
            .collect();

        let data = format!(
            "{}{}{}{}{}",
            self.index, self.timestamp, tx_data, self.previous_hash, self.nonce
        );

        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

fn proof_of_work(mut block: Block, difficulty: usize) -> Block {
    let prefix = "0".repeat(difficulty);
    while !block.calculate_hash().starts_with(&prefix) {
        block.nonce += 1;
    }
    block.hash = block.calculate_hash();
    block
}

#[derive(Debug)]
struct Blockchain {
    chain: Vec<Block>,
    current_transactions: Vec<Transaction>,
    difficulty: usize,
    nodes: HashSet<String>,
}

impl Blockchain {
    fn new() -> Self {
        let mut blockchain = Blockchain {
            chain: vec![],
            current_transactions: vec![],
            difficulty: 4,
            nodes: HashSet::new(),
        };
        blockchain.new_block("0".to_string());
        blockchain
    }

    fn new_transaction(&mut self, tx: Transaction) {
        self.current_transactions.push(tx);
    }

    fn new_block(&mut self, previous_hash: String) -> &Block {
        let index = self.chain.len() as u32;
        let timestamp = Utc::now().to_rfc3339();
        let transactions = self.current_transactions.clone();

        let block = Block {
            index,
            timestamp,
            transactions,
            previous_hash,
            nonce: 0,
            hash: String::new(),
        };

        let mined_block = proof_of_work(block, self.difficulty);
        self.chain.push(mined_block);
        self.current_transactions.clear();
        self.chain.last().unwrap()
    }

    fn last_block(&self) -> &Block {
        self.chain.last().unwrap()
    }

    fn register_node(&mut self, address: &str) {
        if let Ok(parsed) = Url::parse(address) {
            self.nodes.insert(parsed.origin().ascii_serialization());
        }
    }

    async fn resolve_conflicts(&mut self) -> bool {
        let client = reqwest::Client::new();
        let mut max_length = self.chain.len();
        let mut new_chain: Option<Vec<Block>> = None;

        for node in &self.nodes {
            let url = format!("{}/chain", node);
            if let Ok(res) = client.get(&url).send().await {
                if let Ok(chain_data) = res.json::<Vec<Block>>().await {
                    if chain_data.len() > max_length {
                        max_length = chain_data.len();
                        new_chain = Some(chain_data);
                    }
                }
            }
        }

        if let Some(chain) = new_chain {
            self.chain = chain;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Deserialize)]
struct TransactionPayload {
    sender: String,
    recipient: String,
    amount: u32,
}

#[derive(Debug, Deserialize)]
struct RegisterNodes {
    nodes: Vec<String>,
}

async fn add_transaction(
    blockchain: web::Data<Mutex<Blockchain>>,
    payload: web::Json<TransactionPayload>,
) -> impl Responder {
    let tx = Transaction {
        sender: payload.sender.clone(),
        recipient: payload.recipient.clone(),
        amount: payload.amount,
    };

    let mut chain = blockchain.lock().unwrap();
    chain.new_transaction(tx);

    HttpResponse::Ok().json("✅ 交易已添加")
}

async fn mine_block(blockchain: web::Data<Mutex<Blockchain>>) -> impl Responder {
    let mut chain = blockchain.lock().unwrap();
    let prev_hash = chain.last_block().hash.clone();
    let new_block = chain.new_block(prev_hash);
    HttpResponse::Ok().json(new_block)
}

async fn get_chain(blockchain: web::Data<Mutex<Blockchain>>) -> impl Responder {
    let chain = blockchain.lock().unwrap();
    HttpResponse::Ok().json(&chain.chain)
}

async fn register_nodes(
    blockchain: web::Data<Mutex<Blockchain>>,
    payload: web::Json<RegisterNodes>,
) -> impl Responder {
    let mut chain = blockchain.lock().unwrap();
    for node in &payload.nodes {
        chain.register_node(node);
    }
    HttpResponse::Ok().json("✅ 节点已注册")
}

async fn resolve_chain(blockchain: web::Data<Mutex<Blockchain>>) -> impl Responder {
    let blockchain = blockchain.clone();
    let replaced = {
        let blockchain = blockchain.clone();
        actix_web::rt::spawn(async move {
            let mut chain = blockchain.lock().unwrap();
            chain.resolve_conflicts().await
        })
        .await
        .unwrap_or(false)
    };

    if replaced {
        HttpResponse::Ok().json("✅ 本节点链已被替换为最长链")
    } else {
        HttpResponse::Ok().json("✅ 当前链是最长的，无需替换")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let blockchain = web::Data::new(Mutex::new(Blockchain::new()));
    println!("🌐 区块链节点启动中: http://localhost:8889");

    HttpServer::new(move || {
        App::new()
            .app_data(blockchain.clone())
            .route("/transactions/new", web::post().to(add_transaction))
            .route("/mine", web::get().to(mine_block))
            .route("/chain", web::get().to(get_chain))
            .route("/nodes/register", web::post().to(register_nodes))
            .route("/nodes/resolve", web::get().to(resolve_chain))
    })
    .bind("127.0.0.1:8889")?
    .run()
    .await
}
