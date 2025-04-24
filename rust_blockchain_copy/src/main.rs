// main.rs
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Mutex;
use url::Url;
use reqwest::Client;
use futures::executor;

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
    self_address: String,
}

impl Blockchain {
    fn new(self_address: String) -> Self {
        let mut blockchain = Blockchain {
            chain: vec![],
            current_transactions: vec![],
            difficulty: 4,
            nodes: HashSet::new(),
            self_address,
        };
        blockchain.new_block("0".to_string());
        blockchain
    }

    fn new_transaction(&mut self, tx: Transaction) {
        println!("📨 新交易：{} → {}: {}", tx.sender, tx.recipient, tx.amount);
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
        println!("⛏️ 区块已挖出：index={}, hash={}", mined_block.index, mined_block.hash);
        self.chain.push(mined_block);
        self.current_transactions.clear();
        self.chain.last().unwrap()
    }

    fn last_block(&self) -> &Block {
        self.chain.last().unwrap()
    }

    fn register_node(&mut self, address: &str) -> bool {
        if let Ok(parsed) = Url::parse(address) {
            return self.nodes.insert(parsed.origin().ascii_serialization());
        }
        false
    }

    async fn resolve_conflicts(&mut self) -> bool {
        let client = reqwest::Client::new();
        let mut max_length = self.chain.len();
        let mut new_chain: Option<Vec<Block>> = None;

        for node in &self.nodes {
            let url = format!("{}/chain", node);
            println!("🔄 正在尝试从 {} 获取链", url);
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
            println!("✅ 替换本地链为长度为 {} 的远程链", max_length);
            self.chain = chain;
            true
        } else {
            println!("🟢 当前链已是最长");
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

#[derive(Debug, Deserialize, Serialize)]
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
    let new_block = chain.new_block(prev_hash).clone();
    let peers = chain.nodes.clone();
    drop(chain);

    let client = reqwest::Client::new();
    for node in peers {
        let url = format!("{}/blocks/receive", node);
        let block_to_send = new_block.clone();
        match client.post(&url).json(&block_to_send).send().await {
            Ok(res) => println!("✅ 已广播区块至 {node}，响应状态: {}", res.status()),
            Err(e) => eprintln!("❌ 广播至 {node} 失败: {}", e),
        }
    }

    HttpResponse::Ok().json(new_block)
}

async fn receive_block(
    blockchain: web::Data<Mutex<Blockchain>>,
    block: web::Json<Block>,
) -> impl Responder {
    let mut chain = blockchain.lock().unwrap();
    let last_block = chain.last_block().clone();

    if block.previous_hash == last_block.hash && block.index == last_block.index + 1 {
        if block.hash == block.calculate_hash() {
            println!("📥 接收到新区块并成功加入链中：index = {}", block.index);
            chain.chain.push(block.into_inner());
            return HttpResponse::Ok().json("✅ 已添加新区块");
        }
    }

    let blockchain = blockchain.clone();
    tokio::task::spawn_blocking(move || {
        let mut chain = blockchain.lock().unwrap();
        let _ = executor::block_on(chain.resolve_conflicts());
    });

    HttpResponse::Accepted().json("⚠️ 区块未接上，已触发链同步")
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
        println!("🔗 注册节点: {}", node);
        if let Ok(parsed) = Url::parse(node) {
            let origin = parsed.origin().ascii_serialization();
            let is_new = chain.nodes.insert(origin.clone());

            if is_new {
                let reverse_payload = RegisterNodes {
                    nodes: vec![chain.self_address.clone()],
                };
                let url = format!("{}/nodes/register", node);

                tokio::spawn(async move {
                    let client = Client::new();
                    let res = client
                        .post(&url)
                        .json(&reverse_payload)
                        .timeout(std::time::Duration::from_secs(3))
                        .send()
                        .await;

                    match res {
                        Ok(resp) => println!("↩️ 反向注册响应: {}", resp.status()),
                        Err(e) => eprintln!("❌ 反向注册失败: {}", e),
                    }
                });
            }
        }
    }

    println!("📌 当前注册节点: {:?}", chain.nodes);
    HttpResponse::Ok().json("✅ 节点已注册（包含双向注册）")
}

async fn resolve_chain(blockchain: web::Data<Mutex<Blockchain>>) -> impl Responder {
    let blockchain = blockchain.clone();
    let replaced = tokio::task::spawn_blocking(move || {
        let mut chain = blockchain.lock().unwrap();
        executor::block_on(chain.resolve_conflicts())
    })
    .await
    .unwrap_or(false);

    if replaced {
        HttpResponse::Ok().json("✅ 本节点链已被替换为最长链")
    } else {
        HttpResponse::Ok().json("✅ 当前链是最长的，无需替换")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let self_address = std::env::var("SELF_ADDRESS").unwrap_or_else(|_| "http://localhost:8888".to_string());
    let bind_addr = self_address.strip_prefix("http://").unwrap_or("127.0.0.1:8888");

    let blockchain = web::Data::new(Mutex::new(Blockchain::new(self_address.clone())));
    println!("🌐 区块链节点启动中: {}", self_address);

    HttpServer::new(move || {
        App::new()
            .app_data(blockchain.clone())
            .route("/transactions/new", web::post().to(add_transaction))
            .route("/mine", web::get().to(mine_block))
            .route("/chain", web::get().to(get_chain))
            .route("/nodes/register", web::post().to(register_nodes))
            .route("/nodes/resolve", web::get().to(resolve_chain))
            .route("/blocks/receive", web::post().to(receive_block))
    })
    .bind(bind_addr)?
    .run()
    .await
}
