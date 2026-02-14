use anyhow::{anyhow, Context, Result};
use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use rand::rngs::OsRng;

// --- 1. ระบบแบ่งไฟล์ (Custom Rolling Hash) ---
const MIN_CHUNK: usize = 16 * 1024;    // 16KB
const MAX_CHUNK: usize = 256 * 1024;   // 256KB

fn get_chunks(data: &[u8]) -> Vec<(usize, usize)> {
    let mut chunks = Vec::new();
    let mut last_cut = 0;
    
    if data.len() <= MAX_CHUNK {
        chunks.push((0, data.len()));
        return chunks;
    }

    let mut i = MIN_CHUNK;
    while i < data.len() {
        let chunk_size = i - last_cut;
        let hash_pattern = 0x1FFF; 
        
        // ใส่วงเล็บป้องกันการเข้าใจผิดเรื่อง Generics เรียบร้อย
        if (i < data.len() && (data[i] as u32 | ((data[i-1] as u32) << 8)) & hash_pattern == 0) 
           || chunk_size >= MAX_CHUNK {
            if chunk_size >= MIN_CHUNK {
                chunks.push((last_cut, chunk_size));
                last_cut = i;
                i += MIN_CHUNK;
                continue;
            }
        }
        i += 1;
    }
    
    if last_cut < data.len() {
        chunks.push((last_cut, data.len() - last_cut));
    }
    chunks
}

// --- 2. โครงสร้างข้อมูล ---
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ChunkMeta {
    hash: [u8; 32],
    size: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct SecureFileIndex {
    version: u32,
    file_name: String,
    file_size: u64,
    chunks: Vec<ChunkMeta>,
    signature: Vec<u8>,
}

// --- 3. ระบบรักษาความปลอดภัย ---
fn generate_keys() -> Result<()> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    fs::write("private.key", signing_key.to_bytes())?;
    fs::write("public.key", verifying_key.to_bytes())?;
    println!("✅ สร้างกุญแจสำเร็จ! (private.key และ public.key)");
    Ok(())
}

fn load_signing_key(path: &str) -> Result<SigningKey> {
    let bytes = fs::read(path).context("ไม่พบ Private Key")?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("ขนาด Key ผิด"))?;
    Ok(SigningKey::from_bytes(&array))
}

fn load_verifying_key(path: &str) -> Result<VerifyingKey> {
    let bytes = fs::read(path).context("ไม่พบ Public Key")?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("ขนาด Key ผิด"))?;
    Ok(VerifyingKey::from_bytes(&array)?)
}

// --- 4. การทำดัชนี (Indexing) ---
fn build_index(file_path: &str, priv_key_path: &str) -> Result<()> {
    let mut file = fs::File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let priv_key = load_signing_key(priv_key_path)?;
    let chunk_offsets = get_chunks(&buffer);
    
    let mut chunks = Vec::new();
    for (offset, size) in chunk_offsets {
        let chunk_data = &buffer[offset..offset + size];
        let hash = blake3::hash(chunk_data).into();
        chunks.push(ChunkMeta { hash, size: size as u32 });
    }

    let mut index = SecureFileIndex {
        version: 3,
        file_name: Path::new(file_path).file_name().unwrap().to_str().unwrap().to_string(),
        file_size: buffer.len() as u64,
        chunks,
        signature: vec![],
    };

    let serialized = serde_json::to_vec(&index)?;
    index.signature = priv_key.sign(&serialized).to_vec();
    fs::write(format!("{}.idx", file_path), serde_json::to_string_pretty(&index)?)?;

    println!("✅ สร้างดัชนีสำเร็จ: {}.idx", file_path);
    Ok(())
}

// --- 5. การดาวน์โหลด ---
async fn secure_download(url: &str, index_path: &str, pub_key_path: &str, output_dir: &str) -> Result<()> {
    let index_data = fs::read(index_path)?;
    let mut index: SecureFileIndex = serde_json::from_slice(&index_data)?;
    let pub_key = load_verifying_key(pub_key_path)?;

    let sig_bytes = index.signature.clone();
    index.signature = vec![]; 
    let serialized = serde_json::to_vec(&index)?;
    let sig = Signature::from_slice(&sig_bytes)?;

    pub_key.verify(&serialized, &sig).context("⚠️ ลายเซ็นไม่ถูกต้อง!")?;
    
    let output_path = PathBuf::from(output_dir).join(&index.file_name);
    if let Some(p) = output_path.parent() { fs::create_dir_all(p)?; }
    
    let mut file = OpenOptions::new().create(true).write(true).open(&output_path).await?;
    let client = reqwest::Client::new();
    let semaphore = std::sync::Arc::new(Semaphore::new(3)); // ลดเหลือ 3 ท่อเพื่อ RAM 4GB ของพี่

    println!("🔐 เริ่มดาวน์โหลด...");
    let mut offset = 0u64;
    for chunk in index.chunks {
        let permit = semaphore.clone().acquire_owned().await?;
        let chunk_url = url.to_string();
        let chunk_hash = chunk.hash;
        let start = offset;
        let end = offset + chunk.size as u64 - 1;
        offset += chunk.size as u64;

        let resp = client.get(&chunk_url).header("Range", format!("bytes={}-{}", start, end)).send().await?.bytes().await?;
        if blake3::hash(&resp).as_bytes() != &chunk_hash { 
            return Err(anyhow!("Hash mismatch!")); 
        }
        file.write_all(&resp).await?;
        drop(permit);
    }
    println!("🎯 สำเร็จ!");
    Ok(())
}

// --- 6. Main Function ---
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Hyper Pipe Pro - G580 Edition");
        println!("Usage: keygen | index <file> <key> | download <url> <idx> <key> <out>");
        return Ok(())
    }
    match args[1].as_str() {
        "keygen" => generate_keys()?,
        "index" => {
            if args.len() < 4 { return Err(anyhow!("ระบุไฟล์และ key ด้วยพี่")); }
            build_index(&args[2], &args[3])?
        },
        "download" => {
            if args.len() < 6 { return Err(anyhow!("ข้อมูลไม่ครบพี่")); }
            secure_download(&args[2], &args[3], &args[4], &args[5]).await?
        },
        _ => println!("❌ คำสั่งอะไรเนี่ยพี่?"),
    }
    Ok(())
}
