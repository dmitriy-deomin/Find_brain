use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io;
use tokio::task;
use std::io::{BufRead, BufReader, stdout, Write};
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};
use base58::{FromBase58, ToBase58};
use sha2::{Digest, Sha256};
use sv::util::{hash160};
use crate::color::{blue, cyan, green, magenta};

extern crate itertools;

use itertools::Itertools;
use rustils::parse::boolean::string_to_bool;

mod ice_library;
mod color;
mod data;

const BACKSPACE: char = 8u8 as char;
const FILE_CONFIG: &str = "confBrain.txt";

#[tokio::main]
async fn main() {
    let version: &str = env!("CARGO_PKG_VERSION");
    println!("{}", blue("==================="));
    println!("{}{}", blue("FIND BRAIN v:"), magenta(version));
    println!("{}", blue("==================="));


    //Чтение настроек, и если их нет создадим
    //-----------------------------------------------------------------
    let conf = match lines_from_file(&FILE_CONFIG) {
        Ok(text) => { text }
        Err(_) => {
            add_v_file(&FILE_CONFIG, data::get_conf_text().to_string());
            lines_from_file(&FILE_CONFIG).unwrap()
        }
    };

    let dlinn_a_pasvord: usize = first_word(&conf[0].to_string()).to_string().parse::<usize>().unwrap();
    let alvabet = first_word(&conf[1].to_string()).to_string();
    let len_uvelichenie = string_to_bool(first_word(&conf[2].to_string()).to_string());
    let probel = string_to_bool(first_word(&conf[3].to_string()).to_string());
    //---------------------------------------------------------------------

    //читаем файл с адресами и конвертируем их в h160
    let file_content = match lines_from_file("address.txt") {
        Ok(file) => { file }
        Err(_) => {
            let dockerfile = include_str!("address.txt");
            add_v_file("address.txt", dockerfile.to_string());
            lines_from_file("address.txt").expect("kakoyto_pizdec")
        }
    };

    //хешируем
    let mut database = HashSet::new();
    for address in file_content.iter() {
        let binding = address.from_base58().unwrap();
        let a = &binding.as_slice()[1..=20];
        database.insert(a.to_vec());
    }

    println!("{}{:?}", blue("ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));
    println!("{}{:?}", blue("АЛФАВИТ:"), green(&alvabet));
    println!("{}{:?}", blue("ДОБАВЛЕНИЕ ПРОБЕЛА:"), green(probel.clone()));
    println!("{}{:?}", blue("УВЕЛИЧЕНИЕ ДЛИННЫ ПАРОЛЯ:"), green(len_uvelichenie.clone()));
    println!("{}{:?}", blue("АДРЕСОВ ЗАГРУЖЕННО:"), green(database.len()));


    //получать сообщения от потоков
    let (tx, rx) = mpsc::channel();

    //если указано добавлять пробел добавим
    let spase = if probel { " " } else { "" };

    //подготавливаем данные для потока
    let database = Arc::new(database);
    let alvabet = Arc::new(format!("{alvabet}{spase}"));

    //запускаем отдельный поток, а этот будет слушать и инфу отображать
    let clone_db = database.clone();
    let clone_alvabet = alvabet.clone();
    let tx = tx.clone();
    task::spawn_blocking(move || {
        process(&clone_db, tx, dlinn_a_pasvord, &clone_alvabet, len_uvelichenie);
    });


    //отображает инфу в однy строку(обновляемую)
    let mut stdout = stdout();
    for received in rx {
        let list: Vec<&str> = received.split(",").collect();
        let speed = list[0].to_string().parse::<u64>().unwrap();
        print!("{}\r{}", BACKSPACE, green(format!("SPEED:{speed}/s|{}", list[1])));
        stdout.flush().unwrap();
    }
}

fn process(file_content: &Arc<HashSet<Vec<u8>>>, tx: Sender<String>, dlinn_a_pasvord: usize, alvabet: &Arc<String>, len_uvelichenie: bool) {
    let mut start = Instant::now();
    let mut speed: u32 = 0;

    let mut len = dlinn_a_pasvord;

    let ice_library = ice_library::IceLibrary::new();
    ice_library.init_secp256_lib();

    let mut current_combination = vec![0; len];

    let charset_chars: Vec<char> = alvabet.chars().collect();
    let charset_len = charset_chars.len();

    loop {
        // жпт соченил
        let password_string: String = String::from_iter(
            current_combination.iter().map(|&idx| charset_chars[idx])
        );

        // Проверяем пароль, хешеруем
        let h = Sha256::digest(&password_string).to_vec();

        // перегоняем в паблик сжатый и нет
        let pk_u = ice_library.privatekey_to_publickey(&h);
        let pk_c = ice_library.publickey_uncompres_to_compres(&pk_u);

        // получем из них хеш160
        let h160c = hash160(&*pk_c.to_vec()).0;
        let h160u = hash160(&*pk_u.to_vec()).0;

        //проверка наличия в базе
        if file_content.contains(&h160u.to_vec()) {
            let address = get_legacy(h160u, 0x00);
            let private_key_u = hex_to_wif_uncompressed(&h);
            print_and_save(hex::encode(&h), &private_key_u, address, &password_string);
        }
        if file_content.contains(&h160c.to_vec()) {
            let address = get_legacy(h160c, 0x00);
            let private_key_c = hex_to_wif_compressed(&h);
            print_and_save(hex::encode(&h), &private_key_c, address, &password_string);
        }

        //измеряем скорость и шлём прогресс
        speed = speed + 1;
        if start.elapsed() >= Duration::from_secs(1) {
            tx.send(format!("{speed},{password_string}").to_string()).unwrap();
            start = Instant::now();
            speed = 0;
        }

        //это мне нахлабучил жпт, хрен проссыш как работает
        let mut i = len;
        while i > 0 {
            i -= 1;
            if current_combination[i] + 1 < charset_len {
                current_combination[i] += 1;
                break;
            } else {
                current_combination[i] = 0;
            }
        }

        if i == 0 && current_combination[0] == charset_len - 1 {
            //если включенно увеличение длинны увеличим иначе выйдем из цикла
            if len_uvelichenie {
                len = len + 1;
                current_combination = vec![0; len];
                println!("{}{:?}", blue("ДЛИНА ПАРОЛЯ:"), green(len));
            } else {
                println!("{}", blue("ГОТОВО"));
                break;
            }
        }
    }
}


fn lines_from_file(filename: impl AsRef<Path>) -> io::Result<Vec<String>> {
    BufReader::new(File::open(filename)?).lines().collect()
}

fn add_v_file(name: &str, data: String) {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(name)
        .expect("cannot open file")
        .write(data.as_bytes())
        .expect("write failed");
}

fn hex_to_wif_compressed(raw_hex: &Vec<u8>) -> String {
    let mut v = [0; 38];
    v[0] = 0x80;
    v[1..=32].copy_from_slice(&raw_hex.as_ref());
    v[33] = 0x01;
    let checksum = sha256d(&v[0..=33]);
    v[34..=37].copy_from_slice(&checksum[0..=3]);
    v.to_base58()
}

fn hex_to_wif_uncompressed(raw_hex: &Vec<u8>) -> String {
    let mut v = [0; 37];
    v[0] = 0x80;
    v[1..=32].copy_from_slice(&raw_hex.as_ref());
    let checksum = sha256d(&v[0..=32]);
    v[33..37].copy_from_slice(&checksum[0..=3]);
    v.to_base58()
}

fn print_and_save(hex: String, key: &String, addres: String, password_string: &String) {
    println!("{}", cyan("\n!!!!!!!!!!!!!!!!!!!!!!FOUND!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
    println!("{}{}", cyan("ПАРОЛЬ:"), cyan(password_string));
    println!("{}{}", cyan("HEX:"), cyan(hex.clone()));
    println!("{}{}", cyan("PRIVATE KEY:"), cyan(key));
    println!("{}{}", cyan("ADDRESS:"), cyan(addres.clone()));
    let s = format!("ПАРОЛЬ:{}\nHEX:{}\nPRIVATE KEY: {}\nADDRESS {}\n", password_string, hex, key, addres);
    add_v_file("FOUND.txt", s);
    println!("{}", cyan("SAVE TO FOUND.txt"));
    println!("{}", cyan("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
}

fn sha256d(data: &[u8]) -> Vec<u8> {
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(&first_hash);
    second_hash.to_vec()
}

pub fn get_legacy(hash160: [u8; 20], coin: u8) -> String {
    let mut v = Vec::with_capacity(23);
    v.push(coin);
    v.extend_from_slice(&hash160);
    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum[0..4]);
    let b: &[u8] = v.as_ref();
    b.to_base58()
}

fn first_word(s: &String) -> &str {
    s.trim().split_whitespace().next().unwrap_or("")
}