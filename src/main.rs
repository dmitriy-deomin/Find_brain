use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::{io, thread};
use std::io::{BufRead, BufReader, stdout, Write};
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use base58::{FromBase58, ToBase58};
use sv::util::{hash160};
use crate::color::{blue, cyan, green, magenta};

use rustils::parse::boolean::string_to_bool;
use sha2::{Digest, Sha256};

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

    //количество ядер процессора
    let count_cpu = num_cpus::get();

    let cpu_core: usize = first_word(&conf[0].to_string()).to_string().parse::<usize>().unwrap();
    let mut dlinn_a_pasvord: usize = first_word(&conf[1].to_string()).to_string().parse::<usize>().unwrap();
    let alvabet = first_word(&conf[2].to_string()).to_string();
    let len_uvelichenie = string_to_bool(first_word(&conf[3].to_string()).to_string());
    let probel = string_to_bool(first_word(&conf[4].to_string()).to_string());
    let start_perebor = first_word(&conf[5].to_string()).to_string();
    //---------------------------------------------------------------------

    //читаем файл с адресами и конвертируем их в h160 для базы
    //-----------------------------------------------------------------
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
    //-----------------------------------------------------------------------

    println!("{}{}{}", blue("КОЛИЧЕСТВО ЯДЕР ПРОЦЕССОРА:"), green(cpu_core), blue(format!("/{count_cpu}")));
    println!("{}{}", blue("ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));
    println!("{}{}", blue("АЛФАВИТ:"), green(&alvabet));
    println!("{}{}", blue("ДОБАВЛЕНИЕ ПРОБЕЛА:"), green(probel.clone()));
    println!("{}{}", blue("УВЕЛИЧЕНИЕ ДЛИННЫ ПАРОЛЯ:"), green(len_uvelichenie.clone()));
    println!("{}{}", blue("АДРЕСОВ ЗАГРУЖЕННО:"), green(database.len()));
    println!("{}{}", blue("НАЧАЛО ПЕРЕБОРА:"), green(start_perebor.clone()));

    //главные каналы
    let (main_sender, main_receiver) = mpsc::channel();

    // создание потоков
    //-----------------------------------------------------------------------
    //будет храниться список запушеных потоков(каналов для связи)
    let mut channels = Vec::new();
    let database = Arc::new(database);
    for ch in 0..cpu_core {
        let (sender, receiver) = mpsc::channel();
        let database_cl = database.clone();

        let main_sender = main_sender.clone();

        let ice_library = ice_library::IceLibrary::new();
        ice_library.init_secp256_lib();

        // Поток для выполнения задач
        thread::spawn(move || {
            loop {
                let (h, password_string) = receiver.recv().unwrap();

                //получаем публичный ключ
                let pk_u = ice_library.privatekey_to_publickey(&h);//тут компухтер напрягаеться
                let pk_c = ice_library.publickey_uncompres_to_compres(&pk_u);

                //получем из них хеш160
                let h160c = hash160(&*pk_c.to_vec()).0;
                let h160u = hash160(&*pk_u.to_vec()).0;

                //проверка наличия в базе
                if database_cl.contains(&h160u.to_vec()) {
                    let address = get_legacy(h160u, 0x00);
                    let private_key_u = hex_to_wif_uncompressed(&h);
                    print_and_save(hex::encode(&h), &private_key_u, address, &password_string);
                }
                if database_cl.contains(&h160c.to_vec()) {
                    let address = get_legacy(h160c, 0x00);
                    let private_key_c = hex_to_wif_compressed(&h);
                    print_and_save(hex::encode(&h), &private_key_c, address, &password_string);
                }

                //шлём поток
                main_sender.send(ch).unwrap();
            }
        });
        //зажигание хз костыль получился
        sender.send((vec![], "".to_string())).unwrap();
        channels.push(sender);
    }
    //------------------------------------------------------------------------------

    //для измерения скорости
    let mut start = Instant::now();
    let mut speed: u32 = 0;

    let ice_library = ice_library::IceLibrary::new();
    ice_library.init_secp256_lib();

    //если указано добавлять пробел добавим
    let spase = if probel { " " } else { "" };
    let alvabet = format!("{alvabet}{spase}");

    let charset_chars: Vec<char> = alvabet.chars().collect();
    let charset_len = charset_chars.len();
    //состовляем начальную позицию
    let mut current_combination= vec![0; dlinn_a_pasvord];
    for d in 0..dlinn_a_pasvord {
        let position = charset_chars.iter().position(|&ch| ch == start_perebor.chars().nth(d).unwrap_or(charset_chars[0])).unwrap();
        current_combination[d]= position;
    };

    //слушаем ответы потков и если есть шлём новую задачу
    for received in main_receiver {
        let ch = received;

        // следующая комбинация пароля
        let password_string = String::from_iter(
            current_combination.iter().map(|&idx| charset_chars[idx])
        );

        // Отправляем новую в свободный канал
        channels[ch].send((Sha256::digest(&password_string).to_vec(), password_string.clone())).unwrap();

        //это мне нахлабучил жпт, хрен проссыш как работает
        let mut i = dlinn_a_pasvord;
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
                dlinn_a_pasvord = dlinn_a_pasvord + 1;
                current_combination = vec![0; dlinn_a_pasvord];
                println!("{}{:?}", blue("ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));
            } else {
                println!("{}", blue("ГОТОВО"));
                break;
            }
        }

        //измеряем скорость и шлём прогресс
        speed = speed + 1;
        if start.elapsed() >= Duration::from_secs(1) {
            let mut stdout = stdout();
            print!("{}\r{}", BACKSPACE, green(format!("SPEED:{speed}/s|{}", password_string)));
            stdout.flush().unwrap();
            start = Instant::now();
            speed = 0;
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
    if raw_hex.len() == 32 {
        let mut v = [0; 38];
        v[0] = 0x80;
        v[1..33].copy_from_slice(&raw_hex[..]);
        v[33] = 0x01;
        let checksum = sha256d(&v[0..34]);
        v[34..38].copy_from_slice(&checksum[0..4]);
        v.to_base58()
    } else {
        format!("Ошибка hex меньше 64 :'{}'", hex::encode(raw_hex).to_string())
    }
}

fn hex_to_wif_uncompressed(raw_hex: &Vec<u8>) -> String {
    if raw_hex.len() == 32 {
        let mut v = [0; 37];
        v[0] = 0x80;
        v[1..33].copy_from_slice(&raw_hex[..]);
        let checksum = sha256d(&v[0..33]);
        v[33..37].copy_from_slice(&checksum[0..4]);
        v.to_base58()
    } else { format!("Ошибка hex меньше 64 :'{}'", hex::encode(raw_hex).to_string()) }
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
    let second_hash = Sha256::digest(first_hash);
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