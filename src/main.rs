use std::fs::{File, OpenOptions};
use std::{fs, io, thread};
use std::collections::HashSet;
use std::fmt::format;
use std::io::{BufRead, BufReader, Read, stdout, Write};
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use base58::{FromBase58, ToBase58};
//use bloomfilter::Bloom;
use rand::Rng;
use crate::color::{blue, cyan, green, magenta, red};

use rustils::parse::boolean::string_to_bool;
use sha2::{Digest, Sha256};
use sv::util::hash160;
use tiny_keccak::Hasher;
use crate::bloom::{get_len_find_create,get_lines,get_bufer_file};

//mod ice_library;
mod color;
mod data;
mod bloom;


pub const LEGACY_BTC: u8 = 0x00;
pub const LEGACY_BTG: u8 = 0x26;
pub const LEGACY_DASH: u8 = 0x4C;
pub const BIP49_BTC: u8 = 0x05;
pub const BIP49_BTG: u8 = 0x17;
pub const BIP49_DASH: u8 = 0x10;
pub const LEGACY_DOGE: u8 = 0x1E;
pub const BIP49_DOGE: u8 = 0x16;
pub const LEGACY_LTC: u8 = 0x30;


extern crate secp256k1;

use secp256k1::{PublicKey, Secp256k1, SecretKey};
//use tiny_keccak::Keccak;

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
    let mode: usize = first_word(&conf[6].to_string()).to_string().parse::<usize>().unwrap();
    let comb_perebor_left_: usize = first_word(&conf[7].to_string()).to_string().parse::<usize>().unwrap();
    //   let comb_perebor_ryit_: usize = first_word(&conf[8].to_string()).to_string().parse::<usize>().unwrap();
    let minikey = string_to_bool(first_word(&conf[9].to_string()).to_string());
    let show_info = string_to_bool(first_word(&conf[10].to_string()).to_string());
    //---------------------------------------------------------------------

    //если укажут меньше или 0
    let comb_perebor_left = if comb_perebor_left_ > 0 {
        comb_perebor_left_
    } else { 1 };



    //проверяем есть ли файл(создаём) и считаем сколько строк
    let len_btc_txt = get_len_find_create("btc.txt");
    //провереряем если файл с обрубками уже есть то скажем что пропускаем и дальше идём
    if fs::metadata(Path::new("btc_h160.bin")).is_ok() {
        println!("{}", red("файл btc_h160.bin уже существует,конвертирование пропущено"));
    } else {
        println!("{}", blue("конвертирование адресов в h160 и сохранение в btc_h160.bin"));
        //конвертируем в h160 и записываем в файл рядом
        //создаём файл
        let mut file = File::create("btc_h160.bin").unwrap();
        //ищем в списке нужные делаем им харакири и ложим обрубки в файл
        let mut len_btc  = 0;
        for (index, address) in get_bufer_file("btc.txt").lines().enumerate() {

            let binding = match address.expect("REASON").from_base58() {
                Ok(value) => value,
                Err(_err) => {
                    eprintln!("{}", red(format!("ОШИБКА ДЕКОДИРОВАНИЯ В base58 строка:{}",index + 1)));
                    continue; // Пропускаем этот адрес и переходим к следующему
                }
            };

            let mut a: [u8; 20] = [0; 20];

            if binding.len() >= 21 {
                a.copy_from_slice(&binding.as_slice()[1..21]);
                if let Err(e) = file.write_all(&a) {
                    eprintln!("Не удалось записать в файл: {}", e);
                }else {
                    len_btc = len_btc+1;
                }

            } else {
                eprintln!("{}", red(format!("ОШИБКА,АДРЕСС НЕ ВАЛИДЕН строка:{}", index + 1)));
            }

        }
        println!("{}", blue(format!("конвертировано адресов в h160:{}/{}", green(len_btc_txt), green(len_btc))));
    }

    println!("{}", blue("ЗАПИСЬ ДАННЫХ В БАЗУ.."));
    let mut database: HashSet<[u8; 20]> = HashSet::new();
    let file = File::open("btc_h160.bin").expect("неудалось открыть файл");
    let mut reader = BufReader::new(file);
    let mut colichestvo = 0;
    loop {
        let mut array = [0u8; 20];
        match reader.read_exact(&mut array) {
            Ok(_) => {
                colichestvo = colichestvo+1;
                database.insert(array);
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            _ => {}
        }
    }

    println!("{}{} шт", blue("Данные успешно загружены в базу:"),green(format!("{colichestvo}")));

    // let mut database = HashSet::new();
    // println!("{}", blue("ЗАПИСЬ ДАННЫХ В БАЗУ.."));
    // for line in get_bufer_file("btc_h160.txt").lines() {
    //     match line {
    //         Ok(l) => {
    //             // Добавление строки в Bloom фильтр
    //             database.insert(l.as_bytes()[0..20]);
    //         }
    //         Err(e) => { println!("ошибка записи в базу{}", e) }
    //     }
    // }


    //если блум есть загрузим его
    //let database= bloom::load_bloom();

    // // *******************************************
    // //читаем файл с адресами и конвертируем их в h160 для базы
    // // -----------------------------------------------------------------
    // println!("{}", blue("Читаем файл с адресами и конвертируем их в h160"));
    //
    // let file_content = match lines_from_file("address.txt") {
    //     Ok(file) => { file }
    //     Err(_) => {
    //         let dockerfile = include_str!("address.txt");
    //         add_v_file("address.txt", dockerfile.to_string());
    //         lines_from_file("address.txt").expect("kakoyto_pizdec")
    //     }
    // };
    // //-------------------------------------------------------------------------------
    //
    // //   хешируем
    // //----------------------------------------------------------------------------------------
    // let mut database = HashSet::new();
    // for (index, address) in file_content.iter().enumerate() {
    //     let binding = match address.from_base58() {
    //         Ok(value) => value,
    //         Err(_err) => {
    //             eprintln!("{}", red(format!("ОШИБКА ДЕКОДИРОВАНИЯ В base58 адресс:{}/строка:{}", address, index + 1)));
    //             continue; // Пропускаем этот адрес и переходим к следующему
    //         }
    //     };
    //
    //     let mut a: [u8; 20] = [0; 20];
    //     if binding.len() >= 21 {
    //         a.copy_from_slice(&binding.as_slice()[1..21]);
    //         database.insert(a);
    //     } else {
    //         eprintln!("{}", red(format!("ОШИБКА,АДРЕСС НЕ ВАЛИДЕН адресс:{}/строка:{}", address, index + 1)));
    //     }
    // }
    // //-----------------------------------------------------------------------


    //ИНфо блок
    //||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
    println!("{}{}{}", blue("КОЛИЧЕСТВО ЯДЕР ПРОЦЕССОРА:"), green(cpu_core), blue(format!("/{count_cpu}")));
    println!("{}{}", blue("ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));
    if alvabet == "0" {
        println!("{}{}", blue("АЛФАВИТ:"), green("ВСЕ ВОЗМОЖНЫЕ"));
    } else {
        println!("{}{}", blue("АЛФАВИТ:"), green(&alvabet));
    }
    println!("{}{}", blue("ДОБАВЛЕНИЕ ПРОБЕЛА:"), green(probel.clone()));
    if mode == 0 {
        println!("{}{}", blue("УВЕЛИЧЕНИЕ ДЛИННЫ ПАРОЛЯ:"), green(len_uvelichenie.clone()));
        println!("{}{}", blue("НАЧАЛО ПЕРЕБОРА:"), green(start_perebor.clone()));
    }
   // println!("{}{}/{}", blue("H160 АДРЕСОВ ЗАГРУЖЕННО:"), green(database.len()), green(file_content.len()));
    println!("{}{}", blue("РЕЖИМ ГЕНЕРАЦИИ ПАРОЛЯ:"), green(get_mode_text(mode)));
    if mode == 2 {
        println!("{}{}", blue("КОЛИЧЕСТВО ЗНАКОВ ПЕРЕБОРА СЛЕВА:"), green(comb_perebor_left));
    }
    println!("{}{}", blue("ДОБАВЛЕНИЕ S В НАЧАЛЕ(для поиска миникей):"), green(minikey.clone()));
    let prefix = if minikey {
        //если включен режим миникей то отнимем 1 из общей длинны для первой S
        dlinn_a_pasvord = dlinn_a_pasvord - 1;
        //укажем нужный префикс
        "S"
    } else { "" };

    println!("{}{}", blue("ОТОБРАЖЕНИЕ СКОРОСТИ И ТЕКУЩЕГО ПОДБОРА:"), green(show_info.clone()));
    //|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||



    //главные каналы
    let (main_sender, main_receiver) = mpsc::channel();

    // Запускаем выбраное количество потоков(ядер) постоянно работающих
    //----------------------------------------------------------------------------------
    //будет храниться список запушеных потоков(каналов для связи)
    let mut channels = Vec::new();

    let bloom_filter = Arc::new(database);

    for ch in 0..cpu_core {
        //создаём для каждого потока отдельный канал для связи
        let (sender, receiver) = mpsc::channel();

        let database_cl = bloom_filter.clone();

        //главный поток
        let main_sender = main_sender.clone();

        // let ice_library = ice_library::IceLibrary::new();
        // ice_library.init_secp256_lib();
        let secp = Secp256k1::new();


        thread::spawn( move || {
            loop {
                let password_string: String = receiver.recv().unwrap_or("error".to_string());

                //получаем из пароля хекс
                let h = Sha256::digest(format!("{prefix}{}", password_string)).to_vec();

                //получаем публичный ключ
                //  let pk_u = ice_library.privatekey_to_publickey(&h);
                //  let pk_c = ice_library.publickey_uncompres_to_compres(&pk_u);

                // Создаем секретный ключ из байт
                let secret_key = SecretKey::from_slice(&h).expect("32 bytes, within curve order");
                // Создаем публичный ключ из секретного
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                let pk_c = public_key.serialize();
                let pk_u = public_key.serialize_uncompressed();

                //получем из них хеш160
                let h160c = hash160(&pk_c[0..]).0;

                if database_cl.contains(&h160c) {
                    let address = get_legacy(h160c, 0x00);
                    let private_key_c = hex_to_wif_compressed(&h);
                    print_and_save(hex::encode(&h), &private_key_c, address, &password_string);
                }

                //получем из них хеш160
                let h160u = hash160(&pk_u[0..]).0;

                // //проверка наличия в базе
                if database_cl.contains(&h160u){
                    let address = get_legacy(h160u, 0x00);
                    let private_key_u = hex_to_wif_uncompressed(&h.to_vec());
                    print_and_save(hex::encode(&h), &private_key_u, address, &password_string);
                }


                // // //проверка наличия в базе ETH
                // if database_cl.check(&get_eth_kessak_from_public_key(pk_u)){
                //     let address =  get_eth_address_from_public_key(pk_u);
                //     let private_key_u = hex_to_wif_uncompressed(&h.to_vec());
                //     print_and_save(hex::encode(&h), &private_key_u, address, &password_string);
                // }

                //шлём в главный поток для получения следующей задачи
                main_sender.send(ch).unwrap();
            }
        });
        //зажигание хз костыль получился(выполняеться один раз при запуске потока)
        sender.send("start".to_string()).unwrap();
        channels.push(sender);
    }
    //---------------------------------------------------------------------------------------------


    //подготовка к запуску главного цикла
    //-----------------------------------------------------------------------------------------
    //для измерения скорости
    let mut start = Instant::now();
    let mut speed: u32 = 0;
    let one_sek = Duration::from_secs(1);

    let mut rng = rand::thread_rng();

    let alfabet_all = if alvabet == "0".to_string() { true } else { false };

    //если указано добавлять пробел добавим
    let spase = if probel { " " } else { "" };
    let alvabet = format!("{alvabet}{spase}");

    let charset_chars: Vec<char> = alvabet.chars().collect();
    let charset_len = charset_chars.len();

    //состовляем начальную позицию
    let mut current_combination = vec![0; dlinn_a_pasvord];
    //заполняем страртовыми значениями
    for d in comb_perebor_left..dlinn_a_pasvord {
        let position = match start_perebor.chars().nth(d) {
            Some(ch) => {
                // Находим позицию символа в charset_chars
                charset_chars.iter().position(|&c| c == ch).unwrap_or_else(|| {
                    let c = if alfabet_all { char::from_u32(0).unwrap() } else { ch };
                    eprintln!("{}", red(format!("Знак:{} из *начала перебора* ненайден, установлен первый из алфавита", c)));
                    0
                })
            }
            None => { rng.gen_range(0..charset_len) }
        };
        current_combination[d] = position;
    }
    //-----------------------------------------------------------------------------------



    //--ГЛАВНЫЙ ЦИКЛ
    // слушаем ответы потоков и если есть шлём новую задачу
    //----------------------------------------------------------------------------------------------
    for received in main_receiver {
        let ch = received;

        // следующая комбинация пароля если алфавит пустой будем по всем возможным перебирать
        let password_string: String = if alfabet_all {
            current_combination.iter().map(|&c| char::from_u32(c as u32).unwrap_or(' ')).collect()
        } else {
            String::from_iter(
                current_combination.iter().map(|&idx| charset_chars[idx])
            )
        };


        if show_info {
            //измеряем скорость и шлём прогресс
            speed = speed + 1;
            if start.elapsed() >= one_sek {
                let mut stdout = stdout();
                print!("{}\r{}", BACKSPACE, green(format!("SPEED:{speed}/s|{}", (format!("{}{}",prefix, password_string)))));
                stdout.flush().unwrap();
                start = Instant::now();
                speed = 0;
            }
        }

        // Отправляем новую в свободный канал
        channels[ch].send(password_string).unwrap();

        //перебор
        if mode == 0 {
            let mut i = dlinn_a_pasvord;
            while i > 0 {
                i -= 1;
                if alfabet_all {
                    if current_combination[i] + 1 < 0x10FFFF {
                        current_combination[i] += 1;
                        break;
                    } else {
                        current_combination[i] = 0;
                    }
                } else {
                    if current_combination[i] + 1 < charset_len {
                        current_combination[i] += 1;
                        break;
                    } else {
                        current_combination[i] = 0;
                    }
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
        }
        //рандом
        if mode == 1 {
            for f in 0..dlinn_a_pasvord {
                current_combination[f] = rng.gen_range(0..charset_len);
            }
        }

        //комбинированный
        if mode == 2 {
            //будем переберать слева указаное количество
            let mut i = comb_perebor_left;
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
                for f in 0..dlinn_a_pasvord {
                    //заполняем слева начальными значениями
                    if f < comb_perebor_left {
                        current_combination[f] = 0;
                    } else {
                        //остальные рандомно
                        current_combination[f] = rng.gen_range(0..charset_len);
                    }
                }
            }
        }
    }
    //------------------------------------------------------------------------------------
}

fn get_mode_text(mode: usize) -> String {
    match mode {
        0 => "ПОСЛЕДОВАТЕЛЬНЫЙ ПЕРЕБОР".to_string(),
        1 => "РАНДОМ".to_string(),
        2 => "КОМБИНИРОВАННЫЙ".to_string(),
        _ => { "ХЗ".to_string() }
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

//ETH
// pub fn get_eth_address_from_public_key(public_key_u: [u8; 65]) -> String {
//     let mut output = [0u8; 32];
//     let mut hasher = Keccak::v256();
//     hasher.update(public_key_u.split_first().unwrap().1);
//     hasher.finalize(&mut output);
//     hex::encode(&output[12..])
// }
// pub fn get_eth_kessak_from_public_key(public_key_u: [u8; 65]) -> Vec<u8> {
//     let mut output = [0u8; 32];
//     let mut hasher = Keccak::v256();
//     hasher.update(public_key_u.split_first().unwrap().1);
//     hasher.finalize(&mut output);
//     output[12..].to_vec()
// }

//bip49------------------------------------------------------
// pub fn dla_bip_49(public_key: &[u8]) -> Vec<u8> {
//     let digest1 = Sha256::digest(&public_key);
//
//     let hash160_1 = ripemd::Ripemd160::digest(&digest1);
//
//     let mut v = Vec::with_capacity(20);
//     v.push(0x00);
//     v.push(0x14);
//     v.extend_from_slice(&hash160_1);
//
//     let digest2 = Sha256::digest(&v);
//     let hash160_3 = ripemd::Ripemd160::digest(&digest2);
//     let hash_slice = hash160_3;
//     hash_slice.to_vec()
// }
//
// pub fn get_bip49(hash160_3: &[u8], coin: u8) -> String {
//
//     let mut v = Vec::with_capacity(25);
//     v.push(coin);
//     v.extend_from_slice(&hash160_3);
//
//     let checksum = sha256d(&v);
//     v.extend_from_slice(&checksum[0..4]);
//     v.to_base58()
// }
//------------------------------------------------------------------------

// TRX
pub fn get_trx_from_eth(eth: String) -> String {
    let mut v = Vec::with_capacity(50);
    v.push(0x41);
    v.extend_from_slice(hex::decode(eth).unwrap().as_slice());
    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum[0..4]);
    let b: &[u8] = v.as_ref();
    b.to_base58()
}

fn first_word(s: &String) -> &str {
    s.trim().split_whitespace().next().unwrap_or("")
}

fn get_buffer_file(filename: &str) -> io::Lines<io::BufReader<File>> {
    let file = File::open(Path::new(filename)).expect("не удалось открыть файл");
    io::BufReader::new(file).lines()
}