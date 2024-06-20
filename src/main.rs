use std::fs::{File, OpenOptions};
use std::{fs, io, thread};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, BufWriter, Lines, Read, stdout, Write};
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use base58::{FromBase58, ToBase58};
use itertools::Itertools;
use rand::{Rng, thread_rng};
use rand::prelude::IteratorRandom;
use rand::seq::SliceRandom;
use ripemd::{Ripemd160, Digest as Ripemd160Digest};

use crate::color::{blue, cyan, green, magenta, red};
use rustils::parse::boolean::string_to_bool;
use sha2::{Sha256, Digest};
use sv::util::hash160;
use tiny_keccak::{Hasher, Keccak};

#[cfg(not(windows))]
use rust_secp256k1::{PublicKey, Secp256k1, SecretKey};

#[cfg(windows)]
mod ice_library;

#[cfg(windows)]
use ice_library::IceLibrary;

mod color;
mod data;

pub const LEGACY_BTC: u8 = 0x00;
pub const LEGACY_BTG: u8 = 0x26;
pub const LEGACY_DASH: u8 = 0x4C;
pub const BIP49_BTC: u8 = 0x05;
pub const BIP49_BTG: u8 = 0x17;
pub const BIP49_DASH: u8 = 0x10;
pub const LEGACY_DOGE: u8 = 0x1E;
pub const BIP49_DOGE: u8 = 0x16;
pub const LEGACY_LTC: u8 = 0x30;

const BACKSPACE: char = 8u8 as char;
const FILE_CONFIG: &str = "confBrain.txt";
const FILE_LIST: &str = "list.txt";


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

    //рандом
    let mut rng = rand::thread_rng();

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
    let minikey = string_to_bool(first_word(&conf[8].to_string()).to_string());
    let show_info = string_to_bool(first_word(&conf[9].to_string()).to_string());
    let rand_alfabet = string_to_bool(first_word(&conf[10].to_string()).to_string());
    let size_rand_alfabet = first_word(&conf[11].to_string()).to_string().parse::<usize>().unwrap();
    //---------------------------------------------------------------------

    //если укажут меньше или 0
    let comb_perebor_left = if comb_perebor_left_ > 0 {
        comb_perebor_left_
    } else { 1 };

    //если какойто бызы небудет небум искать в ней
    let find_eth;
    let find_btc;

    println!("{}", blue("--"));
    //провереряем если файл с хешами BTC
    //--------------------------------------------------------------------------------------------
    if fs::metadata(Path::new("btc_h160.bin")).is_ok() {
        println!("{}", green("файл btc_h160.bin уже существует,конвертирование пропущено"));
    } else {
        //проверяем есть ли файл(создаём) и считаем сколько строк
        let len_btc_txt = get_len_find_create("btc.txt");

        println!("{}", blue("конвертирование адресов в h160 и сохранение в btc_h160.bin"));
        //конвертируем в h160 и записываем в файл рядом
        //создаём файл
        let mut file = File::create("btc_h160.bin").unwrap();
        //ищем в списке нужные делаем им харакири и ложим обрубки в файл
        let mut len_btc = 0;
        for (index, address) in get_bufer_file("btc.txt").lines().enumerate() {
            let binding = match address.expect("REASON").from_base58() {
                Ok(value) => value,
                Err(_err) => {
                    eprintln!("{}", red(format!("ОШИБКА ДЕКОДИРОВАНИЯ В base58 строка:{}", index + 1)));
                    continue; // Пропускаем этот адрес и переходим к следующему
                }
            };

            let mut a: [u8; 20] = [0; 20];

            if binding.len() >= 21 {
                a.copy_from_slice(&binding.as_slice()[1..21]);
                if let Err(e) = file.write_all(&a) {
                    eprintln!("Не удалось записать в файл: {}", e);
                } else {
                    len_btc = len_btc + 1;
                }
            } else {
                eprintln!("{}", red(format!("ОШИБКА,АДРЕСС НЕ ВАЛИДЕН строка:{}", index + 1)));
            }
        }
        println!("{}", blue(format!("конвертировано адресов в h160:{}/{}", green(len_btc_txt), green(len_btc))));
    }
    //-----------------------------------------------------------------------------------------------

    println!("{}", blue("--"));

    //провереряем если файл с хешами DOGECOIN
    //--------------------------------------------------------------------------------------------
    if fs::metadata(Path::new("dogecoin_h160.bin")).is_ok() {
        println!("{}", green("файл dogecoin_h160.bin уже существует,конвертирование пропущено"));
    } else {
        //проверяем есть ли файл(создаём) и считаем сколько строк
        let len_btc_txt = get_len_find_create("dogecoin.txt");

        println!("{}", blue("конвертирование адресов в h160 и сохранение в dogecoin_h160.bin"));
        //конвертируем в h160 и записываем в файл рядом
        //создаём файл
        let mut file = File::create("dogecoin_h160.bin").unwrap();
        //ищем в списке нужные делаем им харакири и ложим обрубки в файл
        let mut len_btc = 0;
        for (index, address) in get_bufer_file("dogecoin.txt").lines().enumerate() {
            let binding = match address.expect("REASON").from_base58() {
                Ok(value) => value,
                Err(_err) => {
                    eprintln!("{}", red(format!("ОШИБКА ДЕКОДИРОВАНИЯ В base58 строка:{}", index + 1)));
                    continue; // Пропускаем этот адрес и переходим к следующему
                }
            };

            let mut a: [u8; 20] = [0; 20];

            if binding.len() >= 21 {
                a.copy_from_slice(&binding.as_slice()[1..21]);
                if let Err(e) = file.write_all(&a) {
                    eprintln!("Не удалось записать в файл: {}", e);
                } else {
                    len_btc = len_btc + 1;
                }
            } else {
                eprintln!("{}", red(format!("ОШИБКА,АДРЕСС НЕ ВАЛИДЕН строка:{}", index + 1)));
            }
        }
        println!("{}", blue(format!("конвертировано адресов в h160:{}/{}", green(len_btc_txt), green(len_btc))));
    }
    //-----------------------------------------------------------------------------------------------

    println!("{}", blue("--"));

    //провереряем если файл с хешами ETH
    //--------------------------------------------------------------------------------------------
    if fs::metadata(Path::new("eth.bin")).is_ok() {
        println!("{}", green("файл eth.bin уже существует,конвертирование пропущено"));
    } else {
        //проверяем есть ли файл(создаём) и считаем сколько строк
        let len_eth_txt = get_len_find_create("eth.txt");

        println!("{}", blue("конвертирование адресов и сохранение в eth.bin"));

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("eth.bin")
            .unwrap();
        let mut writer = BufWriter::new(file);

        let mut len_eth = 0;
        let mut invalid_addresses = Vec::new();

        for (index, line) in get_bufer_file("eth.txt").lines().enumerate() {
            match line {
                Ok(address) => match eth_address_to_bytes(&address) {
                    Ok(bytes) => {
                        if let Err(e) = writer.write_all(&bytes) {
                            eprintln!("Не удалось записать в файл: {}", e);
                        } else {
                            len_eth += 1;
                        }
                    }
                    Err(e) => {
                        invalid_addresses.push((index, address, e));
                    }
                },
                Err(e) => {
                    invalid_addresses.push((index, "".to_string(), e.to_string()));
                }
            }
        }

        println!("{}", blue(format!("конвертировано адресов:{}/{}", green(len_eth_txt), green(len_eth))));

        if !invalid_addresses.is_empty() {
            println!("Invalid addresses:");
            for (index, address, error) in invalid_addresses {
                println!("Line {}: {} ({})", index + 1, address, error);
            }
        }
    }
    //-----------------------------------------------------------------------------------------------

    //провереряем если файл с хешами TRX
    println!("{}", blue("--"));
    //провереряем если файл с хешами BTC
    //--------------------------------------------------------------------------------------------
    if fs::metadata(Path::new("trx_h160.bin")).is_ok() {
        println!("{}", green("файл trx_h160.bin уже существует,конвертирование пропущено"));
    } else {
        //проверяем есть ли файл(создаём) и считаем сколько строк
        let len_trx_txt = get_len_find_create("trx.txt");

        println!("{}", blue("конвертирование адресов в h160 и сохранение в trx_h160.bin"));
        //конвертируем в h160 и записываем в файл рядом
        //создаём файл
        let mut file = File::create("trx_h160.bin").unwrap();
        //ищем в списке нужные делаем им харакири и ложим обрубки в файл
        let mut len_trx = 0;
        for (index, address) in get_bufer_file("trx.txt").lines().enumerate() {
            let binding = match address.expect("REASON").from_base58() {
                Ok(value) => value,
                Err(_err) => {
                    eprintln!("{}", red(format!("ОШИБКА ДЕКОДИРОВАНИЯ В base58 строка:{}", index + 1)));
                    continue; // Пропускаем этот адрес и переходим к следующему
                }
            };

            let mut a: [u8; 20] = [0; 20];

            if binding.len() >= 21 {
                a.copy_from_slice(&binding.as_slice()[1..21]);
                if let Err(e) = file.write_all(&a) {
                    eprintln!("Не удалось записать в файл: {}", e);
                } else {
                    len_trx = len_trx + 1;
                }
            } else {
                eprintln!("{}", red(format!("ОШИБКА,АДРЕСС НЕ ВАЛИДЕН строка:{}", index + 1)));
            }
        }
        println!("{}", blue(format!("конвертировано адресов в h160:{}/{}", green(len_trx_txt), green(len_trx))));
    }
    //-----------------------------------------------------------------------------------------------
    println!("{}", blue("--"));

    // запись BTC в базу
    let mut colichestvo_btc = 0;
    println!("{}", blue("ЗАПИСЬ BTC ДАННЫХ В БАЗУ.."));
    let mut database: HashSet<[u8; 20]> = HashSet::new();
    let file = File::open("btc_h160.bin").expect("неудалось открыть файл");
    let mut reader = BufReader::new(file);
    loop {
        let mut array = [0u8; 20];
        match reader.read_exact(&mut array) {
            Ok(_) => {
                colichestvo_btc = colichestvo_btc + 1;
                database.insert(array);
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            _ => {}
        }
    }
    println!("{}{}", blue("Данные BTC успешно загружены в базу:"), green(format!("{colichestvo_btc} шт")));
    println!("{}", blue("--"));


    // запись TRX в базу
    let mut colichestvo_trx = 0;
    println!("{}", blue("ЗАПИСЬ TRX ДАННЫХ В БАЗУ.."));
    let file = File::open("trx_h160.bin").expect("неудалось открыть файл");
    let mut reader = BufReader::new(file);
    loop {
        let mut array = [0u8; 20];
        match reader.read_exact(&mut array) {
            Ok(_) => {
                colichestvo_trx = colichestvo_trx + 1;
                database.insert(array);
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            _ => {}
        }
    }
    println!("{}{}", blue("Данные TRX успешно загружены в базу:"), green(format!("{colichestvo_trx} шт")));
    println!("{}", blue("--"));


    // запись DOGECOIN в базу
    let mut colichestvo_dogecoin = 0;
    println!("{}", blue("ЗАПИСЬ DOGECOIN ДАННЫХ В БАЗУ.."));
    let file = File::open("dogecoin_h160.bin").expect("неудалось открыть файл");
    let mut reader = BufReader::new(file);
    loop {
        let mut array = [0u8; 20];
        match reader.read_exact(&mut array) {
            Ok(_) => {
                colichestvo_dogecoin = colichestvo_dogecoin + 1;
                database.insert(array);
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            _ => {}
        }
    }
    println!("{}{}", blue("Данные DOGECOIN успешно загружены в базу:"), green(format!("{colichestvo_dogecoin} шт")));
    println!("{}", blue("--"));

    //запись ETH в базу
    let mut colichestvo_eth = 0;
    println!("{}", blue("ЗАПИСЬ ETH ДАННЫХ В БАЗУ.."));
    let file = File::open("eth.bin").expect("неудалось открыть файл");
    let mut reader = BufReader::new(file);
    loop {
        let mut array = [0u8; 20];
        match reader.read_exact(&mut array) {
            Ok(_) => {
                colichestvo_eth = colichestvo_eth + 1;
                database.insert(array);
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            _ => {}
        }
    }
    println!("{}{}", blue("Данные ETH успешно загружены в базу:"), green(format!("{colichestvo_eth} шт")));


    //включим или выключим проверку BTC
    find_btc = if colichestvo_btc+colichestvo_dogecoin > 0 { true } else { false };

    //включим или выключим проверку ETH
    find_eth = if colichestvo_eth+colichestvo_trx > 0 { true } else { false };

    println!("{}", blue("--"));
    println!("{}{}", blue("ИТОГО ЗАГРУЖЕННО В БАЗУ:"), green(format!("{} шт", colichestvo_btc + colichestvo_eth+colichestvo_dogecoin)));
    println!("{}", blue("--"));


    //ИНфо блок
    //||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
    println!("{}", blue("************************************"));
    println!("{}{}", blue("ГЕНЕРАЦИЯ ETH АДРЕСОВ:"), green(format!("{}", find_eth)));
    println!("{}{}", blue("ГЕНЕРАЦИЯ BTC АДРЕСОВ:"), green(format!("{}", find_btc)));
    println!("{}{}{}", blue("КОЛИЧЕСТВО ЯДЕР ПРОЦЕССОРА:"), green(cpu_core), blue(format!("/{count_cpu}")));
    println!("{}{}", blue("ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));

    //алфавит
    //-------------------------------------------------------------------------
    let alvabet = if rand_alfabet {
        let rndalf = get_rand_alfabet(alvabet, size_rand_alfabet);
        println!("{}{}", blue("СЛУЧАЙНЫЕ ИЗ АЛФАВИТА:"), green(rand_alfabet));
        println!("{}{}", blue("-КОЛИЧЕСТВО СЛУЧАЙНЫХ ИЗ АЛФАВИТА:"), green(size_rand_alfabet));
        println!("{}{}", blue("-АЛФАВИТ:"), green(&rndalf));
        rndalf
    } else {
        println!("{}{}", blue("СЛУЧАЙНЫЕ ИЗ АЛФАВИТА:"), green(rand_alfabet));
        if alvabet == "0" {
            println!("{}{}", blue("АЛФАВИТ:"), green("ВСЕ ВОЗМОЖНЫЕ"));
        } else {
            println!("{}{}", blue("АЛФАВИТ:"), green(&alvabet));
        }
        alvabet
    };
    //-------------------------------------------------------------------------------


    println!("{}{}", blue("ДОБАВЛЕНИЕ ПРОБЕЛА:"), green(probel.clone()));
    if mode == 0 {
        println!("{}{}", blue("УВЕЛИЧЕНИЕ ДЛИННЫ ПАРОЛЯ:"), green(len_uvelichenie.clone()));
        println!("{}{}", blue("НАЧАЛО ПЕРЕБОРА:"), green(start_perebor.clone()));
    }
    println!("{}{}", blue("РЕЖИМ ГЕНЕРАЦИИ ПАРОЛЯ:"), green(get_mode_text(mode)));
    if mode == 2 {
        println!("{}{}", blue("КОЛИЧЕСТВО ЗНАКОВ ПЕРЕБОРА СЛЕВА:"), green(comb_perebor_left));
    }
    if mode == 3 {
        println!("{}", blue("ВКЛЮЧЕННО ИСПОЛЬЗОВАНИЕ СПИСКА:"));
        //Чтение списка шаблонов, и если их нет создадим
        //-----------------------------------------------------------------
        get_len_find_create(FILE_LIST);
    }
    println!("{}{}", blue("ДОБАВЛЕНИЕ S В НАЧАЛЕ(для поиска миникей):"), green(minikey.clone()));
    let prefix = if minikey {
        //если включен режим миникей то отнимем 1 из общей длинны для первой S
        dlinn_a_pasvord = dlinn_a_pasvord - 1;
        //укажем нужный префикс
        "S"
    } else { "" };

    println!("{}{}", blue("ОТОБРАЖЕНИЕ СКОРОСТИ И ТЕКУЩЕГО ПОДБОРА:"), green(show_info.clone()));
    println!("{}", blue("************************************"));
    //|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||


    //проверка есть ли в базе вообще чего
    if find_btc == false && find_eth == false {
        println!("{}", red("БАЗА ПУСТА\nпоместите рядом с программой текстовые файлы со списком адресов:\nbtc.txt eth.txt"));
        jdem_user_to_close_programm();
        return;
    }

    //главные каналы
    let (main_sender, main_receiver) = mpsc::channel();

    // Запускаем выбраное количество потоков(ядер) постоянно работающих
    //----------------------------------------------------------------------------------
    //будет храниться список запушеных потоков(каналов для связи)
    let mut channels = Vec::new();

    let database = Arc::new(database);

    for ch in 0..cpu_core {
        //создаём для каждого потока отдельный канал для связи
        let (sender, receiver) = mpsc::channel();

        let database_cl = database.clone();

        //главный поток
        let main_sender = main_sender.clone();

        #[cfg(windows)]
            let ice_library = {
            let lib = IceLibrary::new();
            lib.init_secp256_lib();
            lib
        };

        //для всего остального
        #[cfg(not(windows))]
            let secp = Secp256k1::new();

        thread::spawn(move || {
            loop {
                let password_string: String = receiver.recv().unwrap_or("error".to_string());

                // Получаем хеш SHA-256 из пароля
                let mut sha256 = Sha256::new();
                sha256.update(format!("{prefix}{}", password_string));
                let h = sha256.finalize().0;

                // Получаем публичный ключ для разных систем , адрюха не дружит с ice_library
                //------------------------------------------------------------------------
                #[cfg(windows)]
                    let (pk_u, pk_c) = {
                    let p = ice_library.privatekey_to_publickey(&h);
                    (p, ice_library.publickey_uncompres_to_compres(&p))
                };

                #[cfg(not(windows))]
                    let (pk_u, pk_c) = {
                    // Создаем секретный ключ из байт
                    let secret_key = SecretKey::from_slice(&h).expect("32 bytes, within curve order");
                    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                    (public_key.serialize_uncompressed(), public_key.serialize())
                };
                //----------------------------------------------------------------------------

                //проверка наличия в базе BTC
                if find_btc {
                    //получем из них хеш160
                    let h160c = hash160(&pk_c[0..]).0;

                    //проверка наличия в базе BTC compress
                    if database_cl.contains(&h160c) {
                        let address_btc = get_legacy(h160c, LEGACY_BTC);
                        let address_doge = get_legacy(h160c, LEGACY_DOGE);
                        let address = format!("\nBTC compress:{}\nDOGECOIN compress:{}",address_btc,address_doge);
                        let private_key_c = hex_to_wif_compressed(&h.to_vec());
                        print_and_save(hex::encode(&h), &private_key_c, address, &password_string);
                    }

                    //получем из них хеш160
                    let h160u = hash160(&pk_u[0..]).0;

                    //проверка наличия в базе BTC uncompres
                    if database_cl.contains(&h160u) {
                        let address_btc = get_legacy(h160u, LEGACY_BTC);
                        let address_doge = get_legacy(h160u, LEGACY_DOGE);
                        let address = format!("\nBTC uncompres:{}\nDOGECOIN uncompres:{}",address_btc,address_doge);
                        let private_key_u = hex_to_wif_uncompressed(&h.to_vec());
                        print_and_save(hex::encode(&h), &private_key_u, address, &password_string);
                    }

                    let bip49_hash160 = bip_49_hash160c(h160c);

                    //проверка наличия в базе BTC bip49 3.....
                    if database_cl.contains(&bip49_hash160) {
                        let address_btc = get_bip49_address(&bip49_hash160, BIP49_BTC);
                        let address_doge = get_bip49_address(&bip49_hash160, BIP49_DOGE);
                        let address = format!("\nBTC bip49:{}\nDOGECOIN bip49:{}",address_btc,address_doge);
                        let private_key_c = hex_to_wif_compressed(&h.to_vec());
                        print_and_save(hex::encode(&h), &private_key_c, address, &password_string);
                    }
                }

                //проверка наличия в базе ETH
                if find_eth {
                    if database_cl.contains(&get_eth_kessak_from_public_key(pk_u)) {
                        let adr_eth = hex::encode(get_eth_kessak_from_public_key(pk_u));
                        let adr_trx = get_trx_from_eth(adr_eth.clone());
                        print_and_save_eth(hex::encode(&h), format!("\nETH 0x{adr_eth}\nTRX {adr_trx}"), &password_string);
                    }
                }

                //шлём в главный поток для получения следующей задачи
                main_sender.send(ch).unwrap();
            }
        });
        //зажигание хз костыль получился(выполняеться один раз при запуске потока)
        sender.send("инициализация потока, пароль <ничто> найденые адреса вне диапазона, хз".to_string()).unwrap();
        channels.push(sender);
    }
    //---------------------------------------------------------------------------------------------


    //подготовка к запуску главного цикла
    //-----------------------------------------------------------------------------------------
    //для измерения скорости
    let mut start = Instant::now();
    let mut speed: u32 = 0;
    let one_sek = Duration::from_secs(1);

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


    let binding = if mode == 3 {
        let lines = read_lines(FILE_LIST);
        // Преобразуем строки в вектор
        lines.filter_map(Result::ok).collect::<Vec<String>>()
    } else {
        let lines = read_lines(FILE_LIST);
        // Преобразуем строки в вектор
        lines.filter_map(Result::ok).collect::<Vec<String>>()
    };

    let list_words = binding.iter().combinations(dlinn_a_pasvord);

    //--ГЛАВНЫЙ ЦИКЛ
    // слушаем ответы потоков и если есть шлём новую задачу
    //----------------------------------------------------------------------------------------------
    for received in main_receiver {
        let ch = received;

        if mode == 3 {
            // Перебираем все возможные комбинации строк
            // Получаем следующую комбинацию
            // let combined_line = if let Some(vec_of_strings) = list_words.next() {
            //     let combined_line = vec_of_strings
            //         .iter()
            //         .map(|s| s.as_str())
            //         .collect::<Vec<&str>>()
            //         .join(" ");
            //     combined_line
            // } else {
            //     println!("{}{}", blue(format!("ДЛИНА ПАРОЛЯ:{} ПЕРЕБРАТА", green(dlinn_a_pasvord))), magenta(format!(" за:{:?}", start.elapsed())));
            //     dlinn_a_pasvord = dlinn_a_pasvord + 1;
            //     list_words = binding.iter().combinations(dlinn_a_pasvord);
            //     println!("{}{:?}", blue("ТЕКУЩАЯ ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));
            //     "ПЕРЕБРАТЫ ВСЕ ВОЗМОЖНЫЕ КОМБИНАЦИИ".to_string()
            // };

            //получаем случайную
            let combined_line = if let Some(random_combination) = list_words.clone().choose(&mut rng) {
                let combined_line = random_combination
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<&str>>()
                    .join(" ");
                combined_line
            } else {
                "No combinations available".to_string()
            };


            if show_info {
                //измеряем скорость и шлём прогресс
                speed = speed + 1;
                if start.elapsed() >= one_sek {
                    let mut stdout = stdout();
                    print!("{}\r{}", BACKSPACE, green(format!("SPEED:{speed}/s|{}", (format!("{}{}", prefix, combined_line)))));
                    stdout.flush().unwrap();
                    start = Instant::now();
                    speed = 0;
                }
            }

            // Отправляем новую в свободный канал
            channels[ch].send(combined_line).unwrap();

        } else {
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
                    print!("{}\r{}", BACKSPACE, green(format!("SPEED:{speed}/s|{}", (format!("{}{}", prefix, password_string)))));
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
                        println!("{}{}", blue(format!("ДЛИНА ПАРОЛЯ:{} ПЕРЕБРАТА", green(dlinn_a_pasvord))), magenta(format!(" за:{:?}", start.elapsed())));
                        dlinn_a_pasvord = dlinn_a_pasvord + 1;
                        current_combination = vec![0; dlinn_a_pasvord];
                        println!("{}{:?}", blue("ТЕКУЩАЯ ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));
                    } else {
                        println!("{}", blue(format!("ГОТОВО,перебраты все возможные из {} длинной {}", alvabet, dlinn_a_pasvord)));
                        jdem_user_to_close_programm();
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

fn print_and_save_eth(hex: String, addres: String, password_string: &String) {
    println!("{}", cyan("\n!!!!!!!!!!!!!!!!!!!!!!FOUND!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
    println!("{}{}", cyan("ПАРОЛЬ:"), cyan(password_string));
    println!("{}{}", cyan("HEX:"), cyan(hex.clone()));
    println!("{}{}", cyan("ADDRESS:"), cyan(addres.clone()));
    let s = format!("ПАРОЛЬ:{}\nHEX:{}\nADDRESS {}\n", password_string, hex, addres);
    add_v_file("FOUND.txt", s);
    println!("{}", cyan("SAVE TO FOUND.txt"));
    println!("{}", cyan("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let digest1 = Sha256::digest(data);
    let digest2 = Sha256::digest(&digest1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest2);
    result
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
pub fn get_eth_kessak_from_public_key(public_key_u: [u8; 65]) -> [u8; 20] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(public_key_u.split_first().unwrap().1);
    hasher.finalize(&mut output);

    let mut result = [0u8; 20];
    result.copy_from_slice(&output[12..32]);
    result
}

fn eth_address_to_bytes(address: &str) -> Result<[u8; 20], String> {
    let hex_str = if address.starts_with("0x") {
        &address[2..]
    } else {
        address
    };

    match hex::decode(hex_str) {
        Ok(decoded) => {
            if decoded.len() == 20 {
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(&decoded);
                Ok(bytes)
            } else {
                Err(format!("Invalid length for address: {}", address))
            }
        }
        Err(_) => Err(format!("Decoding failed for address: {}", address)),
    }
}

//bip49------------------------------------------------------
pub fn bip_49_hash160c(hash160c: [u8; 20]) -> [u8; 20] {
    let mut v = [0u8; 22]; // 22 байта, так как 1 байт для 0x00, 1 байт для 0x14 и 20 байт для hash160c
    v[0] = 0x00;
    v[1] = 0x14;
    v[2..].copy_from_slice(&hash160c);

    let digest2 = Sha256::digest(&v);
    let hash160_3 = Ripemd160::digest(&digest2);

    let mut result = [0u8; 20];
    result.copy_from_slice(&hash160_3);
    result
}

pub fn get_bip49_address(hash160_3: &[u8; 20], coin: u8) -> String {
    let mut v = [0u8; 25];
    v[0] = coin;
    v[1..21].copy_from_slice(hash160_3);

    let checksum = sha256d(&v[..21]);
    v[21..25].copy_from_slice(&checksum[0..4]);

    v.to_base58().to_string()
}
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

//если txt есть считем его строки, иначе создадим и посчитаем
pub fn get_len_find_create(coin: &str) -> usize {
    match fs::metadata(Path::new(coin)) {
        Ok(_) => {
            let lines = get_lines(coin);
            println!("{}{}", blue("НАЙДЕН ФАЙЛ:"), green(format!("{coin}:{lines} строк")));
            lines
        }
        Err(_) => {
            print!("{}{}", blue("ФАЙЛ НЕ НАЙДЕН,ИСПОЛЬЗУЕМ ВСТРОЕНЫЙ:"), green(format!("{coin}:")));
            let dockerfile = match coin {
                "btc.txt" => { include_str!("btc.txt") }
                "dogecoin.txt" => { include_str!("dogecoin.txt") }
                "eth.txt" => { include_str!("eth.txt") }
                "trx.txt" => { include_str!("trx.txt") }
                "list.txt" => { include_str!("bip39_words.txt") }
                _ => { include_str!("btc.txt") }
            };
            add_v_file(coin, dockerfile.to_string());
            let lines = get_lines(coin);
            println!("{}", green(format!("{} строк", lines)));
            lines
        }
    }
}

pub(crate) fn get_bufer_file(file: &str) -> BufReader<File> {
    let file = File::open(file).expect("Не удалось открыть файл");
    BufReader::new(file)
}

// Функция для чтения строк из файла
pub(crate) fn read_lines(file: &str) -> Lines<BufReader<File>> {
    let file = File::open(file).expect("Не удалось открыть файл");
    BufReader::new(file).lines()
}

pub(crate) fn get_lines(file: &str) -> usize {
    let file = File::open(file).expect("Unable to open the file");
    let reader = BufReader::new(file);
    let mut line_count = 0;
    for _line in reader.lines() {
        line_count += 1;
    }
    line_count
}

fn jdem_user_to_close_programm() {
    // Ожидание ввода пользователя для завершения программы
    println!("{}", blue("Нажмите Enter, чтобы завершить программу..."));
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Ошибка чтения строки");
}


//берем случайные символы из строки
fn get_rand_alfabet(alvabet: String, size_rand_alfabet: usize) -> String {
    let mut rng = thread_rng();
    let mut charset_chars: Vec<char> = alvabet.chars().collect();

    // Перемешиваем символы
    charset_chars.shuffle(&mut rng);

    // Берем первые size_rand_alfabet символов
    let selected_chars: Vec<char> = charset_chars.into_iter().take(size_rand_alfabet).collect();

    // Создаем строку из выбранных символов
    selected_chars.into_iter().collect()
}