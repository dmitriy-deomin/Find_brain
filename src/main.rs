use std::fs::{File, OpenOptions};
use std::{fs, io, thread};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, BufWriter, Lines, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
//use std::time::{Duration, Instant};
use base58::{FromBase58, ToBase58};
use bech32::{segwit, hrp};
use bincode::{deserialize_from, serialize_into};
use rand::prelude::*;
use rand::seq::SliceRandom;
use ripemd::{Ripemd160, Digest as Ripemd160Digest};
use crate::color::{blue, cyan, green, magenta, red};
use rustils::parse::boolean::string_to_bool;
use sha2::{Sha256, Digest};
use sv::util::{hash160};
use tiny_keccak::{Hasher, Keccak};
use crossbeam::channel;

#[cfg(not(windows))]
use rust_secp256k1::{PublicKey, Secp256k1, SecretKey};

#[cfg(windows)]
mod ice_library;

#[cfg(windows)]
use ice_library::IceLibrary;
use crate::util::{convert_file, is_text_file};

mod color;
mod data;
mod util;

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
    let mut rng = rand::rng();

    //количество ядер процессора
    let count_cpu = num_cpus::get();

    let cpu_core: usize = first_word(&conf[0].to_string()).to_string().parse::<usize>().unwrap();
    let mut dlinn_a_pasvord: usize = first_word(&conf[1].to_string()).to_string().parse::<usize>().unwrap();
    let mut alvabet = first_word(&conf[2].to_string()).to_string();
    let len_uvelichenie = string_to_bool(first_word(&conf[3].to_string()).to_string());
    let probel = string_to_bool(first_word(&conf[4].to_string()).to_string());
    let start_perebor = first_word(&conf[5].to_string()).to_string();
    let mode: usize = first_word(&conf[6].to_string()).to_string().parse::<usize>().unwrap();
    let comb_perebor_left_: usize = first_word(&conf[7].to_string()).to_string().parse::<usize>().unwrap();
    let minikey = string_to_bool(first_word(&conf[8].to_string()).to_string());
    let show_info = string_to_bool(first_word(&conf[9].to_string()).to_string());
    let rand_alfabet = string_to_bool(first_word(&conf[10].to_string()).to_string());
    let size_rand_alfabet = first_word(&conf[11].to_string()).to_string().parse::<usize>().unwrap();
    let time_save_tekushego_bodbora = first_word(&conf[12].to_string()).to_string().parse::<u32>().unwrap();
    //---------------------------------------------------------------------

    //если укажут меньше или 0
    let comb_perebor_left = if comb_perebor_left_ <= 0 { 1 } else { comb_perebor_left_ };

    //база со всеми адресами
    let mut database: HashSet<[u8; 20]> = HashSet::new();

    //проверим есть ли общая база
    if fs::metadata(Path::new("database.bin")).is_ok() {
        println!("{}", blue("--"));
        println!("{}", green("файл database.bin уже существует,конвертирование пропущено"));
        println!("{}", green("ЗАГРУЗКА БАЗЫ ИЗ database.bin"));
        // Загрузим HashSet из файла load_from_file-однопоточно
        database = match load_from_file("database.bin") {
            Ok(loaded_set) => {
                println!("{}", green(format!("ГОТОВО, В БАЗЕ:{} АДРЕСОВ", loaded_set.len())));
                loaded_set
            }
            Err(e) => {
                eprintln!("{}", red(format!("ОШИБКА: {}", e)));
                return;
            }
        };

        println!("{}", blue("--"));
    } else {
        println!("{}", blue("--"));
            let dir_path = "."; // Текущая директория
            let mut text_files: Vec<PathBuf> = Vec::new(); // Список для хранения путей к текстовым файлам

            if let Ok(entries) = fs::read_dir(dir_path) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if path.is_file() && is_text_file(&path) {
                            text_files.push(path); // Добавляем путь в список
                        }
                    }
                }
            } else {
                eprintln!("Failed to read directory: {}", dir_path);
            }

            if text_files.len() == 0 {
                //
                get_len_find_create("base_btc.txt");
                println!("{}",blue("Файлы рядом ненайдены,используею встроеную базу миникей:"));
                convert_file("base_btc.txt",&mut database);
            }else{
                // Выводим список найденных текстовых файлов
                println!("{}",blue("Найденые рядом файлы:"));
                for file in &text_files {
                    let fname = file.file_name().unwrap().to_str().unwrap().to_string();
                    if  fname.starts_with("base_"){
                        println!("{:?}", green(fname));
                    }
                }
                println!("{}",blue("конвертирование адресов в h160 хеш и добавление в базу"));
                for file in &text_files {
                    let fname = file.file_name().unwrap().to_str().unwrap().to_string();
                    if  fname.starts_with("base_"){
                        println!("{:?}", green(&fname));
                        convert_file(fname.as_str(),&mut database);
                    }
                }
            }



        //проверка есть ли в базе вообще чего
        if database.len() == 0 {
            println!("{}", red("БАЗА ПУСТА\nпоместите рядом с программой текстовые файлы со списком адресов,\
            названия файлов должны начинаться с base_:\nbase_btc.txt,base_eth.txt,base_trx.txt\n(любое количество файлов)"));
            jdem_user_to_close_programm();
            return;
        }


        // Сохраним HashSet в файл
        println!("{}", blue("СОХРАНЕНИЕ ОБШЕЙ БАЗЫ В database.bin"));
        match save_to_file(&database, "database.bin") {
            Ok(_) => println!("{}", blue("ГОТОВО")),
            Err(e) => eprintln!("{}", red(format!("ОШИБКА {}", e))),
        }
        println!("{}", blue("--"));
    }

    //ИНфо блок
    //||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
    println!("{}", blue("************************************"));
    println!("{}{}{}", blue("КОЛИЧЕСТВО ЯДЕР ПРОЦЕССОРА:"), green(cpu_core), blue(format!("/{count_cpu}")));
    println!("{}{}", blue("ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));

    //алфавит
    //-------------------------------------------------------------------------
    let alfabet_ili_list;
    //пустой список
    let mut lines = vec!["первый".to_string()];
    if alvabet == "list.txt" {
        println!("{}", blue("ИСПОЛЬЗОВАНИЕ list.txt ВМЕСТО АЛФАВИТА"));
        get_len_find_create(FILE_LIST);
        //если включенно рандомный список
        let list = read_lines(FILE_LIST);
        println!("{}", blue("-ОБРАБОТКА list.txt"));
        // Преобразуем строки в вектор
        lines =list.filter_map(Result::ok).collect::<Vec<String>>();
        if rand_alfabet {lines = get_rand_list(lines,size_rand_alfabet)};
        if rand_alfabet {
            println!("{}{}", blue("СЛУЧАЙНЫЕ ИЗ СПИСКА:"), green("ВКЛЮЧЕННО"));
            println!("{}{}", blue("-КОЛИЧЕСТВО СЛУЧАЙНЫХ ИЗ СПИСКА:"), green(size_rand_alfabet));
            println!("{}{}", blue("-СПИСОК:"), green(lines.join(" ")));
        };
        println!("{}{}", blue("НАЧАЛО ПЕРЕБОРА:"), green(start_perebor.clone()));
        if mode == 0 {
            println!("{}{}", blue("УВЕЛИЧЕНИЕ ДЛИННЫ ПАРОЛЯ:"), green(len_uvelichenie.clone()));

        }
        println!("{}", blue("-ГОТОВО"));

        alfabet_ili_list = false;
    } else {
        alfabet_ili_list = true;
        alvabet = if rand_alfabet {
            let rndalf = get_rand_alfabet(alvabet, size_rand_alfabet);
            println!("{}{}", blue("СЛУЧАЙНЫЕ ИЗ АЛФАВИТА:"), green("ВКЛЮЧЕННО"));
            println!("{}{}", blue("-КОЛИЧЕСТВО СЛУЧАЙНЫХ ИЗ АЛФАВИТА:"), green(size_rand_alfabet));
            println!("{}{}", blue("-АЛФАВИТ:"), green(&rndalf));
            rndalf
        } else {
            println!("{}{}", blue("СЛУЧАЙНЫЕ ИЗ АЛФАВИТА:"), green("ВЫКЛЮЧЕННО"));
            if alvabet == "0" {
                println!("{}{}", blue("АЛФАВИТ:"), green("ВСЕ ВОЗМОЖНЫЕ"));
            } else {
                println!("{}{}", blue("АЛФАВИТ:"), green(&alvabet));
            }
            alvabet
        };
        println!("{}{}", blue("ДОБАВЛЕНИЕ ПРОБЕЛА:"), green(probel.clone()));

        //если включен режим миникей
        if minikey {
            println!("{}{}", blue("S В НАЧАЛЕ(для поиска миникей и пропуск невалидных ):"), green("ВКЛЮЧЕННО"));
            //проверим правельная ли указана длинна для первой серии 22
            if dlinn_a_pasvord !=22{
                //если че просто покажем предупреждение красным
                println!("{}", red(format!("ВЫСТАВНЕННА ДЛИННА:{dlinn_a_pasvord} , У МИНИКЕЙ ПАРОЛЕЙ ПЕРВОЙ СЕРИИ ДЛИННА 22 СИМВОЛА")));
            }
            //отнимем 1 из общей длинны для первой S
            dlinn_a_pasvord = dlinn_a_pasvord - 1;
        };

        if mode == 0 {
            println!("{}{}", blue("УВЕЛИЧЕНИЕ ДЛИННЫ ПАРОЛЯ:"), green(len_uvelichenie.clone()));
            println!("{}{}", blue("НАЧАЛО ПЕРЕБОРА:"), green(start_perebor.clone()));
        }
        if mode == 2 {
            println!("{}{}", blue("КОЛИЧЕСТВО ЗНАКОВ ПЕРЕБОРА СЛЕВА:"), green(comb_perebor_left));
        }
    }
    //-------------------------------------------------------------------------------
    if mode>2{
        println!("{}", red("!!!"));
        println!("{}", red(format!("{mode} ТАКОГО РЕЖИМА РАБОТА ПОКА НЕТ\nесть:\n0 последовательный перебор\n1 рандом\n2 комбинированый")));
        println!("{}", red("!!!"));
        jdem_user_to_close_programm();
        return;
    }
    println!("{}{}", blue("РЕЖИМ ГЕНЕРАЦИИ ПАРОЛЯ:"), green(get_mode_text(mode)));

    if show_info {
        println!("{}{}", blue("ОТОБРАЖЕНИЕ СКОРОСТИ И ТЕКУЩЕГО ПОДБОРА:"), green("ВКЛЮЧЕННО"));
    } else {
        println!("{}{}", blue("ОТОБРАЖЕНИЕ СКОРОСТИ И ТЕКУЩЕГО ПОДБОРА:"), green("ОТКЛЮЧЕННО"));
        println!("{}{}", blue("-ВРЕМЯ АВТОСОХРАНЕНИЯ ТЕКУЩЕГО ПОДБОРА:"), green(time_save_tekushego_bodbora.clone()));
    }

    println!("{}", blue("************************************"));
    //|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||

    //главные каналы
    let (main_sender, main_receiver) = channel::unbounded();
    // Запускаем выбраное количество потоков(ядер) постоянно работающих
    //----------------------------------------------------------------------------------
    //будет храниться список запушеных потоков(каналов для связи)
    let mut channels = Vec::new();

    let database = Arc::new(database);

    for ch in 0..cpu_core {
        //создаём для каждого потока отдельный канал для связи
        let (sender, receiver) = channel::unbounded();

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
                //let password_string: String = "SG64GZqySYwBm9KxE3wJ29".to_string();

                //если включен режим миникей проверим на валидность ключ
                if minikey {
                    // Получаем хеш SHA-256 из пароля
                    let mut sha256 = Sha256::new();
                    sha256.update(password_string.as_str().to_owned()+"?");

                    // Проверяем, что первый байт равен нулю
                    if sha256.finalize().0[0] == 0{
                        // Получаем хеш SHA-256 из пароля
                        let mut sha256 = Sha256::new();
                        sha256.update(password_string.as_str());
                        let h = sha256.finalize().0;

                        // Получаем публичный ключ для разных систем, адрюха не дружит с ice_library
                        //------------------------------------------------------------------------
                        #[cfg(windows)]
                        let pk_u= ice_library.privatekey_to_publickey(&h);

                        #[cfg(not(windows))]{
                            let secret_key = SecretKey::from_slice(&h).expect("32 bytes, within curve order");
                            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                            let pk_u = public_key.serialize_uncompressed();
                        };
                        //----------------------------------------------------------------------------

                        //получем из них хеш160
                        let h160u = hash160(&pk_u[0..]).0;

                        //проверка наличия в базе BTC uncompres
                        if database_cl.contains(&h160u) {
                            //пропустим ложное
                            if password_string != "инициализация потока, пароль <ничто> найденые адреса вне диапазона, хз" {
                                let address_btc = get_legacy(h160u, LEGACY_BTC);
                                let address = format!("\n-BTC uncompres:{}\n", address_btc);
                                let private_key_u = hex_to_wif_uncompressed(&h.to_vec());
                                print_and_save(hex::encode(&h), &private_key_u, address, &password_string);
                            }
                        }


                    }
                }else {
                    // Получаем хеш SHA-256 из пароля
                    let mut sha256 = Sha256::new();
                    sha256.update(password_string.as_str());
                    let h = sha256.finalize().0;

                    // Получаем публичный ключ для разных систем, адрюха не дружит с ice_library
                    //------------------------------------------------------------------------
                    #[cfg(windows)]
                    let (pk_u, pk_c) = {
                        let p = ice_library.privatekey_to_publickey(&h);
                        (p, ice_library.publickey_uncompres_to_compres(&p))
                    };

                    #[cfg(not(windows))]
                    let (pk_u, pk_c) = {
                        // Создаем секретный ключ из байта
                        let secret_key = SecretKey::from_slice(&h).expect("32 bytes, within curve order");
                        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                        (public_key.serialize_uncompressed(), public_key.serialize())
                    };
                    //----------------------------------------------------------------------------


                    //получем из них хеш160
                    let h160c = hash160(&pk_c[0..]).0;

                    //проверка наличия в базе BTC compress
                    if database_cl.contains(&h160c) {
                        //пропустим ложное
                        if password_string != "инициализация потока, пароль <ничто> найденые адреса вне диапазона, хз"{
                            let address_btc = get_legacy(h160c, LEGACY_BTC);
                            let address_btc_bip84 = segwit::encode(hrp::BC, segwit::VERSION_0, &h160c).unwrap();
                            let address_doge = get_legacy(h160c, LEGACY_DOGE);
                            let address = format!("\n-BTC compress:{}\nBTC bip84:{}\n-DOGECOIN compress:{}", address_btc, address_btc_bip84, address_doge);
                            let private_key_c = hex_to_wif_compressed(&h.to_vec());
                            print_and_save(hex::encode(&h), &private_key_c, address, &password_string);
                        }
                    }

                    //получем из них хеш160
                    let h160u = hash160(&pk_u[0..]).0;

                    //проверка наличия в базе BTC uncompres
                    if database_cl.contains(&h160u) {
                        //пропустим ложное
                        if password_string != "инициализация потока, пароль <ничто> найденые адреса вне диапазона, хз" {
                            let address_btc = get_legacy(h160u, LEGACY_BTC);
                            let address_doge = get_legacy(h160u, LEGACY_DOGE);
                            let address = format!("\n-BTC uncompres:{}\n-DOGECOIN uncompres:{}", address_btc, address_doge);
                            let private_key_u = hex_to_wif_uncompressed(&h.to_vec());
                            print_and_save(hex::encode(&h), &private_key_u, address, &password_string);
                        }
                    }

                    let bip49_hash160 = bip_49_hash160c(h160c);

                    //проверка наличия в базе BTC bip49 3.....
                    if database_cl.contains(&bip49_hash160) {
                        //пропустим ложное
                        if password_string != "инициализация потока, пароль <ничто> найденые адреса вне диапазона, хз" {
                            let address_btc = get_bip49_address(&bip49_hash160, BIP49_BTC);
                            let address_doge = get_bip49_address(&bip49_hash160, BIP49_DOGE);
                            let address = format!("\n-BTC bip49:{}\n-DOGECOIN bip49:{}", address_btc, address_doge);
                            let private_key_c = hex_to_wif_compressed(&h.to_vec());
                            print_and_save(hex::encode(&h), &private_key_c, address, &password_string);
                        }
                    }


                    if database_cl.contains(&get_eth_kessak_from_public_key(pk_u)) {
                        //пропустим ложное
                        if password_string != "инициализация потока, пароль <ничто> найденые адреса вне диапазона, хз" {
                            let adr_eth = hex::encode(get_eth_kessak_from_public_key(pk_u));
                            let adr_trx = get_trx_from_eth(adr_eth.clone());
                            print_and_save_eth(hex::encode(&h), format!("\n-ETH 0x{adr_eth}\n-TRX {adr_trx}"), &password_string);
                        }
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
    //let mut start = Instant::now();
    //let mut speed: u32 = 0;
   // let one_sek = Duration::from_secs(1);

    let alfabet_all = if alvabet == "0".to_string() { true } else { false };

    //если указано добавлять пробел добавим
    let spase = if probel { " " } else { "" };
    let alvabet = format!("{alvabet}{spase}");

    let charset_chars: Vec<char> = alvabet.chars().collect();
    let charset_len = if alfabet_ili_list { charset_chars.len() } else { lines.len() };

    // Инициализация вектора с резервированием памяти
    let mut current_combination: Vec<usize> = Vec::with_capacity(dlinn_a_pasvord);

    //состовляем начальную позицию
    current_combination.extend(vec![0; dlinn_a_pasvord]);

    if alfabet_ili_list{
        //заполняем страртовыми значениями для строки
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
                None => { rng.random_range(0..charset_len) }
            };
            current_combination[d] = position;
        }
    }else{
        // Разбиение строки на слова
        let start_perebor_list: Vec<&str> =start_perebor.split(',').collect();
        // Заполняем стартовыми значениями для фраз
        for d in comb_perebor_left..dlinn_a_pasvord {
            if let Some(&ch) = start_perebor_list.get(d) {
                // Находим позицию слова в charset_chars
                let position = lines.iter().position(|c| c == ch).unwrap_or_else(|| {
                    eprintln!("Слово: '{}' из *начала перебора* не найдено, установлено первое из алфавита", ch);
                    0
                });
                current_combination[d] = position;
            } else {
                current_combination[d] = rng.random_range(0..charset_len);
            }
        }
    }

    //-----------------------------------------------------------------------------------

    //--ГЛАВНЫЙ ЦИКЛ
    // слушаем ответы потоков и если есть шлём новую задачу
    let mut password_string = "stroka".to_string();
    //----------------------------------------------------------------------------------------------
    for received in main_receiver {
        let ch = received;

        if alfabet_ili_list {
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
                    //если включенно увеличение длинны увеличим иначе, выйдем из цикла
                    if len_uvelichenie {
                       // println!("{}{}", blue(format!("ДЛИНА ПАРОЛЯ:{}", green(dlinn_a_pasvord))), magenta(format!(" ПЕРЕБРАТА за:{:?}", start.elapsed())));
                        dlinn_a_pasvord = dlinn_a_pasvord + 1;

                        // Увеличиваем ёмкость вектора, если длина пароля изменилась
                        current_combination.reserve(dlinn_a_pasvord - current_combination.len());

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
                    current_combination[f] = rng.random_range(0..charset_len);
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
                            current_combination[f] = rng.random_range(0..charset_len);
                        }
                    }
                }
            }

            // следующая комбинация пароля если алфавит пустой будем по всем возможным перебирать
            password_string = current_combination.iter()
                .map(|&idx| if alfabet_all { char::from_u32(idx as u32).unwrap_or(' ') } else { charset_chars[idx] })
                .collect();

            password_string = if minikey { format!("S{password_string}") } else { password_string };
        } else {
            // последовательный перебор
            if mode == 0 {
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
                    //если включено увеличение длинны увеличим иначе, выйдем из цикла
                    if len_uvelichenie {
                      //  println!("{}{}", blue(format!("ДЛИНА ПАРОЛЯ:{}", green(dlinn_a_pasvord))), magenta(format!(" ПЕРЕБРАТА за:{:?}", start.elapsed())));
                        dlinn_a_pasvord = dlinn_a_pasvord + 1;

                        // Увеличиваем ёмкость вектора, если длина пароля изменилась
                        current_combination.reserve(dlinn_a_pasvord - current_combination.len());

                        current_combination = vec![0; dlinn_a_pasvord];
                        println!("{}{:?}", blue("ТЕКУЩАЯ ДЛИНА ПАРОЛЯ:"), green(dlinn_a_pasvord));
                    } else {
                        println!("{}", blue(format!("ГОТОВО,перебраты все возможные из {} длинной {}", alvabet, dlinn_a_pasvord)));
                        jdem_user_to_close_programm();
                        break;
                    }
                }

                let mut s = String::new();
                for i in current_combination.iter() {
                    s.push_str(lines.get(*i).unwrap());
                    s.push(' ');
                }

                password_string = s.trim().to_string();
            }

            //случайный набор строк по длинне
            if mode == 1 {
                let mut k = String::new(); // Создаем пустую строку
                for _ in 0..dlinn_a_pasvord {
                    let rand = lines.get(rng.random_range(0..lines.len())).unwrap();
                    k.push_str(rand);
                    k.push(' '); // Добавляем разделитель между словами
                }
                k.pop(); // Удаляем последний пробел
                password_string = k;
            }

            //комбенированый режим
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
                            current_combination[f] = rng.random_range(0..charset_len);
                        }
                    }
                }
                let mut s = String::new();
                for i in current_combination.iter() {
                    s.push_str(lines.get(*i).unwrap());
                    s.push(' ');
                }

                password_string = s.trim().to_string();
            }
        }
        // speed = speed + 1;
        // if show_info {
        //     //измеряем скорость и шлём прогресс
        //     if start.elapsed() >= one_sek {
        //         let mut stdout = stdout();
        //         print!("{}\r{}", BACKSPACE, green(format!("SPEED:{speed}/s|{}", format!("{}", password_string))));
        //         stdout.flush().unwrap();
        //         start = Instant::now();
        //         speed = 0;
        //     }
        //   } else {
        //     // или через некоторое время будем сохранять в файл текущий подбор
        //     if speed > time_save_tekushego_bodbora {
        //         println!("{}{}", blue("ТЕКУЩИЙ ПОДБОР:"), green(password_string.as_str()));
        //
        //         let alf = if alfabet_ili_list { alvabet.clone() } else { format!("List.txt Длинна{}", dlinn_a_pasvord) };
        //
        //         add_v_file("ТЕКУЩИЙ ПОДБОР.txt", format!("{} {}\n", password_string.as_str(), alf));
        //         speed = 0;
        //     }
        // }


        // Отправляем новую в свободный канал
        channels[ch].send(password_string.clone()).unwrap();
    }
}
//------------------------------------------------------------------------------------

fn get_mode_text(mode: usize) -> String {
    match mode {
        0 => "ПОСЛЕДОВАТЕЛЬНЫЙ ПЕРЕБОР".to_string(),
        1 => "РАНДОМ".to_string(),
        2 => "КОМБИНИРОВАННЫЙ".to_string(),
        _ => { red("ХЗ").to_string() }
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
    let s = format!("ПАРОЛЬ:{}\nHEX:{}\nPRIVATE KEY: {}\nADDRESS {}\n\n", password_string, hex, key, addres);
    add_v_file("FOUND.txt", s);
    println!("{}", cyan("СОХРАНЕНО В FOUND.txt"));
    println!("{}", cyan("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
}

fn print_and_save_eth(hex: String, addres: String, password_string: &String) {
    println!("{}", cyan("\n!!!!!!!!!!!!!!!!!!!!!!FOUND!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
    println!("{}{}", cyan("ПАРОЛЬ:"), cyan(password_string));
    println!("{}{}", cyan("HEX:"), cyan(hex.clone()));
    println!("{}{}", cyan("ADDRESS:"), cyan(addres.clone()));
    let s = format!("ПАРОЛЬ:{}\nHEX:{}\nADDRESS {}\n\n", password_string, hex, addres);
    add_v_file("FOUND.txt", s);
    println!("{}", cyan("СОХРАНЕНО В FOUND.txt"));
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
                "base_btc.txt" => { include_str!("base_btc.txt") }
                "list.txt" => { include_str!("list.txt") }
                _ => { include_str!("base_btc.txt") }
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
    let mut charset_chars: Vec<char> = alvabet.chars().collect();

    // Перемешиваем символы
    charset_chars.shuffle(&mut rand::rng());

    // Берем первые size_rand_alfabet символов
    let selected_chars: Vec<char> = charset_chars.into_iter().take(size_rand_alfabet).collect();

    // Создаем строку из выбранных символов
    selected_chars.into_iter().collect()
}

//составляем случайный список из полного
fn get_rand_list(mut list:  Vec<String>, size_rand_alfabet: usize) -> Vec<String> {
    // Перемешиваем символы
    list.shuffle(&mut rand::rng());

    // Берем первые size_rand_alfabet символов
    let selected_chars: Vec<String> = list.into_iter().take(size_rand_alfabet).collect();

    // Создаем строку из выбранных символов
    selected_chars.into_iter().collect()
}



//сохранение и загрузка базы из файла
fn save_to_file(set: &HashSet<[u8; 20]>, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    match File::create(file_path) {
        Ok(file) => {
            let writer = BufWriter::new(file);
            match serialize_into(writer, set) {
                Ok(_) => Ok(()),
                Err(e) => Err(Box::new(e)),
            }
        }
        Err(e) => Err(Box::new(e)),
    }
}

fn load_from_file(file_path: &str) -> Result<HashSet<[u8; 20]>, Box<dyn std::error::Error>> {
    match File::open(file_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            match deserialize_from(reader) {
                Ok(set) => Ok(set),
                Err(e) => Err(Box::new(e)),
            }
        }
        Err(e) => Err(Box::new(e)),
    }
}