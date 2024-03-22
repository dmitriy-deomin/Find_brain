use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use bloomfilter::Bloom;
use serde::{Deserialize, Serialize};
use crate::{add_v_file, lines_from_file};
use crate::color::{blue, green, red};
use std::io::Write;
use base58::FromBase58;

#[derive(Debug, Serialize, Deserialize)]
pub struct MetaDataBloom {
    pub(crate) len_btc: u64,
    number_of_bits: u64,
    number_of_hash_functions: u32,
    sip_keys: [(u64, u64); 2],
}

pub(crate) fn load_bloom() -> (Bloom<Vec<u8>>, MetaDataBloom) {

    //если блум есть загружаем его
    let d_b = Path::new("data");
    let m_b = Path::new("mdata");
    if d_b.exists() && m_b.exists() {
        //чтение из файла настроек блума
        let string_content = fs::read_to_string("mdata").unwrap();
        let mb: MetaDataBloom = serde_json::from_str(&string_content).unwrap();

        //чтение данных блума
        let f: Vec<u8> = get_file_as_byte_vec("data");
        let fd: Vec<u8> = bincode::deserialize(&f[..]).unwrap();
        let database = Bloom::from_existing(&fd, mb.number_of_bits, mb.number_of_hash_functions, mb.sip_keys);

        println!("{}{}", blue("БАЗА ЗАГРУЖЕНА ИЗ БЛУМА:"), green(mb.len_btc));
        (database, mb)
    } else {
        //проверяем есть ли файл(создаём) и считаем сколько строк
        //BTC-------------------------------------------------------
        print!("{}", blue("address.txt addresses:"));
        let len_btc_txt = get_len_find_create("address.txt");
        println!("{}", green(len_btc_txt));

        //провереряем если файл с обрубками уже есть то скажем что пропускаем и дальше идём
        if fs::metadata(Path::new("btc_h160.txt")).is_ok() {
            println!("{}", red("файл btc_h160.txt уже существует,конвертирование пропущено"));
        } else {
            println!("{}", blue("конвертирование адресов в h160 и сохранение в btc_h160.txt"));
            //конвертируем в h160 и записываем в файл рядом
            //создаём файл
            let mut file = match File::create("btc_h160.txt") {
                Ok(f) => f,
                Err(e) => {
                    panic!("Не удалось создать файл: {}", e)
                }
            };
            //ищем в списке нужные делаем им харакири и ложим обрубки в файл
            for line in get_bufer_file("address.txt").lines() {
                match line {
                    Ok(l) => {
                        let binding = l.from_base58().unwrap();
                        let h160 = &binding.as_slice()[1..=20];
                        if let Err(e) = writeln!(file, "{:?}", h160.to_vec()) {
                            eprintln!("Не удалось записать в файл: {}", e);
                        }
                    }
                    Err(e) => { println!("error read btc.txt{}", e) }
                }
            }
        }
        let len_btc = get_lines("btc_h160.txt");
        println!("{}", blue(format!("конвертировано адресов в h160:{}/{}", len_btc_txt, len_btc)));
        //----------------------------------------------------------


        //база для поиска общие в txt
        let num_items_txt = len_btc_txt;
        let num_items = len_btc;

        println!("{}{}", blue("TOTAL ADDRESS .txt:"), green(num_items_txt));

        //запихавание в блуум-------------------------------------------------------
        let fp_rate = 0.00000000001;
        let mut database = Bloom::new_for_fp_rate(num_items, fp_rate);

        println!("{}", blue("LOAD AND SAVE BLOOM BTC"));
        for line in get_bufer_file("btc_h160.txt").lines() {
            match line {
                Ok(l) => {
                    database.set(&l.as_bytes().to_vec()); // Добавление только первых 20 байт из строки в Bloom фильтр
                }
                Err(e) => { println!("error{}", e) }
            }
        }
        //---------------------------------------------------------------------

        //сохранение данных блума
        let vec = database.bitmap();
        let encoded: Vec<u8> = bincode::serialize(&vec).unwrap();
        fs::write("data", encoded).unwrap();

        //сохранение в файл настроек блума
        let save_meta_data = MetaDataBloom {
            len_btc: len_btc as u64,
            number_of_bits: database.number_of_bits(),
            number_of_hash_functions: database.number_of_hash_functions(),
            sip_keys: database.sip_keys(),
        };
        let sj = serde_json::to_string(&save_meta_data).unwrap();
        fs::write("mdata", sj).unwrap();
        (database, save_meta_data)
    }
}

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");
    buffer
}

pub(crate) fn load_db(coin: &str) -> Vec<String> {
    let file_content = lines_from_file(coin).expect("kakoyto_pizdec");
    file_content
}

//если txt есть считем его строки, иначе создадим и посчитаем
pub fn get_len_find_create(coin: &str) -> usize {
    match fs::metadata(Path::new(coin)) {
        Ok(_) => { get_lines(coin) }
        Err(_) => {
            let dockerfile = match coin {
                "address.txt" => { include_str!("address.txt") }
                _ => { include_str!("address.txt") }
            };
            add_v_file(coin, dockerfile.to_string());
            get_lines(coin)
        }
    }
}

fn get_lines(file: &str) -> usize {
    let file = File::open(file).expect("Unable to open the file");
    let reader = BufReader::new(file);
    let mut line_count = 0;
    for _line in reader.lines() {
        line_count += 1;
    }
    line_count
}

fn get_bufer_file(file: &str) -> BufReader<File> {
    let file = File::open(file).expect("Не удалось открыть файл");
    BufReader::new(file)
}
