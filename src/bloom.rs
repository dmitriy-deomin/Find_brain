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

pub(crate) fn load_bloom() ->Bloom<Vec<u8>> {

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

        println!("{}", blue("БАЗА ЗАГРУЖЕНА ИЗ БЛУМА:"));
        println!("{}{}", blue("BTC:"),green(mb.len_btc));
        database
    } else {

        //BTC---------------------------------------------------------------------------------
        //проверяем есть ли файл(создаём) и считаем сколько строк
        let len_btc_txt = get_len_find_create("btc.txt");

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
                    if let Err(e) = writeln!(file, "{:?}", a) {
                        eprintln!("Не удалось записать в файл: {}", e);
                    }
                } else {
                    eprintln!("{}", red(format!("ОШИБКА,АДРЕСС НЕ ВАЛИДЕН строка:{}", index + 1)));
                }

            }
        }
        let len_btc = get_lines("btc_h160.txt");
        println!("{}", blue(format!("конвертировано адресов в h160:{}/{}", green(len_btc_txt), green(len_btc))));
        //-------------------------------------------------------------------------------------------------------







        //запихавание в блуум-------------------------------------------------------
        let fp_rate:f64 = 0.0000000000000000000000000000000000001;
        let mut database = Bloom::new_for_fp_rate(len_btc, fp_rate);

        println!("{}", blue("ЗАПИСЬ ДАННЫХ В БЛУМ.."));
        for line in get_bufer_file("btc_h160.txt").lines() {
            match line {
                Ok(l) => {
                    // Добавление строки в Bloom фильтр
                    database.set(&l.as_bytes().to_vec());
                }
                Err(e) => { println!("ошибка записи в блум{}", e) }
            }
        }
        //---------------------------------------------------------------------



        //удаление временного h160
        //-----------------------------------------------------------------------
        match fs::remove_file("btc_h160.txt") {
            Ok(()) => println!("{}",blue("ВРЕМЕННЫЙ btc_h160.txt УДАЛЕН")),
            Err(e) => println!("ошибка удаления btc_h160.txt: {}", e),
        }
        match fs::remove_file("eth_h160.txt") {
            Ok(()) => println!("{}",blue("ВРЕМЕННЫЙ eth_h160.txt УДАЛЕН")),
            Err(e) => println!("ошибка удаления eth_h160.txt: {}", e),
        }
        //-----------------------------------------------------------

        //сохранение данных блума
        //--------------------------------------------------------------------
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
        //-----------------------------------------------------------------

        database
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
        Ok(_) => {
            let lines =get_lines(coin);
            println!("{}{}", blue("НАЙДЕН ФАЙЛ:"),green(format!("{coin}:{lines} строк")));
            lines
        }
        Err(_) => {
            print!("{}{}", blue("ФАЙЛ НЕ НАЙДЕН,ИСПОЛЬЗУЕМ ВСТРОЕНЫЙ:"),green(format!("{coin}:")));
            let dockerfile = match coin {
                "btc.txt" => { include_str!("btc.txt") }
                "eth.txt" => { include_str!("eth.txt") }
                _ => { include_str!("btc.txt") }
            };
            add_v_file(coin, dockerfile.to_string());
            let lines =get_lines(coin);
            println!("{}",green(format!("{} строк",lines)));
            lines
        }
    }
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

pub(crate)fn get_bufer_file(file: &str) -> BufReader<File> {
    let file = File::open(file).expect("Не удалось открыть файл");
    BufReader::new(file)
}
