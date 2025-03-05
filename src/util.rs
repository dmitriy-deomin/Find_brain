use std::collections::HashSet;
use std::io::BufRead;
use base58::FromBase58;
use bech32::segwit;
use crate::color::{blue, green, red};
use crate::get_bufer_file;

pub fn is_text_file(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        if ext == "txt" {
            return true;
        }
    }
    false
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
fn bip84_to_h160(address: String) -> [u8; 20] {
    let (_hrp, _version, program) = segwit::decode(&address).expect("valid address");

    if program.len() == 20 {
        // Convert Vec<u8> to [u8; 20]
        let mut h160 = [0u8; 20];
        h160.copy_from_slice(&program);
        h160
    } else {
        [0u8; 20]
    }
}
pub fn convert_file(file_name:&str, database:&mut HashSet<[u8; 20]>){

    //ищем в списке нужные делаем им харакири и ложим обрубки в файл
    let mut all_size = 0;
    for (index, address) in get_bufer_file(file_name).lines().enumerate() {
        let address = address.expect("Ошибка чтения адреса со строки");

        //конвертирование в хеш
        //адреса с bc1...
        let binding = if address.starts_with("bc1") {
            bip84_to_h160(address)
        }else {
            //если eth
            if address.len()==40 {
                match eth_address_to_bytes(&address) {
                    Ok(bytes) => {
                        bytes
                    }
                    Err(e) => {
                        eprintln!("{}", red(format!("ОШИБКА, АДРЕС НЕ ВАЛИДЕН строка: {} {}", index + 1, address)));
                        continue;
                    }
                }
            }else {
                //адреса 1.. 3... и трон
                match address.from_base58() {
                    Ok(value) => {
                        let mut a: [u8; 20] = [0; 20];
                        if value.len() >= 21 {
                            a.copy_from_slice(&value.as_slice()[1..21]);
                            a
                        } else {
                            eprintln!("{}", red(format!("ОШИБКА, АДРЕС НЕ ВАЛИДЕН строка: {} {}", index + 1, address)));
                            continue; // Skip this address and move to the next
                        }
                    }
                    Err(_) => {
                        eprintln!("{}", red(format!("ОШИБКА ДЕКОДИРОВАНИЯ В base58 строка: {} {}", index + 1, address)));
                        continue; // Skip this address and move to the next
                    }
                }
            }
        };

        //добавление в базу
        database.insert(binding);
        all_size = all_size + 1;

    }
    println!("{}", blue(format!("конвертировано адресов в h160:{}",green(all_size.to_string()))));
    println!("{}", blue(format!("Всего в базе :{}",green(database.len().to_string()))));

    //-----------------------------------------------------------------------------------------------
    println!("{}", blue("--"));
}