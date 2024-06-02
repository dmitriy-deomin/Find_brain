#[cfg(windows)]
extern crate winres;

#[cfg(windows)]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("ico.ico"); // Укажите путь к вашему файлу иконки
    res.compile().unwrap();
}
