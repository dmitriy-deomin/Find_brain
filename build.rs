fn main() {
    //для иконки в винде
    if cfg!(target_os = "windows") {
        extern crate winres;
        let mut res = winres::WindowsResource::new();
        res.set_icon("ico.ico");
        res.compile().unwrap();
    }
}