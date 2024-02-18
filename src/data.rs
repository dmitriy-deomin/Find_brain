pub fn get_conf_text()->String{
    let t = "3 -Длинна пароля \n\
    abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.,-=*/+{}[]<>!@#$%^&()_ -Алфавит(пробел будет добавлен)\n\
    1 -Увеличивать длинну пароля в конце(0/1)\n\
    ---------------------------\n\
    Описание:\n\
    -Поиск ведеться по старым кошелькам сжатому и несжатому (1...)\n\
    -Найденое сохраниться в FOUND.txt\n\
    !\n\
    ! Верхние строчки НАСТРОЙКИ программы вида:\n\
    ------------------------\n\
    параметр пробел описание\n\
    ------------------------\n\
    СЧИТЫВАЕТЬСЯ ТОЛЬКО ПАРАМЕТР ДО ПРОБЕЛА\n\
    !\n\
    -Задонатить:\n\
      -BTC   bc1qg89l3580w7zgqkc54kufgpdyk3ur88d772l9y0\n\
      -KASPA kaspa:qqp88q66fm3r7fe9usl36kuz9hfrw30huhjtwat8ecxdusvkh80c7zfvz6r9v\n\
      -QIWI  https://qiwi.com/n/DEOMINDMITRIY\n\
    ".to_string();
    t.to_string()
}