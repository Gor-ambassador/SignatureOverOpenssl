# SignatureOverOpenssl
GitHub repository for the ПАЗИ laboratory work

## Сборка проекта:
mkdir build
cd build
cmake ..
make

## Для работы программе необходимо задать три флага:
-m - режим работы (sign - подписать файл, verify - проверить подпись)
-f - путь до подписываемого файла
-k - путь до ключа (секретного при выработке подписи / открытого при проверке подписи)

## Генерация секретного ключа:
openssl genpkey -algorithm RSA -out private.pem

## Генерация открытого ключа:
openssl rsa -pubout -in private.pem -out public.pem

## Подписать файл:
./signature_tool -m sign -f ../file_to_sign -k ./private.pem

### Подпись <filename>.sig создается в том же каталоге, где лежит подписываемый документ.

## Проверить подпись файла:
./signature_tool -m verify -f ../impdoc -k ./public.pem
