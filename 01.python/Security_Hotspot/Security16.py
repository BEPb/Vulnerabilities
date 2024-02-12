###### Расширение файлов архива без контроля потребления ресурсов является чувствительным к безопасности.

'''Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Успешные атаки Zip Bomb происходят, когда приложение расширяет ненадежные архивные файлы, не контролируя размер расширенных данных, что может привести к отказу в обслуживании. Zip-бомба обычно представляет собой вредоносный архивный файл размером в несколько килобайт сжатых данных, преобразованный в гигабайты несжатых данных. Чтобы достичь такого экстремального коэффициента сжатия, злоумышленники сжимают ненужные данные (например, длинную строку повторяющихся байтов).



###### Спросите себя, есть ли

Архивы для расширения ненадежны и:

     Проверка количества записей в архиве не производится.
     Проверка общего размера несжатых данных не производится.
     Соотношение между сжатой и несжатой записью архива не проверяется.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода


For tarfile module:'''

import tarfile

tfile = tarfile.open("TarBomb.tar")
tfile.extractall('./tmp/')  # Sensitive
tfile.close()

For zipfile module:

import zipfile

zfile = zipfile.ZipFile('ZipBomb.zip', 'r')
zfile.extractall('./tmp/') # Sensitive
zfile.close()





### Рекомендуемые методы безопасного кодирования

    ''' Определяйте и контролируйте соотношение между сжатыми и несжатыми данными. Как правило, степень сжатия данных для большинства легальных архивов составляет от 1 до 3.
     Определите и контролируйте порог максимального общего размера несжатых данных.
     Подсчитайте количество записей файлов, извлеченных из архива, и прервите извлечение, если их количество превышает заданный порог, в частности, не рекомендуется рекурсивно расширять архивы (запись архива также может быть архивом).

Соответствующее решение

For tarfile module:'''

import tarfile

THRESHOLD_ENTRIES = 10000
THRESHOLD_SIZE = 1000000000
THRESHOLD_RATIO = 10

totalSizeArchive = 0;
totalEntryArchive = 0;

tfile = tarfile.open("TarBomb.tar")
for entry in tfile:
  tarinfo = tfile.extractfile(entry)

  totalEntryArchive += 1
  sizeEntry = 0
  result = b''
  while True:
    sizeEntry += 1024
    totalSizeArchive += 1024

    ratio = sizeEntry / entry.size
    if ratio > THRESHOLD_RATIO:
      # ratio between compressed and uncompressed data is highly suspicious, looks like a Zip Bomb Attack
      break

    chunk = tarinfo.read(1024)
    if not chunk:
      break

    result += chunk

  if totalEntryArchive > THRESHOLD_ENTRIES:
    # too much entries in this archive, can lead to inodes exhaustion of the system
    break

  if totalSizeArchive > THRESHOLD_SIZE:
    # the uncompressed data size is too much for the application resource capacity
    break

tfile.close()

# For zipfile module:

import zipfile

THRESHOLD_ENTRIES = 10000
THRESHOLD_SIZE = 1000000000
THRESHOLD_RATIO = 10

totalSizeArchive = 0;
totalEntryArchive = 0;

zfile = zipfile.ZipFile('ZipBomb.zip', 'r')
for zinfo in zfile.infolist():
    print('File', zinfo.filename)
    data = zfile.read(zinfo)

    totalEntryArchive += 1

    totalSizeArchive = totalSizeArchive + len(data)
    ratio = len(data) / zinfo.compress_size
    if ratio > THRESHOLD_RATIO:
      # ratio between compressed and uncompressed data is highly suspicious, looks like a Zip Bomb Attack
      break

    if totalSizeArchive > THRESHOLD_SIZE:
      # the uncompressed data size is too much for the application resource capacity
      break

    if totalEntryArchive > THRESHOLD_ENTRIES:
      # too much entries in this archive, can lead to inodes exhaustion of the system
      break

zfile.close()

'''See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-409 - Improper Handling of Highly Compressed Data (Data Amplification)
    bamsoftware.com - A better Zip Bomb'''















