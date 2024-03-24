import sys
import subprocess
import re
import json

from urllib.request import urlopen
from prettytable import PrettyTable

reIP = re.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")


def get_ip_trace_rt(name: str):
    """
    Функция для выполнения трассировки маршрута до указанного домена или IP-адреса.
    Возвращает список IP-адресов, пройденных при трассировке.
    """
    process = subprocess.Popen(["tracert", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = process.communicate()[0].decode("cp866")
    return reIP.findall(result)


def is_grey_ip(ip: str):
    """
    Функция для проверки, является ли IP-адрес "серым" (например, принадлежащим локальной сети).
    Возвращает True, если IP-адрес серый, и False в противном случае.
    """
    ip_parts = list(map(int, ip.split('.')))
    if ((ip_parts[0] == 10) or
            (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or
            (ip_parts[0] == 192 and ip_parts[1] == 168) or
            (ip_parts[0] == 100 and 64 <= ip_parts[1] <= 127)):
        return True

    else:
        return False


def parse(site, reg):
    """
    Функция для поиска и извлечения информации из текста сайта с помощью регулярного выражения.
    Возвращает найденное значение или пустую строку.
    """
    try:
        a = reg.findall(site)
        return a[0]

    except IndexError:
        return ''


def get_info_by_ip(ip):
    """
    Функция для получения информации о IP-адресе с помощью запроса к сервису ip-api.com.
    Возвращает кортеж с IP-адресом, AS Name, Country и Provider.
    """
    if not is_grey_ip(ip):
        try:
            with urlopen(f"http://ip-api.com/json/{ip}") as response:
                site_data = response.read().decode('utf-8')
                site_json = json.loads(site_data)

                ip = site_json["query"]
                as_name = site_json["as"][2:7]
                country = site_json["countryCode"]
                provider = site_json["org"]

                return ip, as_name, country, provider

        except:
            return ip, '', '', ''


def create_table(ips):
    """
    Функция для создания красивой таблицы с информацией об IP-адресах.
    Принимает список IP-адресов и выводит таблицу с данными о каждом IP-адресе.
    """
    th = ["№", "IP", "AS Name", "Country", "Provider"]
    td_data = []
    number = 1
    for i in ips:
        info = get_info_by_ip(i)

        if info is not None and info[1]:
            td_data.append(number)
            td_data.extend(info)
            number += 1

    columns = len(th)
    table = PrettyTable(th)

    while td_data:
        table.add_row(td_data[:columns])
        td_data = td_data[columns:]

    print(table)


def main():
    """
    На вход подаётся доменное имя или IP-адрес из аргументов командной строки,
    выполняет трассировку маршрута до указанного адреса
    и выводит информацию об IP-адресах в таблице
    (ip, название автономной системы, страна, провайдер)
    """
    if len(sys.argv) < 2:
        print('Usage: python main.py <domain name or ip>')
        return
    ips = get_ip_trace_rt(sys.argv[1])
    create_table(ips)


if __name__ == '__main__':
    main()
