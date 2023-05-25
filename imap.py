import argparse
import getpass
import imaplib
import email
import sys
from email.header import decode_header


def decode_str(s):
    """
    Декодирует строку, используя подходящую кодировку
    """
    if not s:
        return s
    decoded_s = decode_header(s)
    decoded_parts = []
    for part, encoding in decoded_s:
        if encoding:
            decoded_parts.append(part.decode(encoding))
        else:
            decoded_parts.append(str(part))
    return ' '.join(decoded_parts)


def get_attachments(msg):
    """
    Получает информацию обо всех вложениях в сообщении
    """
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() is not None:
            filename = decode_str(part.get_filename())
            if filename is None:
                filename = "unknown"
            size = len(part.get_payload(decode=True))
            attachments.append((filename, size))
    return attachments


def login(username, password, server, use_ssl):
    """
    Подключается к почтовому серверу
    """
    if use_ssl:
        conn = imaplib.IMAP4_SSL(server)
    else:
        conn = imaplib.IMAP4(server)
    conn.login(username, password)
    return conn


def fetch_emails(conn, start, end):
    """
    Получает список писем с сервера
    """
    conn.select('INBOX')
    _, data = conn.search(None, 'ALL')
    email_ids = data[0].split()
    if start is None:
        start = 1
    if end is None:
        end = len(email_ids)
    else:
        end = min(end, len(email_ids))
    for i in range(start - 1, end):
        email_id = email_ids[i]
        _, data = conn.fetch(email_id, '(RFC822)')
        msg = email.message_from_bytes(data[0][1])
        yield msg


def print_emails(emails):
    """
    Выводит информацию о письмах
    """
    print('{:<30} {:<30} {:<30} {:<30} {:<30} {:<15} {:<30}'.format('Кому',
                                                                    'От кого',
                                                                    'Тема',
                                                                    'Дата',
                                                                    'Размер',
                                                                    'Количество вложений',
                                                                    'Вложения'))

    for msg in emails:
        to = decode_str(msg['To']) if msg['To'] else ""
        frm = decode_str(msg['From']) if msg['From'] else ""
        subject = decode_str(msg['Subject']) if msg['Subject'] else ""
        date = decode_str(msg['Date']) if msg['Date'] else ""
        size = len(msg.as_bytes())
        attachments = get_attachments(msg)
        attachment_count = len(attachments)
        attachment_names = ', '.join([attach[0] for attach in attachments])
        attachment_sizes = ', '.join([str(attach[1]) for attach in attachments])
        print(
            '{:<30} {:<30} {:<30} {:<30} {:<30} {:<15} {:<30}'.format(to, frm,
                                                                      subject,
                                                                      date,
                                                                      size,
                                                                      attachment_count,
                                                                      '{} ({})'.format(
                                                                          attachment_names,
                                                                          attachment_sizes) if attachment_count > 0 else '-').encode(
                'utf-8').decode(sys.stdout.encoding))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Получает информацию о письмах в почтовом ящике')
    parser.add_argument('-s', '--server', type=str, required=True,
                        help='Адрес (или доменное имя) IMAP-сервера в формате адрес[:порт] (порт по умолчанию 143)')
    parser.add_argument('-u', '--user', type=str, required=True,
                        help='Имя пользователя')
    parser.add_argument('-n', '--number', type=int, nargs=2,
                        help='Диапазон писем (начальный и конечный индексы)')
    parser.add_argument('--ssl', action='store_true',
                        help='Разрешить использование SSL, если сервер поддерживает (по умолчанию не использовать)')
    args = parser.parse_args()

    server = args.server
    use_ssl = args.ssl
    username = args.user

    start = None
    end = None
    if args.number:
        start, end = args.number

    password = getpass.getpass()
    conn = login(username, password, server, use_ssl)
    emails = fetch_emails(conn, start, end)
    print_emails(emails)
    conn.close()

# Пример ввода для запуска скрипта: python imap.py -s imap.gmail.com -u your_address@gmail.com -n 1 10 --ssl
