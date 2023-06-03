import os
import argparse
import getpass
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders


def get_files(directory):
    return [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and f.endswith(('.png', '.jpg', '.jpeg'))]


def main():
    parser = argparse.ArgumentParser(description='Send all images in a directory as email attachments.')
    parser.add_argument('--ssl', action='store_true', help='Use SSL connection.')
    parser.add_argument('-s', '--server', type=str, required=True, help='SMTP server address in format address[:port]. Default port is 25.')
    parser.add_argument('-t', '--to', type=str, required=True, help='Recipient email address.')
    parser.add_argument('-f', '--fromm', type=str, default='', help='Sender email address. Default is <>.')
    parser.add_argument('--subject', type=str, default='Happy Pictures', help='Optional email subject. Default is "Happy Pictures".')
    parser.add_argument('--auth', action='store_true', help='Ask for SMTP authorization.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display communication with the server.')
    parser.add_argument('-d', '--directory', type=str, default='.', help='Directory with images. Default is $pwd.')
    args = parser.parse_args()

    if ':' in args.server:
        server, port = args.server.split(':')
        port = int(port)
    else:
        server = args.server
        port = 465 if args.ssl else 25

    files = get_files(args.directory)
    if not files:
        print('No images found in the directory.')
        return

    msg = MIMEMultipart()
    msg['From'] = args.fromm
    msg['To'] = args.to
    msg['Subject'] = args.subject

    for file in files:
        try:
            with open(file, 'rb') as fp:
                img = MIMEBase('image', 'jpeg')
                img.set_payload(fp.read())
                encoders.encode_base64(img)
            img.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file))
            msg.attach(img)
        except Exception as e:
            print(f'Unable to open one of the files: {e}')
            return

    try:
        if args.ssl:
            server = smtplib.SMTP_SSL(server, port)
        else:
            server = smtplib.SMTP(server, port)
            server.starttls()
        if args.verbose:
            server.set_debuglevel(1)
        if args.auth:
            server.login(args.fromm, getpass.getpass())
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f'Unable to send the email: {e}')


if __name__ == '__main__':
    main()

# Пример запуска через терминал:
# python smtp-mime.py --ssl -s smtp.gmail.com:465 -t recipient@gmail.com -f sender@gmail.com --auth -v -d full_address_to_directory