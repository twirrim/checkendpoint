#!/usr/bin/env python

import socket
import ssl
import datetime
import smtplib
import argparse
import sys
import logging

# The one external library
import certifi


def get_connection(address, port):
    ''' Establishes an SSL connection to the specified address and port '''

    # Find out where certifi's root certs are
    cacerts_location = certifi.where()

    # Establish the socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Wrap up the socket with ssl
    ssl_sock = ssl.wrap_socket(s,
                               ca_certs=cacerts_location,
                               cert_reqs=ssl.CERT_REQUIRED)

    ssl_sock.connect((address, port))

    return ssl_sock


def verify_hostname(connection, address):
    '''
    Pass in the connection, along with address to verify the certificate
    matches the specified address.
    '''

    for entry in connection.getpeercert()['subject']:
        if entry[0][0] == "commonName":
            if entry[0][1] == address:
                # It's valid
                return True

    # If it's not against 'subject', it could be a 'subjectAltName'
    for entry in connection.getpeercert()['subjectAltName']:
        if entry[1] == address:
            # It's valid!
            return True

    # If we don't match either 'subject' or 'subjectAltName' it's not valid
    return False


def expiring_certificate(connection, expiry_days):
    '''
    Pass in the connection and number of days. Verify that the expiry date isn't
    within the specified number of days
    '''

    # Convert the presented certificate's expiry date into a datetime object.
    # This could be done in one line, but for readability, we'll do this over three

    expiry_date = connection.getpeercert()['notAfter']
    expiry_epoch = ssl.cert_time_to_seconds(expiry_date)
    expires = datetime.datetime.fromtimestamp(expiry_epoch)

    # Create a datetime object of the specified date
    now = datetime.datetime.now()
    specified_date = now + datetime.timedelta(days=expiry_days)

    # this evalutes to True if the certificate expires before the specified
    # expiry date.

    return expires < specified_date


def send_email(expiry_date, address, email_to, email_from):
    server = "localhost"
    # It would probably be neater if used format here
    message = """\
From: %s
To: %s
Subject: SSL certificate for %s due to expire %s


The SSL certificate for %s is due to expire on %s.  Please update and replace.
""" % (email_from, email_to, address, expiry_date, address, expiry_date)

    smtp_server = smtplib.SMTP(server)
    smtp_server.sendmail(email_from, [email_to], message)
    smtp_server.quit()


def get_arguments():
    ''' parse the command line arguments '''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", dest='address', required=True, type=str, help='The endpoint to check')
    parser.add_argument("--port", dest='port', required=True, type=int, help='The port on the endpoint to check')
    parser.add_argument("--to", dest='to_address', required=True, type=str, help='who to email in case of alert')
    parser.add_argument("--from", dest='from_address', required=True, type=str, help='who should email come from')
    parser.add_argument("--expiry", dest='expiry', required=True, type=int, help='Number of days until expiry')

    return parser.parse_args()


def main():
    ''' Tie it all together'''
    logging.basicConfig(level=logging.DEBUG)
    args = get_arguments()
    connection = get_connection(args.address, args.port)
    if verify_hostname(connection, args.address):
        logging.debug("Certificate for %s is valid" % args.address)
        if expiring_certificate(connection, args.expiry):
            logging.debug("Certificate for %s is going to expire" % args.address)
            send_email(connection.getpeercert()['notAfter'],
                       args.address,
                       args.to_address,
                       args.from_address)
        else:
            logging.debug("Certificate is valid and isn't expiring")
    else:
        # If you get here, oops.
        logging.critical("Certificate did not match host name")
        sys.exit(1)

if __name__ == '__main__':
    main()
