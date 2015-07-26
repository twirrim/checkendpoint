import pytest

# We're going to fake a connection for purposes of testing.
# So far all we use is getpeercert method, so that's all we need to fake
class fake_connection(object):
    def __init__(self):
        pass

    def getpeercert(self):
        cert_details = {'notAfter': 'Dec 31 00:00:00 2015 GMT',
                        'subjectAltName': (('DNS', 'www.fake.com'),),
                        'subject': ((('countryName', u'US'),),
                                    (('stateOrProvinceName', u'Oregon'),),
                                    (('localityName', u'Springfield'),),
                                    (('organizationName', u'FakeCompany'),),
                                    (('commonName', u'fake.com'),))}
        return cert_details


def test_get_connection():
    assert False


def test_verify_hostname_with_valid_hostname():
    assert False


def test_verify_hostname_with_valid_altname():
    assert False


def test_verify_hostname_with_invalid_hostname():
    assert False


def test_expiring_certificate_with_good_cert():
    assert False


def test_expiring_certificate_with_bad_cert():
    assert False


def test_send_email():
    assert False
