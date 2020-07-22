import OpenSSL
import sys

from OpenSSL import crypto
from asn1crypto.core import Sequence


###############################################################################################
#   parse_CRL_distribution_point() function:                                                  #
#     Parses out the URL where we can download the CRL from.                                  #
#   PRECONDITION: Accepts PEM encoded cert.                                                   #
#   POSTCONDITION: Returns a string which is the URL                                          #
###############################################################################################

def parse_CRL_distribution_point(certificate):

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)

    # firstly, parse out the x509 extension "X509v3 CRL Distribution Points"
    # the "CRL Distribution Point" is a fancy way of saying the URL where we
    # can download the CRL from
    try:
        # iterate over all x509 extensions
        for x509_extension_index in range(cert.get_extension_count()):

            # if the x509 extension is named "crlDistributionPoints", then we have a hit!
            if cert.get_extension(x509_extension_index).get_short_name() == 'crlDistributionPoints'.encode():
                ext = cert.get_extension(x509_extension_index)
                break

    except:
        LOG.warning("This error message seems bad, but really isnt.")
        # some x509 extensions ITSD has do not have a name and traceback.
        # I don't know why the hell they do this.
        # we don't care about unnamed extensions anywho.
    data=ext.get_data()


    # ASN deserialization
    parsed = Sequence.load(data)
    serialized = parsed.dump()


    # Could not figure out proper deserialization; using this jank to get a string.
    # some magic, courtesey of stack overflow...
    # this takes the bytes object and converts into a string and parses the URL out
    # https://stackoverflow.com/questions/606191/convert-bytes-to-a-string
    stream = [parsed[0].contents]
    PY3K = sys.version_info >= (3, 0)

    lines = []
    for line in stream:
        if not PY3K:
            lines.append(line)
        else:
            lines.append(line.decode('utf-8', 'backslashreplace'))

    try:
        CRL_distribution_point="http"+lines[0].split("http")[1].split(".crl")[0]+".crl"
    except Exception as e:
        #LOG.warning("Invalid CRL distribution Point for user: {0}. More debug info here: {1}. You Had one job ITSD.".format(subject_dn(certobject.subject), e))
        LOG.warning("Invalid CRL distribution Point for user: {0}. More debug info here: {1}. You Had one job ITSD.".format("...", e))
        return(1)
    return(CRL_distribution_point)
