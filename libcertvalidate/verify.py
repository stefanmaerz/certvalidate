import logging
import os
import subprocess

#TODO: Parse this from a yaml config file
CA_TRUST = [("ROOT1.crt", "LEAF1.crt"),
            ("ROOT2.crt", "LEAF2.crt"),
CA_DIR = 'cadir'


LOG = logging.getLogger(__name__)

###############################################################################################
#   verify function:                                                                          #
#    Cryptographically verifies the chain of trust for a given certificate to validate whether#
#    or not it is a properly issued Certificate.                                              #
#   PRECONDITION: Accepts a PEM ecoded certificate.                                           #
#   POSTCONDITION: Returns 3 things:                                                          #
#   1) a Boolean Value:                                                                       #
#    True = a valid certificate.                                                              #
#    False = a Invalid certificate                                                            #
#   2) found_ca: a string which contains the name of the CA which issued this cert            #
#   3) openssl_error: the output of openssl if it returns an error code                       #
###############################################################################################
def verify(certificate):
    LOG.debug("Trying to verify against known CAs")
    valid = False
    found_ca = None
    openssl_error = None
    for cert_auth, intermediate in CA_TRUST:
        command = [
            "openssl", "verify", "-CAfile",
            os.path.join(CA_DIR, cert_auth), "-untrusted",
            os.path.join(CA_DIR, intermediate),
        ]

        LOG.debug(" ".join(command))
        verify_proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )
        out, err = verify_proc.communicate(certificate.encode())

        verify_proc.wait()

        # if "%s: OK" % temp_file.name in out.decode():
        if "stdin: OK" in out.decode():
            LOG.info("Successful verification against known CAs")
            found_ca = cert_auth
            valid = True
            break
        # local issuer is a error that usually just means that the intermediate is wrong, which is expected and unhelpful
        if "OK" in out.decode() and "unable to get local issuer certificate" not in out.decode():
            openssl_error = out
            valid = False
        else:
            LOG.debug(out)
            LOG.debug(err)
            valid = False

    return valid, found_ca, openssl_error
