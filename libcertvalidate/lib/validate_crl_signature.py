import os
import pkg_resources
import OpenSSL



#TODO: Parse this from a yaml config file
CA_TRUST = [("ORNLCAROOT.crt", "ORNLCASC.crt"),
            ("ORNLCAROOT02.crt", "ORNLCASC02.crt"),
            ("Entrust2019root.pem", "Entrust2019SSA.pem"),
            ("Entrust2025root.pem", "Entrust2025SSA.pem"),
            ("Entrust2029root.pem", "Entrust2029SSA.pem"),
            ("ORNLRootCAv1.pem", "ORNLCA1v1.pem"),
            ("ORNLRootCAv1.pem", "ORNLCA2v1.pem")]
CA_DIR = 'cadir'

###############################################################################################
#   validate_CRL_signature() function:                                                        #
#     Validates the digital signature of the CRL.                                             #
#   PRECONDITION: Accepts DER formatted CRL.                                                  #
#   POSTCONDITION: Returns a bool:                                                            #
#       True: Valid                                                                           #
#       False: invalid                                                                        #
###############################################################################################
def validate_CRL_signature(der_crl_data):

    valid_signature=False

    for CA in CA_TRUST:
        # grab the issuing CA PEM Cert from file
        file = open(os.path.join(CA_DIR, CA[1]), mode='r')
        cacert = file.read()
        file.close()

        # load the DER encoded CRL into a pyOpenSSL crl object
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, der_crl_data) #resp.content)

        # Export CRL as a cryptography CRL.
        crl_crypto = crl.to_cryptography()

        # Load CA CERTIFICATE into the CA cert object
        ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cacert.encode())

        # Get CA Public Key as _RSAPublicKey
        ca_pub_key = ca.get_pubkey().to_cryptography_key()

        # Validate CRL against CA
        valid_signature = crl_crypto.is_signature_valid(ca_pub_key)

        if valid_signature:
            break

    return valid_signature
