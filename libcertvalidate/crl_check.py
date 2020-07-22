#!/usr/bin/env python3
import urllib.request
import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes

from libcertvalidate.lib.crl_distribution_point import parse_CRL_distribution_point
from libcertvalidate.lib.subject_dn import subject_dn
from libcertvalidate.lib.validate_crl_signature import validate_CRL_signature



LOG = logging.getLogger(__name__)
###############################################################################################
#   crl_check() function:                                                                     #
#    Checks a certificate against its Certificate Revocation List (CRL)                       #
#   PRECONDITION: Accepts PEM encoded cert.                                                   #
#   POSTCONDITION: Returns a bool:                                                            #
#                   - True = cert is revoked                                                  #
#                   - False = cert is not revoked,                                            #
###############################################################################################
def crl_check(certificate):
    crl_distribution_point = parse_CRL_distribution_point(certificate)
    if crl_distribution_point == 1:
        return 0  #this happens when ITSD has improperly formatted certs.
                  #We can either reject the use of these certs or do
                  #"opportunistic" crypto..... :sadpanda:

    certobject = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

    #TODO: Add exceptio handler here to detect if the urllib thing fails.
    try:
        response = urllib.request.urlopen(crl_distribution_point)
    except Exception as err:
        LOG.warning("Could not download CRL from %s. Debug info: %s", crl_distribution_point, err)
        return 1

    der_crl_data = response.read() # a `bytes` object

    crl = x509.load_der_x509_crl(der_crl_data, default_backend())

    sub_dn_cert = subject_dn(certobject.subject)
    if validate_CRL_signature(der_crl_data):
        #https://cryptography.io/en/latest/x509/reference/?highlight=crl#cryptography.x509.CertificateRevocationList.get_revoked_certificate_by_serial_number
        #The Python NoneType indicates no hit in the CRL
        if crl.get_revoked_certificate_by_serial_number(certobject.serial_number) is None:
            LOG.info("%s's certificate has not been revoked.", sub_dn_cert)
            return 0
        LOG.error("%s's certificate has been revoked.", sub_dn_cert)
        return 1
    LOG.error("Unable to validate CRL signature for %s' certificate.", sub_dn_cert)
    return 1



#Below is the list of CRLs for NCCS user certificates in the MFA4 repo FYI
'''mac111578:enrollees sm7$ cat output.txt | sort | uniq -c | sort -n
   1                   URI:http://crl.ornl.gov/ORNL%20CA%201%20v1.crl
  10                   URI:http://crlint.ornl.gov/ornl/ORNLCASC(1).crl
  15                   URI:ldap:///CN=ORNLCASC(1),CN=ORNLCASC,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=ornl,DC=gov?certificateRevocationList?base?objectClass=cRLDistributionPoint
  30                   URI:http://crlint.ornl.gov/ornl/ORNLCASC(2).crl
  60                   URI:http://sspweb.managed.entrust.com/CRLs/EMSSSPCA2.crl
  60                   URI:ldap://sspdir.managed.entrust.com/cn=WinCombined2,ou=Entrust%20Managed%20Services%20SSP%20CA,ou=Certification%20Authorities,o=Entrust,c=US?certificateRevocationList;binary
  '''

    #proxy = {'http': 'http://proxy.ccs.ornl.gov:3128/'}
