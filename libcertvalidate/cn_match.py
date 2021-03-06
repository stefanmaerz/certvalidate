from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from whoswho import who
from fuzzywuzzy import fuzz



from libcertvalidate.lib.subject_dn import subject_dn


###############################################################################################
#   CN_match function:                                                                        #
#    CN Matching verifies that the common name in the subject of a given x509 certs  is       #
#    assocaited with an identity.
#    This is a hard problem. For example, CHRISTOPHER != CHRIS, so we can't do                #
#    simple string parsing. Instead I leveraged some fuzzy text parsing to solve the problem  #
#    for me. One such tool is taken from the feild of information Theory and called           #
#    Levenshtein distance: https://en.wikipedia.org/wiki/Levenshtein_distance                 #
#    However this has the clear downside of the result being probabilistic                    #
#   PRECONDITION: Accepts a PEM ecoded certificate and one or two idnetifier strings          #
#   POSTCONDITION: Returns a bool:                                                            #
#    True = one of the identifier strings is in the Common name (valid).                      #
#    False = both of the identifier strings are not in the Common Name                        #
#            (invalid -- cross assignment has happened here).                                 #
###############################################################################################
def CN_match(certificate, identity1='', identity2=''):

    #load the pem into a certobject
    certobject = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

    #convert certobject into subject string
    subject=subject_dn(certobject.subject)
    commonName=''

    for attribute in certobject.subject:
        if attribute.oid == NameOID.COMMON_NAME:
            commonName=attribute.value


    # Use some fuzzy logic string matching libs (leveraging Levenshtein distance)
    # to determine if common name matches the identity
    # Note: this is probabilistic. So not perfect: we can't rule out the possibility
    # of cross posting certificates. However it is now unlikely, unless two
    # People have similiar names.
    if who.ratio(commonName, identity1) < 65:
        if fuzz.token_sort_ratio(commonName, identity1) < 75:
            LOG.warning: ("{0} does not match the common name for this cert: ({1})!\
                           Skipping over cert.'".format(identity1, commonName))
            return False

    return True
