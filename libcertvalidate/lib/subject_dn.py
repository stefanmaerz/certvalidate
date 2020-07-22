from cryptography.x509.oid import NameOID


###############################################################################################
#   subject_dn() function:                                                                    #
#    This addresses a shortcomming of how the python cryptography library parses x509 certs   #
#    It does not pull out data very well, so some preocessing is required.                    #
#   PRECONDITION: Accepts a crypgraphy object of attributes.                                  #
#   POSTCONDITION: Returns a string that looks like a proper subject line                     #
###############################################################################################
def subject_dn(attributes, reverse=False):

    subject = []

    # Keep track of where we find the UID and CN so we can insert into the subject attribute list
    cn = None
    cn_place = 0
    uid = None
    uid_place = 0

    if reverse:
        insert_into = 0
    else:
        insert_into = len(attributes)

    place = len(attributes)
    for attribute in attributes:
        place -= 1
        if attribute.oid == NameOID.COUNTRY_NAME:
            subject.insert(insert_into, "C=" + attribute.value)
        elif attribute.oid == NameOID.DOMAIN_COMPONENT:
            subject.insert(insert_into, "DC=" + attribute.value)
        elif attribute.oid == NameOID.ORGANIZATION_NAME:
            subject.insert(insert_into, "O=" + attribute.value)
        elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
            subject.insert(insert_into, "OU=" + attribute.value)
        elif attribute.oid == NameOID.COMMON_NAME:
            if reverse:
                cn = "CN=" + attribute.value
                cn_place = place
            else:
                subject.insert(insert_into, "CN=" + attribute.value)
        elif attribute.oid == NameOID.USER_ID:
            if reverse:
                uid = "UID=" + attribute.value
                uid_place = place
            else:
                subject.insert(insert_into, "UID=" + attribute.value)
        else:
            LOG.critical("error could not find {0}".format(attribute))
            sys.exit(1)

    if not reverse:
        return "/".join(subject)

    LOG.debug(subject)
    LOG.debug("cn value: {0}, uid value: {1}, cn_place: {2}, uid_place: {3}".format(cn, uid, cn_place, uid_place))

    # Looks like: subject= /C=US/O=U.S. Government/OU=Department of Energy/UID=89001000743346/CN=RYAN ADAMSON (Affiliate)
    # We want this to go into the mapper file: UID=89001000743346+CN=RYAN ADAMSON (Affiliate),OU=Department of Energy,O=U.S. Government,C=US

    if cn != None and uid != None:
        subject.insert(min(cn_place, uid_place), "{0}+{1}".format(uid, cn))
    elif cn != None:
        subject.insert(cn_place, cn)

    return "/".join(subject)
