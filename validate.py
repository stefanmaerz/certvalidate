print("hello world!!")


from libcertvalidate.cn_match import CN_match
from libcertvalidate.crl_check import crl_check
from libcertvalidate.verify import verify

f = open("cert.pem", "r")
sm7_cert=f.read()


#This works!!
#print(CN_match(sm7_cert, "Stefan Maerz"))


#This works!!
#print(crl_check(sm7_cert))

#This works!!
print(verify(sm7_cert))
