
import rsa
def gen_Asym_key():
    public_key, private_key = rsa.newkeys(1824)
    return public_key, private_key