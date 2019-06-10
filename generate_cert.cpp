#include<bits/stdc++.h>
#include<openssl/pem.h>
#include<openssl/x509.h>

EVP_PKEY * generate_key()
{
    EVP_PKEY * pkey = EVP_PKEY_new();

    RSA * rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);

    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        std::cerr << "Unable to generate 2048-bit RSA key." << std::endl;
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

X509 * generate_x509(EVP_PKEY * pkey)
{
    X509 * x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, pkey);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME * name = X509_get_subject_name(x509);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"US",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"GOOGLE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"GOOGLE", -1, -1, 0);

    X509_set_issuer_name(x509, name);

    if(!X509_sign(x509, pkey, EVP_sha1()))
    {
        std::cerr << "Error signing certificate." << std::endl;
        X509_free(x509);
        return NULL;
    }

    return x509;
}

bool write_to_disk(EVP_PKEY * pkey, X509 * x509)
{

    FILE * pkey_file = fopen("key.pem", "wb");

    bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);

    FILE * x509_file = fopen("cert.pem", "wb");

    ret = PEM_write_X509(x509_file, x509);
    fclose(x509_file);


    return true;
}

int main(int argc, char ** argv)
{

    EVP_PKEY * pkey = generate_key();
    if(!pkey)
        return 1;

    X509 * x509 = generate_x509(pkey);
    if(!x509)
    {
        EVP_PKEY_free(pkey);
        return 1;
    }

    bool ret = write_to_disk(pkey, x509);
    EVP_PKEY_free(pkey);
    X509_free(x509);

    if(ret)
    {
        std::cout << "Success!" << std::endl;
        return 0;
    }
    else
        return 1;
}
