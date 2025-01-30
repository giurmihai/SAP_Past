**Keytool command:**

**Se genereaza keystore cu un pair de cheie publica + cheie privata**
```
keytool.exe -genkey -keyalg RSA -alias ismkey1 -keypass passism1 -storepass passks -keystore ismkeystore.ks -dname "cn=ISM, ou=ISM, o=IT&C Security Master, c=RO"
```

**Se genereaza certificatul (se exporta public key)**
```
keytool.exe -export -alias ismkey1 -file ISMCertificateX509.cer -keystore ismkeystore.ks -storepass passks
```

> CN : CommonName. OU : OrganizationalUnit. O : Organization. L : Locality

**Keytool adding certificate:**
```
keytool -importcert -file certificate.cer -keystore keystore.jks -alias "ismasero"    **(SE IMPORTA CHEIA PUBLICA)**
```

**Note:**
> keytool.exe -genkey -keyalg RSA -alias ismkey1 -keypass passism1 -storepass passks -keystore ismkeystore.ks -dname "cn=ISM, ou=ISM, o=IT&C Security Master, c=RO"

> Can be seen 2 levels of protection: -keypass: parola la cheia privata, -storepass: parola la store-ul care contine mai multe chestii. Ca o baza de date.

Exporting the private key from the keystore
```
openssl pkcs12 -in ismkeystore.p12 -nocerts -nodes -out private_key.pem
```
```
This command is converting a Java KeyStore (JKS) format (keystore.jks) to a PKCS#12 format (keystore.p12). PKCS#12 is a standard format that can store both private keys and certificates in a single file. 
keytool -v -importkeystore -srckeystore keystore.jks -destkeystore keystore.p12 -deststoretype PKCS12
```
