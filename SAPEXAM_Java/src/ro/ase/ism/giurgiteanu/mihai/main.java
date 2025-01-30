
import java.security.Signature;
import java.security.cert.CertificateException;


public static String getHexString(byte[] value) {
    StringBuilder result = new StringBuilder();
    result.append("0x");
    for(byte b : value) {
        result.append(String.format(" %02X", b));
    }
    return result.toString();
}

public static void decrypt(
        String filename,
        String outputFile,
        String password,
        String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {


    //IV the cipher file at the beginning

    File inputFile = new File(filename);
    if(!inputFile.exists()) {
        throw new UnsupportedOperationException("Missing file");
    }
    File outFile = new File(outputFile);
    if(!outFile.exists()) {
        outFile.createNewFile();
    }

    FileInputStream fis = new FileInputStream(inputFile);
    FileOutputStream fos = new FileOutputStream(outFile);

    Cipher cipher = Cipher.getInstance(algorithm + "/CBC/NoPadding");

    //IV
    byte[] iv = new byte[cipher.getBlockSize()];
    iv[10] = (byte)0xff;
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    //


    SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);

    cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

    byte[] buffer = new byte[cipher.getBlockSize()];
    int noBytes = 0;

    while(true) {
        noBytes = fis.read(buffer);
        if(noBytes == -1) {
            break;
        }
        byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
        fos.write(cipherBlock);
    }
    byte[] lastBlock = cipher.doFinal();
    fos.write(lastBlock);

    fis.close();
    fos.close();
}



public static File Cerinta1() throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
    final String refBase64 = "pP+QN170gTIZzl/AfxFscko/OnJ3Gb9y1274ZTCpu/c=";

    File location = new File("C:\\Users\\giurg\\Desktop\\SAPHavingFun\\exams\\january\\users2");
    if(!location.exists()) {
        throw new UnsupportedOperationException("FOLDER is not there");
    }

    int counter =0;
    File[] files =  location.listFiles();
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    var base64Encoder = Base64.getEncoder();
    byte[] buffer = new byte[8];
    int bytesRead;
    for(File file : files) {
        try(var fis = new FileInputStream(file))
        {
            while((bytesRead = fis.read(buffer))!=-1)
            {
                sha256.update(buffer, 0, bytesRead);
            }
            if(base64Encoder.encodeToString(sha256.digest()).equals(refBase64))
            {
                System.out.printf("The user file name is: %s%n", file.getName());
                return file;

            }
        }

    }
    System.out.println("Count no files: " + counter);
    return null;
}

public static String Cerinta2(File fisier, String parola) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
    System.out.println(fisier.getName() + " " + parola);
    decrypt(fisier.getAbsolutePath(),"C:\\Users\\giurg\\Desktop\\SAPHavingFun\\exams\\january\\users2\\pula.txt", parola,"AES");
    File file = new File("C:\\Users\\giurg\\Desktop\\SAPHavingFun\\exams\\january\\users2\\pula.txt");
    FileReader fileReader = new FileReader(file);
    BufferedReader bufferedReader = new BufferedReader(fileReader);

    String line;
    while((line = bufferedReader.readLine()) != null) {
        System.out.println("File line: " + line);
        return line;
    }

    bufferedReader.close();
    return null;
}





public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, KeyStoreException, UnrecoverableKeyException, CertificateException, SignatureException {
    // Cerinta 1
    File fisier =  Cerinta1();
    System.out.println("Ola:" + fisier.getName());
    // Cerinta 2
    final String filePass = "userfilepass@9]9";
    String parola = Cerinta2(fisier, filePass);
    // Cerinta 3
    System.out.println("Mamamama: " + parola);
    int WrittenBytes = Cerinta3(parola);
    System.out.println(WrittenBytes);
    // Cerinta 4
    Cerinta4(WrittenBytes);

}

public static byte[] signFile(String filename, PrivateKey key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    File file = new File(filename);
    if(!file.exists()) {
        throw new FileNotFoundException();
    }
    FileInputStream fis = new FileInputStream(file);

    byte[] fileContent = fis.readAllBytes();

    fis.close();

    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(key);

    signature.update(fileContent);
    return signature.sign();
}

public static void Cerinta4(int writtenBytes) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
    String filePath = "C:\\Users\\giurg\\Desktop\\SAPHavingFun\\exams\\january\\users2\\pulaBinary.bin";
    //Keystore get
    File file = new File("C:\\Users\\giurg\\Desktop\\SAPHavingFun\\exams\\january\\ismkeystore.ks");
    if(!file.exists()) {
        throw new UnsupportedOperationException("Missing key store file");
    }

    FileInputStream fis = new FileInputStream(file);

    KeyStore ks = KeyStore.getInstance("pkcs12");
    ks.load(fis, "passks".toCharArray());

    fis.close();
    //
    //Keystore list
    System.out.println("Key store content: ");
    Enumeration<String> aliases = ks.aliases();

    while(aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        System.out.println("Entry: " + alias);
        if(ks.isCertificateEntry(alias)) {
            System.out.println("-- Is a certificate");
        }
        if(ks.isKeyEntry(alias)) {
            System.out.println("-- Is a key pair");
        }
    }
    //
//Get private Key
    if(ks == null) {
        throw new UnsupportedOperationException("Missing Key Store");
    }
    if(ks.containsAlias("ismkey1")) {
        PrivateKey privIsm1 = (PrivateKey) ks.getKey("ismkey1", "passism1".toCharArray());
        byte[] signature =
                signFile(filePath, privIsm1);
        System.out.println("Digital signature value: ");
        System.out.println(getHexString(signature));

        //Write Signature file
        String signaturePath = filePath + ".sig";
        FileOutputStream fos = new FileOutputStream(signaturePath);
        fos.write(signature);
        fos.close();

        System.out.println("Signature saved to: " + signaturePath);

    }
    //
}

private static int Cerinta3(String password) throws NoSuchAlgorithmException {
//    System.out.println("Parola este:" + parola);
    String saltedPass = password+"ism2021";
    System.out.println(saltedPass);

    int bytesWritten;
    PBEKeySpec pbeKeySpec = new PBEKeySpec(saltedPass.toCharArray(), password.getBytes(), 150, 160);
    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    String filePath="C:\\Users\\giurg\\Desktop\\SAPHavingFun\\exams\\january\\users2\\pulaBinary.bin";
    try(var fos = new FileOutputStream(filePath))
    {
        byte[] toWrite = secretKeyFactory.generateSecret(pbeKeySpec).getEncoded();
        fos.write(toWrite);
        bytesWritten = toWrite.length;
    } catch (FileNotFoundException e) {
        throw new RuntimeException(e);
    } catch (IOException e) {
        throw new RuntimeException(e);
    } catch (InvalidKeySpecException e) {
        throw new RuntimeException(e);
    }


    //Verification
    PBEKeySpec pbeKeySpec2 = new PBEKeySpec(("root@8#7@9%8@6@3"+"ism2021").toCharArray(), password.getBytes(), 150, 160);
    try(var fis = new FileInputStream(filePath))
    {
        byte[] buffer = new byte[20];
        int bytesRead = fis.read(buffer);
        if(bytesRead != 20)
        {
            throw new UnsupportedOperationException("The file is not there.");
        }
        if(Arrays.equals(secretKeyFactory.generateSecret(pbeKeySpec2).getEncoded(), buffer))
        {
            System.out.println("The password is correct.");
        }
        else
        {
            System.out.println("The password is incorrect.");
        }
    } catch (FileNotFoundException e) {
        throw new RuntimeException(e);
    } catch (IOException e) {
        throw new RuntimeException(e);
    } catch (InvalidKeySpecException e) {
        throw new RuntimeException(e);
    }
    return bytesWritten;
}



