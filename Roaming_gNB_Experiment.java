import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Random;



public class Roaming_gNB_Experiment {


    public static String Plaintext;
    public static String encryptedString;
    public static int PlaintextLength = 10;
    public static int RSA_Key_length = 4096;
    public static int AES_Key_Length = 256;

    public static int aes;
    public static float des;
    //public static BigInteger rsa; // initialize the val ==> NPE 
    public static BigInteger rsa; // = BigInteger.ZERO;  

    public static int PORT = 999;
    public static int sessions =20;

    public static long Start_time;
    public static long End_time;
    public static long Process_time;
    public static long Received_time;
    public static long Sending_time;

    private KeyFactory keyFactory;
    private PrivateKey privateKey;
    private PublicKey publicKey;



    public static String input;


    //Secret Key for DES
    public static final String SECRET_KEY_DES = "wo/**bhd";

    //Secret Key and Salt for the AESEncrypt() and AESDecrypt() Functions
    public static final String SECRET_KEY = "my_super_secret_key_ho_ho_ho";
    public static final String SALT = "ssshhhhhhhhhhh!!!!";


    public Roaming_gNB_Experiment()throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, Exception{

        ServerSocket serverSocket = new ServerSocket(PORT);
        Socket socket = serverSocket.accept();
        try {
            int sesCount=0;
            while (true) {
            
                //Socket socket = serverSocket.accept();

                try {
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                    encryptedString = in.readLine();

                    Received_time = System.nanoTime();

                    System.out.println("Received Message : "+encryptedString);

                    System.out.println("Message Received time : "+Received_time);


                    //AES Constructor
                    Roaming_gNB_Experiment gNBr_AES = new Roaming_gNB_Experiment(aes);

                    //DES Constructor
                    //Roaming_gNB_Experiment gNBr_DES = new Roaming_gNB_Experiment(des);

                    //RSA Constructor
                    // Assign rsa value : 
                    //rsa = BigInteger.valueOf(0);
                    //Roaming_gNB_Experiment gNBr_RSA = new Roaming_gNB_Experiment(rsa);

                    //VerticalSpace();

                } finally {
                    sesCount++;
                    if(sesCount >= sessions){
                    socket.close();
                    break;
                    }
                    
                    System.out.println("Session End :"+sesCount);
                    VerticalSpace();
                }
            }

        } finally {
            serverSocket.close();
            //socket.close();
        }



    }


    public Roaming_gNB_Experiment(BigInteger RSA) throws NoSuchAlgorithmException,IOException, InvalidKeySpecException,Exception {


        KeyFactory kf = KeyFactory.getInstance("RSA");

        InputStream is = this.getClass().getClassLoader().getResourceAsStream("PRIVATE_KEY_FILE.txt");

        String stringPrivateKey = new String(is.readAllBytes());
        is.close();

        byte[] decodedPrivateKey = Base64.getDecoder().decode(stringPrivateKey);

        KeySpec keySpecPriv = new PKCS8EncodedKeySpec(decodedPrivateKey);

        privateKey = keyFactory.generatePrivate(keySpecPriv);

        is = this.getClass().getClassLoader().getResourceAsStream("PUBLIC_KEY_FILE.txt");

        String stringPublicKey = new String(is.readAllBytes());
        is.close();

        byte[] decodedPublicKey = Base64.getDecoder().decode(stringPublicKey);

        KeySpec keySpecPub = new X509EncodedKeySpec(decodedPublicKey);

        publicKey = keyFactory.generatePublic(keySpecPub);

        System.out.println("Loaded RSA Private Key : "+privateKey);
        System.out.println("Loaded RSA Public Key : "+publicKey);

        Start_time = System.nanoTime();
        String decryptedString = RSA_decrypt(encryptedString.getBytes(),privateKey);
        End_time = System.nanoTime();
        Process_time = TimeDifference(Start_time,End_time);

        System.out.println("RSA Decrypted Text : "+decryptedString);
        System.out.println("Time taken for the Decryption Process [ms]: "+Nano2MilliSeconds(Process_time));

    }

    public Roaming_gNB_Experiment(int AES) throws IOException,NullPointerException{

        System.out.println("Received Message : "+encryptedString+" received at "+getCurrentTimestamp());

        Start_time = System.nanoTime();
        String decryptedString = AES_Decrypt(encryptedString);
        End_time = System.nanoTime();
        Process_time = TimeDifference(Start_time,End_time);
        System.out.println("AES Decrypted Text : "+decryptedString);
        System.out.println("Time taken for the Decryption Process [ms]: "+Nano2MilliSeconds(Process_time));

    }

    public Roaming_gNB_Experiment(float DES) throws IOException,NullPointerException{

        System.out.println("Received Message : "+encryptedString+" received at "+getCurrentTimestamp());

        Start_time = System.nanoTime();
        String decryptedString = DES_Decrypt(encryptedString);
        End_time = System.nanoTime();
        Process_time = TimeDifference(Start_time,End_time);
        System.out.println("DES Decrypted Text : "+decryptedString);
        System.out.println("Time taken for the Decryption Process [ms]: "+Nano2MilliSeconds(Process_time));

    }


    public static void main(String[] args) throws UnknownHostException, Exception {

        System.out.println("Roaming gNB is Functioning at..\n"+getCurrentTimestamp()+"\n\n");

        //Socket Constructor
        Roaming_gNB_Experiment gNBr = new Roaming_gNB_Experiment();


    }

    public static String RandomStringGenerator() {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = PlaintextLength;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }

    public static Timestamp getCurrentTimestamp(){
        return new Timestamp(System.currentTimeMillis());
    }

    public static Timestamp getCurrentTS(){
        return new Timestamp(System.nanoTime());
    }

    public static long Nano2MilliSeconds(long nanoTime){

        return (nanoTime/1000000);

    }

    public void VerticalSpace(){

        System.out.println("\n\n");
    }

    public static long TimeDifference(long start_time, long end_time){

        return (end_time - start_time);
    }

    public static String Hash (String message) throws NoSuchAlgorithmException {
        // getInstance() method is called with algorithm SHA-512
        MessageDigest md = MessageDigest.getInstance("SHA-512");

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the HashText
        return hashtext;
    }

    /////////////////////////// RSA /////////////////////////////////////////////
    public static byte[] RSA_encrypt (String plainText,PublicKey publicKey ) throws Exception
    {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Perform Encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes()) ;

        return cipherText;
    }

    public static String RSA_decrypt (byte[] cipherTextArray, PrivateKey privateKey) throws Exception
    {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }

    ///////////////////////////////////// AES /////////////////////////////////////////
    public static String AES_Encrypt(String strToEncrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, AES_Key_Length);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String AES_Decrypt(String strToDecrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, AES_Key_Length);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    /////////////////////////////////////////////////  DES  //////////////////////////////////////////////////////////////

    public static String DES_Encrypt(String str) {
        try {
            byte[] keyBytes = SECRET_KEY_DES.getBytes();
            byte[] content = str.getBytes();
            DESKeySpec keySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey key = keyFactory.generateSecret(keySpec);

            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(keySpec.getKey()));
            byte[] result = cipher.doFinal(content);
            return byteToHexString(result);
        } catch (Exception e) {
            System.out.println("exception:" + e.toString());
        }
        return null;
    }

    public static String DES_Decrypt(String str) {
        try {
            byte[] keyBytes = SECRET_KEY_DES.getBytes();
            byte[] content = hexToByteArray(str);
            DESKeySpec keySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey key = keyFactory.generateSecret(keySpec);

            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(keyBytes));
            byte[] result = cipher.doFinal(content);
            return new String(result);
        } catch (Exception e) {
            System.out.println("exception:" + e.toString());
        }
        return null;
    }

    private static String byteToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length);
        String sTemp;
        for (byte aByte : bytes) {
            sTemp = Integer.toHexString(0xFF & aByte);
            if (sTemp.length() < 2)
                sb.append(0);
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

    private static byte[] hexToByteArray(String inHex) {
        int hexLen = inHex.length();
        byte[] result;
        if (hexLen % 2 == 1) {
            hexLen++;
            result = new byte[(hexLen / 2)];
            inHex = "0" + inHex;
        } else {
            result = new byte[(hexLen / 2)];
        }
        int j = 0;
        for (int i = 0; i < hexLen; i += 2) {
            result[j] = (byte) Integer.parseInt(inHex.substring(i, i + 2), 16);
            j++;
        }
        return result;
    }

}
