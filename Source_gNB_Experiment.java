import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Random;

public class Source_gNB_Experiment {

    public static String Plaintext;
    public static int PlaintextLength = 16; //bytes
    public static int RSA_Key_length = 4096; //bits
    public static int AES_Key_Length = 256; //bits

    public static int aes;
    public static float des;
    public static BigInteger rsa;

    public static int PORT = 999;
    public static String roamAddress ="192.168.1.102";
    public static String mqttIP ="192.168.1.100";
    public static int ses_count = 20;

    public static long Start_time;
    public static long End_time;
    public static long Process_time;
    public static long Received_time;
    public static long Sending_time;

    public static String encryptedString;


    //Secret Key for DES
    public static final String SECRET_KEY_DES = "wo/**bhd";

    //Secret Key and Salt for the AESEncrypt() and AESDecrypt() Functions
    public static final String SECRET_KEY = "my_super_secret_key_ho_ho_ho";
    public static final String SALT = "ssshhhhhhhhhhh!!!!";



    public Source_gNB_Experiment(String[] args) throws IOException, NoSuchAlgorithmException, NullPointerException, Exception {

        InetAddress ipAddress = InetAddress.getLocalHost();
        //Socket Connection Establishment
        Socket socket = new Socket(roamAddress , PORT);

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        for(int i=1;i<= ses_count;i++){
            
            System.out.print("Session :"+i+"\n");
            String ses_str = String.valueOf(i)+"-"+"AES";
            MQTT_send("1",ses_str); //status ==> 1
        

        //%%%%%%%%%%%%%%%%%%%%%% AES ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

        //AES Constructor
        Source_gNB_Experiment gNBs_AES = new Source_gNB_Experiment(aes);

        //%%%%%%%%%%%%%%%%%%%%%% DES ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

        //DES Constructor
        //Source_gNB_Experiment gNBs_DES = new Source_gNB_Experiment(des);

        //%%%%%%%%%%%%%%%%%%%%%% RSA ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

        //RSA Constructor
        //Source_gNB_Experiment gNBs_RSA = new Source_gNB_Experiment(rsa);


        //%%%%%%%%%%%%%%%%%%%%%%  MESSAGE SENDING  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

        out.println(encryptedString);

        Sending_time = System.nanoTime();

        System.out.println("Message Sent time [ns]: "+Sending_time);

        //Process_time = TimeDifference(Start_time,End_time);

        //System.out.println("Time taken for the Encryption Process [ms]: "+Nano2MilliSeconds(Process_time));

        VerticalSpace();
        MQTT_send("0",ses_str); //status ==> 0
        }
        MQTT_send("0","End"); 
    }



    public Source_gNB_Experiment(int AES) throws IOException, NoSuchAlgorithmException, NullPointerException {

        Start_time = System.nanoTime();
        encryptedString = AES_Encrypt(Plaintext);
        End_time = System.nanoTime();

        System.out.println("AES Encrypted String : "+encryptedString);
        System.out.println("Size of the Encrypted String : "+encryptedString.getBytes().length);

        Process_time = TimeDifference(Start_time,End_time);

        System.out.println("Time taken for the Encryption Process [ms]: "+Nano2MilliSeconds(Process_time));

        VerticalSpace();

        //Decryption Process
        //Start_time = System.nanoTime();
        //String decryptedString = AES_Decrypt(encryptedString);
        //End_time = System.nanoTime();
        //Process_time = TimeDifference(Start_time,End_time);
        //System.out.println("AES Decrypted Text : "+decryptedString);
        //System.out.println("Time taken for the Decryption Process [ms]: "+Nano2MilliSeconds(Process_time));

    }

    public Source_gNB_Experiment(float DES) throws IOException, NoSuchAlgorithmException, NullPointerException {

        Start_time = System.nanoTime();
        encryptedString = DES_Encrypt(Plaintext);
        End_time = System.nanoTime();

        System.out.println("DES Encrypted String : "+encryptedString);
        System.out.println("Size of the Encrypted String : "+encryptedString.getBytes().length);

        Process_time = TimeDifference(Start_time,End_time);

        System.out.println("Time taken for the Encryption Process [ms]: "+Nano2MilliSeconds(Process_time));

        VerticalSpace();

    }

    public Source_gNB_Experiment(BigInteger RSA) throws IOException, NoSuchAlgorithmException, NullPointerException,Exception {


        // Get an instance of the RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_Key_length);

        // Generate the KeyPair
        KeyPair keyPair = keyPairGenerator.generateKeyPair();



        // Get the public and private key
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("RSA Private Key : "+privateKey);
        System.out.println("RSA Public Key : "+publicKey);

        //Creating the Files for storing the Private and Public Keys
        File privateKeyFile = new File("PRIVATE_KEY_FILE.txt");
        privateKeyFile.createNewFile();

        File publicKeyFile = new File("PUBLIC_KEY_FILE.txt");
        publicKeyFile.createNewFile();

        byte[] encodedPublicKey = publicKey.getEncoded();
        String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);

        byte[] encodedPrivateKey = privateKey.getEncoded();
        String b64PrivateKey = Base64.getEncoder().encodeToString(encodedPrivateKey);

        //Writing the Keys to the created files
        try (OutputStreamWriter publicKeyWriter =
                     new OutputStreamWriter(
                             new FileOutputStream(publicKeyFile),
                             StandardCharsets.US_ASCII.newEncoder())) {
            publicKeyWriter.write(b64PublicKey);
        }

        try (OutputStreamWriter privateKeyWriter =
                     new OutputStreamWriter(
                             new FileOutputStream(privateKeyFile),
                             StandardCharsets.US_ASCII.newEncoder())) {
            privateKeyWriter.write(b64PrivateKey);
        }

        System.out.println("Keys are written to the Files.......\n\n");

        VerticalSpace();

        //Encryption
        Start_time = System.nanoTime();
        byte[] cipherTextArray = RSA_encrypt(Plaintext, publicKey);
        encryptedString = Base64.getEncoder().encodeToString(cipherTextArray);
        End_time = System.nanoTime();
        Process_time = TimeDifference(Start_time,End_time);

        System.out.println("RSA Encrypted String : "+encryptedString);
        System.out.println("Size of the Encrypted String : "+encryptedString.getBytes().length);
        System.out.println("Time taken for the Encryption Process [ms]: "+Nano2MilliSeconds(Process_time));
    }

    public static void main(String[] args) throws UnknownHostException, Exception {

        System.out.println("Source gNB MEC Server is Running at "+getCurrentTimestamp());
        
        //%%%%%%%%%%%%%%%%%%%%%% MQTT Call %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        //MQTT_send(1,"1-AES");
        
        //Plaintext = "Plain text which need to be encrypted by the specified Encryption Algorithm";

        //Random String with Different Byte Sizes
        Plaintext = RandomStringGenerator();
        System.out.println("Plaintext : "+Plaintext);

        System.out.println("Size of the Plaintext : "+Plaintext.getBytes().length);

        //Socket Constructor
        Source_gNB_Experiment gNBs = new Source_gNB_Experiment(args);
        MQTT_send("0","END");
        //AES Constructor
        //Source_gNB_Experiment gNBs_AES = new Source_gNB_Experiment(aes);

        //RSA Constructor
        //Source_gNB_Experiment gNBs_RSA = new Source_gNB_Experiment(rsa);

    }
    
    public static void MQTT_send(String status, String session){
        ProcessBuilder pb=new ProcessBuilder("python3", "/home/pi/Project/java_src/mqtt-windows.py", status, session, mqttIP); // source_status,session,IP
        pb.redirectErrorStream(true);
        try{
        Process proc =pb.start();
        }catch(IOException e){
            e.printStackTrace();
            
            }
        /*
        Reader reader = new InputStreamReader(proc.getInputStream());
        int ch;
        while((ch = reader.read()) != -1){
            System.out.print((char) ch);
            
            }
            reader.close();
        */
        
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
