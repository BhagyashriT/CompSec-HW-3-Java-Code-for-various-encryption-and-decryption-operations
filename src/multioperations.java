import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class multioperations {

	static Cipher cipher;
	static IvParameterSpec ivParameterSpec;
	public static void main(String[] args) throws Exception {
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); ;
		SecretKey secretKey;
		String plainTextkb = "";
		try
		{
			plainTextkb = new	String(Files.readAllBytes(Paths.get("small.txt")));
		}
		catch (IOException e) { e.printStackTrace(); }
		String plainTextmb = "";

		try
		{
			plainTextmb = new String(Files.readAllBytes(Paths.get("big.txt")));
		}
		catch (IOException e) 
		{ 
			e.printStackTrace(); 
		}

		System.out.println("What do you want to do?\n "
				+ "1. CBC for 128 bits key.\n "
				+ "2. CTR for 128 bits key. \n "
				+ "3. CTR with 256 bits key. \n "
				+ "4. Calculate hash using SHA-256. \n "
				+ "5. Calculate hash using SHA-512. \n "
				+ "6. Calculate hash using SHA3-256.\n "
				+ "7. Encrypt and Decrypt using PKCS#1 v2 padding using 2048-bit RSA key.\n "
				+ "8. Encrypt and Decrypt using PKCS#1 v2 padding using 3072-bit RSA key.\n "
				+ "9. Sign the files using 2048-bit DSA key.\n"
				+ "10. Sign the files using 3072-bit DSA key.");
		@SuppressWarnings("resource")
		Scanner sc=new Scanner(System.in);
		int num=sc.nextInt();
		if(num==1||num==2||num==3)
		{
			long startTime = System.nanoTime();
			keyGenerator = KeyGenerator.getInstance("AES");
			/*Since the block would be of a fixed size, the IV would also be of fixed size, unlike the key*/
			int ivSize16 = 16;
			byte[] iv16 = new byte[ivSize16];
			SecureRandom random = new SecureRandom();
			random.nextBytes(iv16);
			ivParameterSpec = new IvParameterSpec(iv16);

			if(num == 1 || num == 2 )
			{
				keyGenerator.init(128);
			}
			else if( num == 3)
			{
				keyGenerator.init(256);
			}
			secretKey = keyGenerator.generateKey();
			long endTime = System.nanoTime();
			startTime = 0;
			System.out.println("Key generation took:  "+(endTime -startTime) * Math.pow(10,-9)+ "s");
			if( num == 1 )
			{
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			}
			else if( num == 2 || num == 3)
			{
				cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			}
			long startTime2 = System.nanoTime();
			String encryptedText = encrypt(plainTextkb, secretKey);
			long endTime2 = System.nanoTime();
			System.out.println("To do Encryption for 1kb file, it took "+(endTime2- startTime2) * Math.pow(10,-9)+ "s");
			long startTime3 = System.nanoTime();

			String decryptedText = decrypt(encryptedText, secretKey);
			long endTime3 = System.nanoTime();
			System.out.println("To do Decryption for 1kb file, it took "+(endTime3 - startTime3) * Math.pow(10,-9)+ "s");

			long startTime4 = System.nanoTime();
			encryptedText = encrypt(plainTextmb, secretKey);
			long endTime4 = System.nanoTime();
			System.out.println("To do Encryption for 1mb file, it took "+(endTime4 - startTime4) * Math.pow(10,-9)+ "s");

			long startTime5 = System.nanoTime();
			decryptedText = decrypt(encryptedText, secretKey);
			long endTime5 = System.nanoTime();
			System.out.println("To do Decryption for 1mb file, it took "+(endTime5 - startTime5) * Math.pow(10,-9)+ "s");
		}
		else if(num == 4)
		{
			shamethod(4,plainTextkb,plainTextmb);

		}
		else if(num==5)
		{
			shamethod(5,plainTextkb,plainTextmb);


		}
		else if(num==6)
		{
			sha3256method(plainTextkb,plainTextmb);

		}
		if(num==7||num==8)
		{
			long startTime = System.nanoTime();
			KeyPair keyPair = buildKeyPair(num);
			PublicKey pubKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			long endTime = System.nanoTime();
			System.out.println("Key generator step took "+(endTime - startTime) * Math.pow(10,-9)+ "s");
			/* encrypt the message*/

			//	byte [] encrypted = encryptRSA(pubKey, plainTextkb);
			File biggerFile1 = new File("small.txt");

			try (RandomAccessFile data = new RandomAccessFile( biggerFile1, "r")) {
				byte[] readSpecificLength = new byte[200];
				startTime = System.nanoTime();
				for (long i = 0, len = data.length() / 200; i < len; i++) {
					data.readFully(readSpecificLength);
					byte [] encrypted = encryptRSA(pubKey, new	String(readSpecificLength));
					//System.out.println(new String(encrypted)); // <<encrypted	message>>
					/* decrypt the message*/
					byte[] secret = decryptRSA(privateKey, encrypted);
					//System.out.println(new String(secret1));
				}
			}
			endTime = System.nanoTime();
			System.out.println("RSA encryption & decryption for 1 KB file took "+(endTime - startTime) * Math.pow(10,-9)+ "s");


			System.out.println("START OF BIG FILE RSA ENCRYPTION ");
			File biggerFile = new File("big.txt");
			try (RandomAccessFile data1 = new RandomAccessFile( biggerFile, "r")) {
				byte[] readSpecificLength1 = new byte[200];
				startTime = System.nanoTime();
				for (long i = 0, len = data1.length() / 200; i < len; i++) {
					data1.readFully(readSpecificLength1);
					byte [] encrypted1 = encryptRSA(pubKey, new	String(readSpecificLength1));
					//System.out.println(new String(encrypted)); // <<encrypted	message>>
					/* decrypt the message*/
					byte[] secret1 = decryptRSA(privateKey, encrypted1);
					//System.out.println(new String(secret1));
				}
			}
			endTime = System.nanoTime();
			System.out.println("RSA encryption & decryption for 1 MB file took "+(endTime - startTime) * Math.pow(10,-9)+ "s");
		}
		else if(num == 9 || num == 10 )
		{
			int noOfBits = 0;
			if(num == 9 )
			{
				noOfBits = 512;
			}
			else
			{
				noOfBits = 1024;
			}
			long startTime = System.nanoTime();
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
			kpg.initialize(noOfBits, new SecureRandom());
			KeyPair dsaKeyPair = kpg.generateKeyPair();
			DSAPrivateKey privateKey = (DSAPrivateKey) dsaKeyPair.getPrivate();
			DSAPublicKey publicKey = (DSAPublicKey) dsaKeyPair.getPublic();
			long endTime = System.nanoTime();
			System.out.println("Key-pair generator step took "+(endTime - startTime) * Math.pow(10,-9)+ "s");
			Signature sign = Signature.getInstance("DSA");
			
			startTime = System.nanoTime();
			sign.initSign(privateKey);
			sign.update(plainTextkb.getBytes());
			String signedText = new String(sign.sign());
			endTime = System.nanoTime();
			System.out.println("DSA Signing step for 1 KB file took "+(endTime- startTime) * Math.pow(10,-9)+ "s");

			//System.out.println("The signature for "+ noOfBits +" bit DSA is:" + signedText);
			startTime = System.nanoTime();
			sign.initSign(privateKey);
			sign.update(plainTextmb.getBytes());
			String signedText1 = new String(sign.sign());
			endTime = System.nanoTime();
			System.out.println("DSA Signing step for 1 MB file took "+(endTime - startTime) * Math.pow(10,-9)+ "s");
			//System.out.println("The signature for "+ noOfBits +" bit DSA for the bigger file is: " + signedText1);
		}
	}

	public static byte[] encryptRSA(PublicKey publicKey, String message) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");  
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);  

		return cipher.doFinal(message.getBytes());  
	}

	public static byte[] decryptRSA(PrivateKey privateKey, byte [] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");  
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(encrypted);
	}
	public static KeyPair buildKeyPair(int num) throws NoSuchAlgorithmException {
		int keySize =0;
		if(num == 7)
		{
			keySize = 2048;
		}
		else if( num == 8 )
		{
			keySize = 3072;
		}

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keySize);      
		return keyPairGenerator.genKeyPair();
	}
	public static KeyPair generateKeyPair()	throws GeneralSecurityException
	{
		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
		keyPair.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
		return keyPair.generateKeyPair();
	}
	public static byte[] encrypt(PrivateKey privateKey, String message) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");  
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);  
		return cipher.doFinal(message.getBytes());  
	}

	public static byte[] decrypt(PublicKey publicKey, byte [] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");  
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encrypted);
	}
	public static String encrypt(String plainText, SecretKey secretKey)
			throws Exception 
	{
		byte[] plainTextByte = plainText.getBytes();
		/*Initialization through encryption mode and the cipher text*/
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

		/*Encryption of the plain text*/
		byte[] encryptedByte = cipher.doFinal(plainTextByte);
		Base64.Encoder encoder = Base64.getEncoder();
		String encryptedText = encoder.encodeToString(encryptedByte);
		return encryptedText;
	}
	public static String decrypt(String encryptedText, SecretKey secretKey)
			throws Exception 
	{
		Base64.Decoder decoder = Base64.getDecoder();
		byte[] encryptedTextByte = decoder.decode(encryptedText);

		/*Initialization through decryption mode and the cipher text*/
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

		/*Decryption of the encrypted text*/
		byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
		String decryptedText = new String(decryptedByte);
		return decryptedText;
	}

	//Part 4, 5, 6

	private static void sha3256method(String plainTextkb, String plainTextmb) throws IOException {
		// TODO Auto-generated method stub
		//String hashedfile = new	String(Files.readAllBytes(Paths.get("hashedfile.txt")));
		//same as DigestSHA3 md = new SHA3.Digest256();
		long startTime = System.nanoTime();
		DigestSHA3 digest2 = new SHA3.Digest256();
		digest2.update(plainTextkb.getBytes(StandardCharsets.UTF_8));
		byte[] encodedhash2 = digest2.digest();
		String hashString2  = new String(encodedhash2);
		long endTime = System.nanoTime();
		System.out.println("Time taken to create hash for 1kb file is: "+(endTime - startTime) * Math.pow(10,-9)+ "s");
		long startTime1 = System.nanoTime();
		DigestSHA3 digest2mb = new SHA3.Digest256(); //same as DigestSHA3 md = new SHA3.Digest256();
		digest2.update(plainTextmb.getBytes(StandardCharsets.UTF_8));
		byte[] encodedhashbig2 = digest2mb.digest();
		String hashStringBig2  = new String(encodedhashbig2);
		long endTime1 = System.nanoTime();
		System.out.println("Time taken to create hash for 1mb file is: "+(endTime1 - startTime1) * Math.pow(10,-9)+ "s");


	}

	private static void shamethod(Integer n, String plainTextkb, String plainTextmb) throws NoSuchAlgorithmException, IOException {
		// TODO Auto-generated method stub
		String[] HashArray = {"SHA-256","SHA-512"};
		int j;

		if (n==4)
		{
			j=0;
		}
		else
			j=1;


		long startTime = System.nanoTime();
		MessageDigest md = MessageDigest.getInstance(HashArray[j]); //Change the Hash Array Number from 0-6 (If you change it to 0 then MD2 hash will be set,as per line number 29)

		byte[] encodedhash =md.digest(plainTextkb.getBytes(StandardCharsets.UTF_8));		
		System.out.println("Operation successful");
		long endTime = System.nanoTime();
		System.out.println("Time taken to create hash for 1kb file is: "+(endTime - startTime) * Math.pow(10,-9)+ "s");

		long startTime1 = System.nanoTime();
		byte[] encodedhashbig =	md.digest(plainTextmb.getBytes(StandardCharsets.UTF_8));
		long endTime1 = System.nanoTime();
		System.out.println("Time taken to create hash for 1mb file is: "+(endTime1 - startTime1) * Math.pow(10,-9)+ "s");


	}
	
}


