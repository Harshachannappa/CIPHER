package com.ctl.cipherTools;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/*
 * 
 * Property of CenturyLink 2017 ©  
 * 
 * 
 */

public class CipherMe {
	
	public static void usage(){
		System.out.println("Please verify inputs passed!!");
		System.out.println( "Usage:\n\t java CipherMe <-e|-d> <stringToCiper|stringToDeciper>  <key>" );
		System.out.println("\nExample: java -jar CipherMe -e blahBlahBlah mySecretKey");
	}

	/*public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		
		if ( ( args.length != 3 ) || !( args[0].equals("-e") | args[0].equals("-d") ) )
		{
			usage();
			return;
		}

		if(args[1] == null || args[1].equals("") || args[2] == null || args[2].equals(""))
		{
			usage();
			return;
		}
			//set the parameters passed as input.
			String mode = args[0];
			String inputText = args[1];
			String Key = args[2];
						

			//base 64 encoder initialization
			Base64 b64 = new Base64();
			
			if(mode.equals("-e"))
				System.out.println(encryptWithKey(inputText, Key, b64));
			else if (mode.equals("-d"))
				System.out.println(decryptWithKey(inputText, Key, b64));
			else
				usage();
	

	}*/

	//base 64 encoder initialization
	private static Base64 b64 = new Base64();
	
	private static SecretKeySpec secretKey;
    private static byte[] key;
 
    public static void setKey(String myKey) 
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); 
            secretKey = new SecretKeySpec(key, "AES");
        } 
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } 
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
 
    public static String encryptWithKey(String strToEncrypt, String secret) 
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return b64.encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } 
        catch (Exception e) 
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
 
    public static String decryptWithKey(String strToDecrypt, String secret) 
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(b64.decode(strToDecrypt)));
        } 
        catch (Exception e) 
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

}
