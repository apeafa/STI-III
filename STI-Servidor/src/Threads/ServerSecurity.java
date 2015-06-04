/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Threads;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Erbi
 */
public class ServerSecurity {
    private static SecretKey key;
    IvParameterSpec iv; 
    
    
    public ServerSecurity(){
        try {
            generateKey();
            SecureRandom random = new SecureRandom();
            iv = new IvParameterSpec(random.generateSeed(16));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ServerSecurity.class.getName()).log(Level.SEVERE, null, ex);
        }        
    }
    
    public final static void generateKey() throws NoSuchAlgorithmException{
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        kg.init(random);
        key = kg.generateKey();
       }
    
    public  byte[] encrypt(final byte[] message) throws IllegalBlockSizeException,
    BadPaddingException, NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException,
    UnsupportedEncodingException, InvalidAlgorithmParameterException {

      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE,key,iv);

      byte[] stringBytes = message;

      byte[] raw = cipher.doFinal(stringBytes);

      return raw;
    }
    
    public byte[] decrypt(final byte[] encrypted) throws InvalidKeyException,
    NoSuchAlgorithmException, NoSuchPaddingException,
    IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {

      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, key, iv);
  

      byte[] stringBytes = cipher.doFinal(encrypted);

      return stringBytes;
    }

    public static SecretKey getKey() {
        return key;
    }

    public static void setKey(SecretKey key) {
        ServerSecurity.key = key;
    }
    
    
}
