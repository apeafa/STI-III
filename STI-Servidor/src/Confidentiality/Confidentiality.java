/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Confidentiality;

import Controlador.Mensagem;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Erbi
 */
public class Confidentiality {
    private static SecretKey key;
    private static IvParameterSpec iv;
    
    public Confidentiality() throws NoSuchAlgorithmException{
        generateKey();
        SecureRandom random = new SecureRandom();
        iv = new IvParameterSpec(random.generateSeed(16));
    }
    
    public void generateKey() throws NoSuchAlgorithmException{
      KeyGenerator kg = KeyGenerator.getInstance("AES");
      SecureRandom random = new SecureRandom();
      kg.init(random);
      key = kg.generateKey();
    }
    
    public Mensagem encrypt(final String message, int ID) throws IllegalBlockSizeException,
    BadPaddingException, NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException,
    UnsupportedEncodingException, InvalidAlgorithmParameterException {
      //generateKey();
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);

      byte[] stringBytes = message.getBytes();

      byte[] raw = cipher.doFinal(stringBytes);
      
      //System.out.println("Encriptado: " + new String(raw));
      //System.out.println("key: " + key);
      //System.out.println("ar: " + stringBytes);
      Mensagem m = new Mensagem(Base64.getEncoder().encodeToString(raw), key.getEncoded(), iv.getIV(), ID);
      return m;
    }
    
    public Mensagem decrypt(final String encrypted, final byte[] chave, final byte[] param, int ID) throws InvalidKeyException,
    NoSuchAlgorithmException, NoSuchPaddingException,
    IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {

      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      IvParameterSpec ivSpec=new IvParameterSpec(param);
      SecretKey keySpec=new SecretKeySpec(chave,"AES");
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);     
      //System.out.println("Encriptado: " + encrypted);
      //System.out.println("Aey: " + chave);
      byte[] raw = Base64.getDecoder().decode(encrypted);
      //System.out.println("ar: " + stringBytes);
      byte[] stringBytes  = cipher.doFinal(raw);
      //System.out.println("FEITO");
      String clearText = new String(stringBytes, "UTF8");
      Mensagem m = new Mensagem(clearText, keySpec.getEncoded(), ivSpec.getIV(), ID);
      return m;
    }
}
