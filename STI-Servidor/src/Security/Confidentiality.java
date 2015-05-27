/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Security;

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
import java.util.logging.Level;
import java.util.logging.Logger;
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
    
    public Confidentiality(int verbose) throws NoSuchAlgorithmException{
        generateKey(verbose);
        SecureRandom random = new SecureRandom();
        iv = new IvParameterSpec(random.generateSeed(16));
    }
    
    public String regenarateKey(int verbose){
        try {
            generateKey(verbose);
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Impossivel gerar chave nova");
        }
        return key.toString();
    }
    
    public void generateKey(int verbose) throws NoSuchAlgorithmException{
      KeyGenerator kg = KeyGenerator.getInstance("AES");
      SecureRandom random = new SecureRandom();
      kg.init(random);
      key = kg.generateKey();
      if(verbose != 1){
        System.out.println("[Chave criada] = " + key);
        System.out.println("A chave foi criada");
      }
    }
    
    public Mensagem encrypt(final String message, int ID, int verbose) throws IllegalBlockSizeException,
    BadPaddingException, NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException,
    UnsupportedEncodingException, InvalidAlgorithmParameterException {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);

      byte[] stringBytes = message.getBytes();

      byte[] raw = cipher.doFinal(stringBytes);
      
      Mensagem m = new Mensagem(Base64.getEncoder().encodeToString(raw), key.getEncoded(), iv.getIV(), ID, verbose);
      
      if(verbose != 1){
        System.out.println("[Mensagem Encriptada] = " + m.getMensagem());
        System.out.println("[Chave] = " + new String(m.getChave()));
        System.out.println("A mensagem foi encriptada");
      }
      
      return m;
    }
    
    public Mensagem decrypt(final String encrypted, final byte[] chave, final byte[] param, int ID, int verbose) throws InvalidKeyException,
    NoSuchAlgorithmException, NoSuchPaddingException,
    IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {

      if(verbose != 1){
        System.out.println("[Mensagem Encriptada] = " + encrypted);
        System.out.println("[Chave] = " + new String(chave));
        System.out.println("A mensagem vai ser desencriptada");
      }
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      IvParameterSpec ivSpec=new IvParameterSpec(param);
      SecretKey keySpec=new SecretKeySpec(chave,"AES");
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);     
      byte[] raw = Base64.getDecoder().decode(encrypted);
      byte[] stringBytes  = cipher.doFinal(raw);
      String clearText = new String(stringBytes, "UTF8");
      Mensagem m = new Mensagem(clearText, keySpec.getEncoded(), ivSpec.getIV(), ID, verbose);
      return m;
    }
}
