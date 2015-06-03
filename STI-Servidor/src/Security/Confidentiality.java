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
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

// Esta classe trata da confidencialidade das mensagens (encriptaçao, desencriptação, chaves)
public class Confidentiality {
    private  SecretKey key;
    private  IvParameterSpec iv;
    
    public Confidentiality(int verbose) throws NoSuchAlgorithmException{
        //generateKey(verbose);
        SecureRandom random = new SecureRandom();
        iv = new IvParameterSpec(random.generateSeed(8));
    }
    
    
    public void setKey(byte[] key){
        this.key = new SecretKeySpec(key, 0, key.length, "DES");
    }
    
    // Esta função é responsável pela encriptação de uma mensagem com o mode AES/CBC/PKCS5Padding
    // A função recebe uma mensagem o ID e o modo verbose
    // É responsáve por criar a classe mensagem de acordo com a mensagem recebida e retornar a mesma
    public Mensagem encrypt(final String message, int ID, int verbose) throws IllegalBlockSizeException,
    BadPaddingException, NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException,
    UnsupportedEncodingException, InvalidAlgorithmParameterException {
      Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
      
      byte[] stringBytes = message.getBytes();

      byte[] raw = cipher.doFinal(stringBytes);
      
      Mensagem m = new Mensagem(Base64.getEncoder().encodeToString(raw), iv.getIV(), ID, verbose);    
      if(verbose != 1){
        System.out.println("[Mensagem Encriptada] = " + m.getMensagem());
        System.out.println("A mensagem foi encriptada");
      }
      
      return m;
    }
    
    public byte[] decryptByte(byte[] keyEncripted, byte[] param) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
      Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
      IvParameterSpec ivSpec=new IvParameterSpec(param);
      
      cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);  
      byte[] stringBytes  = cipher.doFinal(keyEncripted);
      return stringBytes;
    }
    
    
    
    // Esta função é responsável pela desencriptacao de uma mensagem com o mode AES/CBC/PKCS5Padding
    // A função recebe a mensagem encriptada, a chave de quem a encriptou, a seed iv e o ID
    // É responsáve por criar a classe mensagem com a mensagem desencriptada
    public Mensagem decrypt(final String encrypted, byte[] chaveEncriptada, final byte[] param, int ID, int verbose) throws InvalidKeyException,
    NoSuchAlgorithmException, NoSuchPaddingException,
    IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {

      if(verbose != 1){
        System.out.println("[Mensagem Encriptada] = " + encrypted);
        System.out.println("A mensagem vai ser desencriptada");
      }
      
      Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
      IvParameterSpec ivSpec=new IvParameterSpec(param);
      
      // Desencriptar a chave para obter a chave de ORIGEM. Para isso usamos a chave DESTINO
      cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);  
      byte[] chaveNormal = cipher.doFinal(chaveEncriptada);      
      byte[] raw = Base64.getDecoder().decode(encrypted);
      
      SecretKey normal = new SecretKeySpec(chaveNormal, 0, chaveNormal.length, "DES");
      
      ivSpec = new IvParameterSpec(cipher.getIV());
      cipher.init(Cipher.DECRYPT_MODE, normal, ivSpec);  
      // Obter a Mensagem desencrpitando usando a chave normal
      byte[] stringBytes  = cipher.doFinal(raw);
      String clearText = new String(stringBytes, "UTF8");
      Mensagem m = new Mensagem(clearText, ivSpec.getIV(), ID, verbose);
      return m;
    }
    
    
}
