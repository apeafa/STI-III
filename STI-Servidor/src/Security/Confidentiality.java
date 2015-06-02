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
    private static SecretKey key;
    private static IvParameterSpec iv;
    
    public Confidentiality(int verbose) throws NoSuchAlgorithmException{
        //generateKey(verbose);
        SecureRandom random = new SecureRandom();
        iv = new IvParameterSpec(random.generateSeed(8));
    }
    
//    // Esta função é chamada sempre que é para se gerar uma chave nova
//    public String regenarateKey(int verbose){
//        try {
//            generateKey(verbose);
//        } catch (NoSuchAlgorithmException ex) {
//            System.out.println("Impossivel gerar chave nova");
//        }
//        return key.toString();
//    }
    
    public void setKey(byte[] key){
        this.key = new SecretKeySpec(key, 0, key.length, "DES");
    }
    
//    // esta função é camada sempre que é para se gerar uma chave nova com o algoritmo AES
//    public void generateKey(int verbose) throws NoSuchAlgorithmException{
//      KeyGenerator kg = KeyGenerator.getInstance("AES");
//      SecureRandom random = new SecureRandom();
//      kg.init(random);
//      key = kg.generateKey();
//      if(verbose != 1){
//        System.out.println("[Chave criada] = " + key);
//        System.out.println("A chave foi criada");
//      }
//    }
    
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
      System.out.println("CLIENT: " + key);
      
      return m;
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
      
      System.out.println("CLIENT: " + key);
      Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
      IvParameterSpec ivSpec=new IvParameterSpec(param);
      
      // Desencriptar a chave para obter a chave de ORIGEM. Para isso usamos a chave DESTINO
      cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);  
      byte[] chaveNormal = cipher.doFinal(chaveEncriptada);      
      byte[] raw = Base64.getDecoder().decode(encrypted);
      
      SecretKey normal = new SecretKeySpec(chaveNormal, 0, chaveNormal.length, "DES");
      
      System.out.println("CLIENT: " + normal);
      ivSpec = new IvParameterSpec(cipher.getIV());
      cipher.init(Cipher.DECRYPT_MODE, normal, ivSpec);  
      // Obter a Mensagem desencrpitando usando a chave normal
      byte[] stringBytes  = cipher.doFinal(raw);
      String clearText = new String(stringBytes, "UTF8");
      Mensagem m = new Mensagem(clearText, ivSpec.getIV(), ID, verbose);
      return m;
    }
}
