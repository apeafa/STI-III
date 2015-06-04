/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import NonSecurity.Ataques;
import Security.Confidentiality;
import Security.MD5;
import Security.MySignature;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author Erbi
 */

// Classe controlador é responsável por controlar as acções de cada cliente
public class Controlador {
    Confidentiality conf;
    MySignature mySignature;
    // Esta thread e variável são responsáveis pelo tempo de renovação de cada chave para cada cliente
    
    
    //-------------------------------------------------------------------------------------------
    private Ataques ataques;
    
    // VARIAVEIS EXTRA    
    private static int VERBOSE = 1;
    private static Boolean ALTERA_MENSAGEM_PARA_MD5 = false;
    private static Boolean ALTERA_CHAVE_CONFIDENCIALIDADE = false;
    private static Boolean ALTERA_MENSAGEM_ASSINATURA = false;
    
    public Controlador(){
        ataques = new Ataques();
        mySignature = new MySignature();
        try {
            conf = new Confidentiality(VERBOSE);            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Controlador.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        if(VERBOSE != 1){
                System.out.println("Criado controlador. Pronto para trabalhar");
            }
    }
    
    public void setKey(byte[] key){
        conf.setKey(key);
    }
    
    public void setPrivateKey(byte[] privateKey){
        mySignature.setPrivateKey(privateKey);
    }
    
    // Esta função é responsável por tratar da recepção de mensagems dos clientes
    // a função recebe uma mensagem e irá mandar desencriptar a mesma, retornando a mensagem desencriptada
    // irá também fazer a validação da HASH do MD5 CHECK SUM
    public Mensagem receberMensagem(Mensagem m){
        Mensagem desencriptado = null;
        if(ALTERA_CHAVE_CONFIDENCIALIDADE){
            byte[] key = ataques.alteraChaveConfidencialidade(m, VERBOSE);
            m.setChave(key);
        }
        try {
            desencriptado = conf.decrypt(m.getMensagem(), m.getChaveDesencriptar(), m.getIv(), m.getID(), VERBOSE);

            Signature myVerifySign = Signature.getInstance("MD5withRSA");  
            byte[] chavePublica = conf.decryptByte(m.getPublicKey(), desencriptado.iv);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(chavePublica);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey newPublicKey = keyFactory.generatePublic(publicKeySpec);            
            myVerifySign.initVerify(newPublicKey);
            if(ALTERA_MENSAGEM_ASSINATURA)
                myVerifySign.update("...!!!!!".getBytes());
            else
                myVerifySign.update(desencriptado.getMensagem().getBytes());
            byte[] byteSignedData = m.getSignature();
            boolean verifySign = myVerifySign.verify(byteSignedData);
            if (verifySign == false){
                System.out.println("Error in validating Signature ");
                return null;
            }
            else
                System.out.println("Successfully validated Signature ");
            
            
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | IOException | InvalidAlgorithmParameterException ex) {
            System.out.println("Erro: " + ex);
            return null;
        }catch(BadPaddingException | IllegalArgumentException ex2){
            System.out.println("Impossivel tratar mensagem, Chave/Mensagem alterada: " + ex2);
            return null;
        } catch (InvalidKeySpecException | SignatureException ex) {
            Logger.getLogger(Controlador.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        if(ALTERA_MENSAGEM_PARA_MD5)
            ataques.alteraMensagem(desencriptado, VERBOSE);
        
        // VALIDAçÂO da HASH DO md5 check sum para verificar se a mensagem é igual à origem
        if(!comparaMD5(desencriptado))
            desencriptado.setMensagem("A mensagem não está disponivel pois sofreu alterações");
        
        return desencriptado;
    }
    
    
    // Esta função é responsável por tratar do envio de mensagens dos clientes
    // a função recebe uma mensagem e irá mandar encriptar a mesma, retornando a mensagem encriptada
    public Mensagem enviarMensagem(String mensagem){
        Mensagem encriptado = null;
        
        try {
            encriptado = conf.encrypt(mensagem, 0, VERBOSE);
            Signature mySign = Signature.getInstance("MD5withRSA");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            byte[] privada = mySignature.getPrivate();
            
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privada);
            PrivateKey myPrivateKey = kf.generatePrivate(privateKeySpec);
            mySign.initSign(myPrivateKey);
            mySign.update(mensagem.getBytes());
            byte[] byteSignedData = mySign.sign();
            encriptado.setPrivateKey(privada);
            encriptado.setSignature(byteSignedData);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            System.out.println("Erro: " + ex);
        } catch (InvalidKeySpecException | SignatureException ex) {
            Logger.getLogger(Controlador.class.getName()).log(Level.SEVERE, null, ex);
        }
        return encriptado;
    }
    
    // Esta função é responsável por comparar as HASH do MD5 CHECK SUM para verificar se a mensagem original
    // sofreu alterações depois do seu envio
    public Boolean comparaMD5(Mensagem msg){
        MD5 comparaMensagem = new MD5(msg.getMensagem(), VERBOSE);
        if(VERBOSE != 1){
            System.out.println("Mensagem com MD5 criado agora : " + comparaMensagem.getMessageDigest());
            System.out.println("Mensagem com MD5 criado origem: " + msg.getMD5Hash());
        }
        if(comparaMensagem.getMessageDigest().equals(msg.getMD5Hash()))
            return true;
        else
            return false;
    }
    
    public String renovarChave(){
        return "";//conf.regenarateKey(VERBOSE);
    }
    
    public int getVerbose(){
        return VERBOSE;
    }

    
}
