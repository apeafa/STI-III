/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import Security.MD5;
import Security.MySignature;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.Signature;

/**
 *
 * @author Erbi
 */

// Esta classe é a que transporta todos os dados
// transporta a mensagem encriptada
// transporta a chave de quem a envia
// o id de quem a envia
// a seed iv
// transporta a hash original da mensagem MD5 Check sum
public class Mensagem implements Serializable{
    String mensagem;
    int ID;
    byte[] iv;
    MD5 md5;
    byte[] chave;
    byte[] mySign;
    byte[] publicKey;
    byte[] privateKey;
    
    public Mensagem(String mensagem, byte[] iv, int ID, int verbose) {
        this.mensagem = mensagem;
        this.iv = iv;
        this.ID = ID;
        md5 = new MD5(mensagem, verbose);
    }
    
    public void setPublicKey(byte[] key){
        this.publicKey = key;
    }
    
    public byte[] getPublicKey(){
        return publicKey;
    }
    
    public void setPrivateKey(byte[] key){
        this.privateKey = key;
    }
    
    public byte[] getPrivateKey(){
        return privateKey;
    }
    
    public void setSignature(byte[] mySign){
        this.mySign = mySign;
    }
    
    public byte[] getSignature(){
        return mySign;
    }
    
    public void setChave(byte[] chave){
        this.chave = chave;
    }
    
    public byte[] getChaveDesencriptar(){
        return chave;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }
    
    
    public String getMensagem() {
        return mensagem;
    }

    public void setMensagem(String mensagem) {
        this.mensagem = mensagem;
    }


    @Override
    public String toString() {
        return mensagem;
    }  

    public int getID() {
        return ID;
    }

    public void setID(int ID) {
        this.ID = ID;
    }
    
    public BigInteger getMD5Hash(){
        return md5.getMessageDigest();
    }
}
