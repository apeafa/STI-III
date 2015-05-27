/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import Security.MD5;
import java.io.Serializable;
import java.math.BigInteger;

/**
 *
 * @author Erbi
 */
public class Mensagem implements Serializable{
    String mensagem;
    byte[] chave;
    int ID;
    byte[] iv;
    MD5 md5;

    public Mensagem(String mensagem, byte[] chave, byte[] iv, int ID) {
        this.mensagem = mensagem;
        this.chave = chave;
        this.iv = iv;
        this.ID = ID;
        md5 = new MD5(mensagem);
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

    public byte[] getChave() {
        return chave;
    }

    public void setChave(byte[] chave) {
        this.chave = chave;
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
