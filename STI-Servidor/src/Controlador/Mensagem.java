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

// Esta classe é a que transporta todos os dados
// transporta a mensagem encriptada
// transporta a chave de quem a envia
// o id de quem a envia
// a seed iv
// transporta a hash original da mensagem MD5 Check sum
public class Mensagem implements Serializable{
    String mensagem;
    byte[] chave;
    int ID;
    byte[] iv;
    MD5 md5;

    public Mensagem(String mensagem, byte[] chave, byte[] iv, int ID, int verbose) {
        this.mensagem = mensagem;
        this.chave = chave;
        this.iv = iv;
        this.ID = ID;
        md5 = new MD5(mensagem, verbose);
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
