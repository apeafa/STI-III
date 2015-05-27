/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import Confidentiality.Confidentiality;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Erbi
 */
public class Controlador {
    static Confidentiality conf;
    
    public Controlador(){
        try {
            conf = new Confidentiality();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Controlador.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public Mensagem receberMensagem(Mensagem m){
        Mensagem desencriptado = null;
        //System.out.println(m.getMensagem());
        try {
            //System.out.println("TESTE:" + m.getMensagem());
            desencriptado = conf.decrypt(m.getMensagem(), m.getChave(), m.getIv(), m.getID());
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidAlgorithmParameterException ex) {
            System.out.println("Erro: " + ex);
        }
      
        
        return desencriptado;
    }
    
    public Mensagem enviarMensagem(String mensagem){
        Mensagem encriptado = null;
        
        try {
            encriptado = conf.encrypt(mensagem, 0);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            System.out.println("Erro");
        }
        return encriptado;
    }
}
