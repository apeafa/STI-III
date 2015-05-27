/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import Security.Confidentiality;
import Security.MD5;
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
    Thread t;
    int verbose;
    private static int TIME_TO_REGENERATE_KEY = 10000;
    
    public Controlador(int verbose){
        try {
            conf = new Confidentiality();            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Controlador.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.verbose = verbose;
        t = new Thread(new RenewKey(this));
        t.start();
        
        if(verbose != 1){
                System.out.println("Criado controlador. Pronto para trabalhar");
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
      
        if(!comparaMD5(desencriptado))
            desencriptado.setMensagem("A mensagem não está disponivel pois sofreu alterações");
        
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
    
    public Boolean comparaMD5(Mensagem msg){
        MD5 comparaMensagem = new MD5(msg.getMensagem());
        if(verbose != 1){
            System.out.println("Mensagem com MD5 criado agora : " + comparaMensagem.getMessageDigest());
            System.out.println("Mensagem com MD5 criado origem: " + msg.getMD5Hash());
        }
        if(comparaMensagem.getMessageDigest().equals(msg.getMD5Hash()))
            return true;
        else
            return false;
    }
    
    public String renovarChave(){
        return conf.regenarateKey();
    }
    
    public int getVerbose(){
        return verbose;
    }
    
    public class RenewKey implements Runnable{
        Controlador c;

        public RenewKey(Controlador c){
            this.c = c;
        }
            @Override
            public void run() {
                while(c != null){
                    try {
                        Thread.sleep(TIME_TO_REGENERATE_KEY);
                        if(c.getVerbose() == 1)
                            c.renovarChave();
                        else
                            System.out.println("Nova chave: " + c.renovarChave());
                    } catch (InterruptedException ex) {                
                    }
                }
            }

    }
}
