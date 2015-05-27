/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import NonSecurity.Ataques;
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

// Classe controlador é responsável por controlar as acções de cada cliente
public class Controlador {
    static Confidentiality conf;
    // Esta thread e variável são responsáveis pelo tempo de renovação de cada chave para cada cliente
    Thread t;
    private static int TIME_TO_REGENERATE_KEY = 10000;
    //-------------------------------------------------------------------------------------------
    private Ataques ataques;
    
    // VARIAVEIS EXTRA    
    private static int VERBOSE = 1;
    private static Boolean ALTERA_MENSAGEM_PARA_MD5 = false;
    private static Boolean ALTERA_CHAVE_CONFIDENCIALIDADE = false;
    
    public Controlador(){
        ataques = new Ataques();
        try {
            conf = new Confidentiality(VERBOSE);            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Controlador.class.getName()).log(Level.SEVERE, null, ex);
        }
        t = new Thread(new RenewKey(this));
        t.start();
        
        if(VERBOSE != 1){
                System.out.println("Criado controlador. Pronto para trabalhar");
            }
    }
    
    // Esta função é responsável por tratar da recepção de mensagems dos clientes
    // a função recebe uma mensagem e irá mandar desencriptar a mesma, retornando a mensagem desencriptada
    // irá também fazer a validação da HASH do MD5 CHECK SUM
    public Mensagem receberMensagem(Mensagem m){
        Mensagem desencriptado = null;
        
        if(ALTERA_CHAVE_CONFIDENCIALIDADE){
            ataques.alteraChaveConfidencialidade(m, VERBOSE);
        }
        
        try {
            desencriptado = conf.decrypt(m.getMensagem(), m.getChave(), m.getIv(), m.getID(), VERBOSE);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | IOException | InvalidAlgorithmParameterException ex) {
            System.out.println("Erro: " + ex);
            return null;
        }catch(BadPaddingException | IllegalArgumentException ex2){
            System.out.println("Impossivel tratar mensagem, Chave/Mensagem alterada");
            return null;
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
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            System.out.println("Erro: " + ex);
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
        return conf.regenarateKey(VERBOSE);
    }
    
    public int getVerbose(){
        return VERBOSE;
    }

    // Esta classe é lançada para que a chave seja renovada de TIME_TO_REGENERATE_KEY em TIME_TO_REGENERATE_KEY tempo
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
