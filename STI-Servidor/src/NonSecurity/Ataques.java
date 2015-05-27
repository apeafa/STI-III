/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package NonSecurity;

import Controlador.Mensagem;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;

/**
 *
 * @author Erbi
 */

// Esta classe é responsável por simular os ataques
public class Ataques {    
    public Mensagem alteraMensagem(Mensagem m, int verbose){
        if(verbose != 1)
            System.out.println("A MENSAGEM IRA SER ALTERADA COM ESTE ATAQUE");
        
        m.setMensagem("Esta mensagem foi alterada, lá lá lá lá lá 123454864531as5fa73r´+w´ro23ir");
        return m;
    }
    
    public void alteraChaveConfidencialidade(Mensagem m, int verbose){
        if(verbose != 1)
            System.out.println("A CHAVE IRA SER ALTERADA COM ESTE ATAQUE");
      KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance("AES");
            SecureRandom random = new SecureRandom();
            kg.init(random);
            m.setChave(kg.generateKey().getEncoded());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Erro ataque: " + ex);
        }      
    }
}
