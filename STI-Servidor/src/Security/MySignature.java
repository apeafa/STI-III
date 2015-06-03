/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Security;

/**
 *
 * @author Erbi
 */

// Esta classe server para guardar a chave privada do cliente
public class MySignature{
    byte[] myPrivateKey;
    
    public MySignature(){   
    }   
    
    public void setPrivateKey(byte[] privatekey){
        myPrivateKey = privatekey;
    }
    
    public byte[] getPrivate(){
        return myPrivateKey;
    }
}
