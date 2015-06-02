package Threads;


import Controlador.ClientsKeys;
import Controlador.Mensagem;
import Security.DHKeyAgreement2;
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class ChatServer implements Runnable
{  
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private Thread thread = null;
	private int clientCount = 0;
        private ClientsKeys clientsKeys;
        private DHKeyAgreement2 keyAgreement;

	public ChatServer(int port)
    	{  
                keyAgreement = new DHKeyAgreement2(this);
                clientsKeys = new ClientsKeys();
		try
      		{  
            		// Binds to port and starts server
			System.out.println("Binding to port " + port);
            		server_socket = new ServerSocket(port);  
                       
            		System.out.println("Server started: " + server_socket);
            		start();
        	}
      		catch(IOException ioexception)
      		{  
            		// Error binding to port
            		System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
                }
              
          
    	}
        
    	public void run()
    	{  
        	while (thread != null)
        	{  
            		try
            		{  
                		// Adds new thread for new client
                		System.out.println("Waiting for a client ..."); 
                		addThread(server_socket.accept()); 
            		}
            		catch(IOException ioexception)
            		{
                		System.out.println("Accept error: " + ioexception); stop();
            		}
        	}
    	}
    
   	public void start()
    	{  
        	if (thread == null)
        	{  
            		// Starts new thread for client
            		thread = new Thread(this); 
            		thread.start();
        	}
    	}
    
    	public void stop()
    	{  
        	if (thread != null)
        	{
            		// Stops running thread for client
            		thread.stop(); 
            		thread = null;
        	}
    	}
   
        
    	private int findClient(int ID)
    	{  
        	// Returns client from id
        	for (int i = 0; i < clientCount; i++)
            		if (clients[i].getID() == ID)
                		return i;
        	return -1;
    	}
        
        public void inserirSecretKey(int ID, byte[] key){
            clientsKeys.addKey(ID, key);
        }
        
        public byte[] getKEYbyID(int ID){
            return clientsKeys.getChaveFromID(ID);
        }
    
    	public synchronized void handle(int ID, Mensagem m)
    	{   
            if(m == null)
                return;
            m.setID(ID);
            String input = m.getMensagem();
        	if (input.equals(".quit"))
            	{  
                	int leaving_id = findClient(ID);
                	// Client exits
                        m.setMensagem(".quit");
                	clients[leaving_id].send(m);
                	// Notify remaing users
                	for (int i = 0; i < clientCount; i++)
                    		if (i!=leaving_id){
                                    m.setMensagem("Client " +ID + " exits..");
                                    clients[i].send(m);
                                }
                	remove(ID);
            	}
        	else
            		// Brodcast message for every other client online
            		for (int i = 0; i < clientCount; i++){
                            try {
                                m = encrypt(m, ID, clients[i].getID());
                                m.setMensagem(input);
                                m.setID(ID);
                                clients[i].send(m); 
                            } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
                                Logger.getLogger(ChatServer.class.getName()).log(Level.SEVERE, null, ex);
                            }                              
                        }
    	}
        
        // Esta função é responsável pela encriptação de uma mensagem com o mode AES/CBC/PKCS5Padding
    // A função recebe uma mensagem o ID e o modo verbose
    // É responsáve por criar a classe mensagem de acordo com a mensagem recebida e retornar a mesma
    public Mensagem encrypt(final Mensagem message, int ID_envia, int ID_destino) throws IllegalBlockSizeException,
    BadPaddingException, NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException,
    UnsupportedEncodingException, InvalidAlgorithmParameterException {
        
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        
        // Obter a chave DESTINO e a chave ORIGEM
        byte [] chaveDestino = clientsKeys.getChaveFromID(ID_destino);
        byte [] chaveOrigem = clientsKeys.getChaveFromID(ID_envia);
        
        // Criar a chave DESTINO
        SecretKey keyDESTINO = new SecretKeySpec(chaveDestino, 0, chaveDestino.length, "DES");
        IvParameterSpec iv = new IvParameterSpec(message.getIv());
        cipher.init(Cipher.ENCRYPT_MODE, keyDESTINO, iv);          
        
        // Encriptar a chave de ORIGEM com a chave DESTINO
        byte[] raw = cipher.doFinal(chaveOrigem); 
        SecretKey lol = new SecretKeySpec(chaveDestino, 0, chaveDestino.length, "DES");
        System.out.println("SERVER: " + lol);
        Mensagem m = new Mensagem(Base64.getEncoder().encodeToString(raw), iv.getIV(), ID_envia, 1);
        m.setChave(raw);
        
        return m;
    }
    
    	public synchronized void remove(int ID)
    	{  
        	int pos = findClient(ID);
      
       	 	if (pos >= 0)
        	{  
            		// Removes thread for exiting client
            		ChatServerThread toTerminate = clients[pos];
            		System.out.println("Removing client thread " + ID + " at " + pos);
            		if (pos < clientCount-1)
                		for (int i = pos+1; i < clientCount; i++)
                    			clients[i-1] = clients[i];
            		clientCount--;
         
            		try
            		{  
                		toTerminate.close(); 
            		}
         
            		catch(IOException ioe)
            		{  
                		System.out.println("Error closing thread: " + ioe); 
            		}
         
            		toTerminate.stop(); 
        	}
    	}
    
    	private void addThread(Socket socket)
    	{  
    	    	if (clientCount < clients.length)
        	{  
            		// Adds thread for new accepted client
            		System.out.println("Client accepted: " + socket);
                        keyAgreement.SetID(socket.getPort());
                        try {
                                keyAgreement.run("");
                            } catch (Exception ex) {
                                Logger.getLogger(ChatServer.class.getName()).log(Level.SEVERE, null, ex);
                            }
            		clients[clientCount] = new ChatServerThread(this, socket, keyAgreement.getChaveRetornoCliente());
                        
                        inserirSecretKey(socket.getPort(), keyAgreement.getChaveRetornoServidor());
                        
                            
           		try
            		{  
                		clients[clientCount].open(); 
                		clients[clientCount].start();  
                		clientCount++; 
            		}
            		catch(IOException ioe)
            		{  
               			System.out.println("Error opening thread: " + ioe); 
            		}
       	 	}
        	else
            		System.out.println("Client refused: maximum " + clients.length + " reached.");
    	}
    
    
	public static void main(String args[])
   	{  
        	ChatServer server = null;
                
        	//if (args.length != 1)
            		// Displays correct usage for server
            		//System.out.println("Usage: java ChatServer port");
        	//else
            		// Calls new server
            	//	server = new ChatServer(Integer.parseInt(args[0]));
                server = new ChatServer(3000);
    	}

}

class ChatServerThread extends Thread
{  
    private ChatServer       server    = null;
    private Socket           socket    = null;
    private int              ID        = -1;
    private ObjectInputStream  streamIn  =  null;
    private ObjectOutputStream streamOut = null;
    private byte[] chave;
    
    public ChatServerThread(ChatServer _server, Socket _socket, byte[] chave)
    {  
        super();
        server = _server;
        socket = _socket;
        ID     = socket.getPort();            
        this.chave = chave;
    }
    
    // Sends message to client
    public void send(Mensagem msg)
    {   
        try
        {  
            streamOut.writeObject(msg);
            streamOut.flush();
        }
       
        catch(IOException ioexception)
        {  
            System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            stop();
        }
    }
    
    // Gets id for client
    public int getID()
    {  
        return ID;
    }
   
    // Runs thread
    public void run()
    {  
        System.out.println("Server Thread " + ID + " running.");
        
        try {
            streamOut.writeObject(new Mensagem("", chave, 0, 0));
        } catch (IOException ex) {
        }
        
        while (true)
        {  
            try
            {  
                server.handle(ID, (Mensagem)streamIn.readObject());
            }
         
            catch(IOException ioe)
            {  
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(ChatServerThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    
    // Opens thread
    public void open() throws IOException
    {          
        streamIn = new ObjectInputStream(socket.getInputStream());
        streamOut = new ObjectOutputStream(socket.getOutputStream());        
    }
    
    // Closes thread
    public void close() throws IOException
    {  
        if (socket != null)    socket.close();
        if (streamIn != null)  streamIn.close();
        if (streamOut != null) streamOut.close();
    }
    
}

