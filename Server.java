package com.pepe.apps.chatroom.room.encrypted;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import java.util.Base64;

/**
 *
 * @author Pepe
 */
public class Server extends JFrame {

    private final String aesKey = "ËâÒÐÆÞÚÐÎÕÂáÌáÈ×ÌÔ××ÕËÞè×ÜÈÔÞèÚÐÂìåÑÔì×ßÂÞåÍÖÓ×ØÝÑÅåËÑËÔÑÔÇÝÂÝÖÉãèÓîÚÞÓÉßßÎãÖÐÊßÊÅÒåÂÒÈíàÎËáØÛÈÕÂæÚÎÓÜÈÌØÑØçäÏÚËÜÑÔØÛÌÙÎã";
    private final String obsKey = "fpioajeofnasjndajsduojeuojaseuthaypiawpwairepiowjgawegjamfdsajncnvnueurawjeruhejadjnajdsnfjneugnashgrjakfjaurgyahgasgde";
    private Base64.Encoder encoder;
    private Base64.Decoder decoder;
        
    private ArrayList clientOutputStreams;
    private ArrayList<String> users;    
    private ArrayList<String> ips;
    
    private int port = 5354;
    
    public Server() {
        this.encoder = Base64.getEncoder();
        this.decoder = Base64.getDecoder();

        initUI();
        setVisible(true);
        txtCmd.requestFocus();
        
        // TESTS
    }
    
    private void initUI() {
        txtCmd = new JTextField();
        scrollArea = new JScrollPane();
        area = new JTextArea();

        setTitle("Server");
        setResizable(false);
        setLocationRelativeTo(null);
        getContentPane().setBackground(Color.BLACK);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setPreferredSize(new Dimension(500, 500));

        area.setColumns(20);
        area.setRows(5);
        area.setEditable(false);
        area.setBackground(Color.BLACK);
        area.setForeground(Color.GREEN);
        area.setCaretColor(Color.YELLOW);
                
        scrollArea.setViewportView(area);        
        
        txtCmd.setBackground(Color.BLACK);
        txtCmd.setForeground(Color.GREEN);       
        
        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addComponent(txtCmd)
            .addComponent(scrollArea, GroupLayout.DEFAULT_SIZE, 500, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addComponent(scrollArea, GroupLayout.DEFAULT_SIZE, 469, Short.MAX_VALUE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtCmd, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE))
        );

        pack();
        
        txtCmd.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {}

            @Override
            public void keyPressed(KeyEvent e) {
                if(e.getKeyCode() == KeyEvent.VK_ENTER) {
                    String cmd = txtCmd.getText();
                    txtCmd.setText("");
                    if(cmd.startsWith("/")) {           
                        String c = cmd.replaceFirst("/", "");
                        area.append("$ " + c + "\n");
                        processCmd(c);
                    }
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {}
        });
    }      
    
    private void processCmd(String cmd) {
        switch(cmd) {
            case "start":
                area.append("Starting Server...\n");
                server.start();
                break;
                
            case "stop":
                try {Thread.sleep(1000);} catch (InterruptedException ex) {Thread.currentThread().interrupt();}
                tellEveryone("Server:is stopping and all users will be disconnected.\n:Chat");
                area.append("Server stopping... \n");
                server.stop();
                area.setText("[SUCCESS] Server stopped.");                
                break;
                
            case "userlist":
                area.append("Online users: \n");
                for (String current_user : users) {
                    area.append(current_user + " - " + ips.get(users.indexOf(current_user)));
                    area.append("\n");
                }
                break;                        
            
            case "help":
                
                break;
            default:
                area.append("[ERROR] Command not found.\n");
        }
    }
    
    private String encryptMessageToSend(String message) {
        // 1. OBFUSCATE MESSAGE
        // 2. -> ENCRYPT BASE64
        // 3. -> ENCRYPT AES_B64 w/ aesKey        
        //return encryptAES(true, encryptBase64(obfuscate(message)));
        
        // 1. ENCRYPT AES_B64 w/ aesKey
        // 2. -> OBFUSCATE
        // 3. -> ENCRYPT BASE64
        return encrypt(true, message);
    }

    private String decryptMessageReceived(String message) {
        // 1. DECRYPT AES_B64 w/ aesKey
        // 2. -> DECRYPT BASE64
        // 3. -> UNOBFUSCATE FINAL STR
        //return unobfuscate(decryptBase64(decryptAES(true, message)));
        
        // 1. DECRYPT BASE64
        // 2. -> UNOBFUSCATE
        // 3. -> DECRYPT AES_B64 w/ aesKey
        return decrypt(true, message);
    }
    
    // CRYPTO UTILS
    private String obfuscate(String s) {
        char[] result = new char[s.length()];
        for (int i = 0; i < s.length(); i++) {
            result[i] = (char) (s.charAt(i) + obsKey.charAt(i % obsKey.length()));
        }
        return new String(result);
    }

    private String unobfuscate(String s) {
        char[] result = new char[s.length()];
        for (int i = 0; i < s.length(); i++) {
            result[i] = (char) (s.charAt(i) - obsKey.charAt(i % obsKey.length()));
        }
        return new String(result);
    }
    
    // BASE 64
    
    // STR -> ENCRYPTED STR
    private String encryptBase64(String s) { 
        try {       
            return new String(encoder.encode(s.getBytes("UTF-8")));
        } catch(UnsupportedEncodingException ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    // ENCRYPTED STR -> DECRYPTED STR
    private String decryptBase64(String s) { 
        return new String(decoder.decode(s));        
    }
    
    // BYTE[] -> ENCRYPTED STR
    private String encryptBase64Bytes(byte[] binaryData) { 
        return new String(encoder.encode(binaryData));
    }
    
    // ENCRYPTED STR -> DECRYPTED BYTE[]
    private byte[] decryptBase64String(String s) { 
        return decoder.decode(s);
    }
    
    // AES
    
    private String encrypt(boolean strongAes, String s) {
        try {
            // SET KEY mKey
            byte[] key = unobfuscate(aesKey).trim().getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            // ENCRYPT str
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");        
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            if (strongAes) {
                return encryptBase64Bytes(cipher.doFinal(s.getBytes("UTF-8")));                
                //return encryptBase64(obfuscate(new String(cipher.doFinal(s.getBytes("UTF-8")))));
                
            } else {
                return new String(cipher.doFinal(s.getBytes("UTF-8")));
            }
            
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    private String decrypt(boolean strongAes, String s) {
        try {
            // SET KEY mKey
            byte[] key = unobfuscate(aesKey).trim().getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            // DECRYPT str
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            if(strongAes) {
                return new String(cipher.doFinal(decryptBase64String(s)));
                //return new String(cipher.doFinal(unobfuscate(decryptBase64(s)).getBytes("UTF-8")));
            } else {
                return new String(cipher.doFinal(s.getBytes("UTF-8")));
            }
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    // CHAT
    
    // CONNECTION THREADS
    Thread server = new Thread(new Runnable() {
        @Override
        public void run() {
            clientOutputStreams = new ArrayList();
            users = new ArrayList();
            ips = new ArrayList();
            
            try {
                ServerSocket server = new ServerSocket(port);                
                area.append("[SUCCESS] Server started with port " + port + ".\n");
                while (true) {
                    Socket clientSock = server.accept();
                    PrintWriter writer = new PrintWriter(clientSock.getOutputStream());
                    clientOutputStreams.add(writer);                    
                    
                    new Thread(new ClientHandler(clientSock, writer)).start();
                    area.append("[DATA] Got a connection. \n");
                }
            } catch (Exception ex) {
                area.append("[ERROR] Error making a connection. \n");
            }
        }
    });    
    
    public class ClientHandler implements Runnable {

        private BufferedReader reader;
        private Socket sock;
        private PrintWriter client;
        private String ip;
        
        public ClientHandler(Socket clientSocket, PrintWriter user) {
            client = user;
            try {
                sock = clientSocket;
                reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                ip = sock.getInetAddress().getHostAddress();
            } catch (Exception ex) {
                area.append("Unexpected error... \n");
                area.append(ex.getMessage()+"\n");
            }

        }

        @Override
        public void run() {
            String stream;
            String[] data;

            try {
                while ((stream = reader.readLine()) != null) {
                    //area.append(stream + "\n");
                    String message = decryptMessageReceived(stream);
                    if(!message.trim().equals("")) {
                        area.append("Received: " + message + "\n");
                        data = message.split(":");

//                        for (String token : data) {
//                            area.append(token + "\n");
//                        }

                        switch (data[2]) {
                            case "Connect":
                                tellEveryone((data[0] + ":" + data[1] + ":Chat"));
                                userAdd(data[0], ip);
                                break;
                                        
                            case "Disconnect":
                                tellEveryone((data[0] + ":has disconnected." + ":Chat"));
                                userRemove(data[0], ip);
                                break;
                                
                            case "Chat":
                                tellEveryone(message);
                                break;
                                
                            default:
                                area.append("[ERROR] Couldnt read stream received. \n Data: " + message);
                        }
                    }
                }
            } catch (Exception ex) {
                area.append("Lost a connection. \n");
                ex.printStackTrace();
                clientOutputStreams.remove(client);
            }
        }
    }
    
    // UTILS
    private void userAdd(String username, String ip) {
        String message, add = ": :Connect", done = "Server: :Done", name = username;
        area.append("Before " + name + " added. \n");
        if(userAlreadyLogged(name)) {
            ips.remove(users.indexOf(name));
            users.remove(name);
        } else {
            users.add(name);
        }
        ips.add(ip);
        area.append("After " + name + " added. \n");
        String[] tempList = new String[(users.size())];
        users.toArray(tempList);

        for (String token : tempList) {
            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }

    private void userRemove(String username, String ip) {
        String message, add = ": :Connect", done = "Server: :Done";        
        users.remove(username);
        ips.remove(ip);
        String[] tempList = new String[(users.size())];
        users.toArray(tempList);

        for (String token : tempList) {
            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }

    private void tellEveryone(String message) {
        Iterator it = clientOutputStreams.iterator();
        area.append("Telling Everyone: [ " + message + " ]\n");
        while (it.hasNext()) {
            try {
                PrintWriter writer = (PrintWriter) it.next();
                writer.println(encryptMessageToSend(message));
                writer.flush();
            } catch (Exception ex) {                
                area.append("Error telling everyone. \n");
            }
        }
    }
    
    private boolean userAlreadyLogged(String username) {
        for(String object : users) {
            if(object.equals(username)) {
                return true;
            }
        }
        return false;
    }
    // JFRAME COMPONENTS
    private JTextField txtCmd;
    private JTextArea area;
    private JScrollPane scrollArea;

    public static void main(String[] args) {
        new Server();
    }
}