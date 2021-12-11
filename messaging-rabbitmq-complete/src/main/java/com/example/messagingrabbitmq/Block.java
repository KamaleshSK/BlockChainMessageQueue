package com.example.messagingrabbitmq;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Block {
	
	static {
	    Security.addProvider(new BouncyCastleProvider());
	}
	
	public static int capacity = 5;
	public String hash;
	public String previousHash; 
	public String merkleRoot;
	public ArrayList<Message> messages; //our data will be a simple message.
	public long timeStamp; //as number of milliseconds since 1/1/1970.
	public int nonce;
	
	//Calculate new hash based on blocks contents
	public String calculateHash() {
		String calculatedhash = StringUtil.applySha256( 
				this.previousHash +
				Long.toString(timeStamp) +
				Integer.toString(this.nonce) + 
				this.merkleRoot
				);
		return calculatedhash;
	}
	
	// Increases nonce value until hash target is reached.
	public void mineBlock(int difficulty) {
		merkleRoot = StringUtil.getMerkleRoot(messages);
		String target = StringUtil.getDifficultyString(difficulty); //Create a string with difficulty * "0" 
		while(!hash.substring(0, difficulty).equals(target)) {
			nonce ++;
			this.hash = calculateHash();
		}
		System.out.println("Block Mined!!! : " + hash);
	}
	
	//Add messages to this block
	public boolean addTransaction(Message message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		//process transaction and check if valid, unless block is genesis block then ignore.
		if(message == null) return false;		
		if((!"0".equals(this.previousHash))) {
			if((message.processMessage() != true)) {
				System.out.println("Message failed to process. Discarded.");
				return false;
			}
		}
		
		this.messages = new ArrayList<Message>();
		this.messages.add(message);
		System.out.println("Message Successfully added to Block");
		return true;
	}
	
}
