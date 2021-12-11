package com.example.messagingrabbitmq;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.concurrent.CountDownLatch;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.gson.Gson;

@Component
public class Receiver {

	private CountDownLatch latch = new CountDownLatch(1);
	
	static {
	    Security.addProvider(new BouncyCastleProvider());
	}

	public void receiveMessage(String messageString) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		
		Message message = new Gson().fromJson(messageString, Message.class);
		
		// do the message processing here 
		if (message.processMessage() == false) {
			return;
		}
		
		if (BlockChain.blockchain.size() == 0) {
			// create genesis block and add message
			Block genesis = new Block();
			genesis.previousHash = "0";
			genesis.addTransaction(new Message("", "", "0".getBytes(), "", ""));
			genesis.timeStamp = new Date().getTime();
			genesis.hash = genesis.calculateHash();
			BlockChain.addBlock(genesis);
		} 
		
		Block current = new Block();
		int size = BlockChain.blockchain.size();
		current.previousHash = BlockChain.blockchain.get(size-1).hash;
		current.addTransaction(message);
		current.timeStamp = new Date().getTime();
		current.hash = current.calculateHash();
		BlockChain.addBlock(current);
		BlockChain.isChainValid();
		
		System.out.println("Received <" + message + ">");
		
		latch.countDown();
	}

	public CountDownLatch getLatch() {
		return latch;
	}

}
