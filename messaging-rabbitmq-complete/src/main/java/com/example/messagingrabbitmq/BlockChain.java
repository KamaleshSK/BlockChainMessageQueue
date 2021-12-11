package com.example.messagingrabbitmq;

import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class BlockChain {
	
	static {
	    Security.addProvider(new BouncyCastleProvider());
	}

	public static final int difficulty = 3;
	public static ArrayList<Block> blockchain = new ArrayList<Block>();
	
	public static Boolean isChainValid() {
		Block currentBlock; 
		Block previousBlock;
		String hashTarget = new String(new char[difficulty]).replace('\0', '0');
		
		
		//loop through blockchain to check hashes:
		for(int i=1; i < blockchain.size(); i++) {
			
			currentBlock = blockchain.get(i);
			previousBlock = blockchain.get(i-1);
			//compare registered hash and calculated hash:
			if(!currentBlock.hash.equals(currentBlock.calculateHash()) ){
				System.out.println("#Current Hashes not equal");
				return false;
			}
			//compare previous hash and registered previous hash
			if(!previousBlock.hash.equals(currentBlock.previousHash) ) {
				System.out.println("#Previous Hashes not equal");
				return false;
			}
			//check if hash is solved
			if(!currentBlock.hash.substring(0, difficulty).equals(hashTarget)) {
				System.out.println("#This block hasn't been mined");
				return false;
			}
		}	
		
		return true;
	}
	
	public static void addBlock(Block newBlock) {
		newBlock.mineBlock(difficulty);
		blockchain.add(newBlock);
	}
}
