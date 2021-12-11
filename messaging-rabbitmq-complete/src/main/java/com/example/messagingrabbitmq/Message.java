package com.example.messagingrabbitmq;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;





public class Message {
	
	static {
	    Security.addProvider(new BouncyCastleProvider());
	}

	private String encryptedAesSymmetricKey;
	private String encryptedMessage;
	private byte[] signature;
	private String senderPublicKey;
	private String recipientPublicKey;
	
	public Message() {
		
	}
	
	public Message(String encryptedRandomSymmetricKey, String encryptedMessage, byte[] signature, String senderPublicKey, String recipientPublicKey) {
		this.encryptedAesSymmetricKey = encryptedRandomSymmetricKey;
		this.encryptedMessage = encryptedMessage;
		this.signature = signature;
		this.senderPublicKey = senderPublicKey;
		this.recipientPublicKey = recipientPublicKey;
	}

	public String getSenderPublicKey() {
		return senderPublicKey;
	}

	public void setSenderPublicKey(String senderPublicKey) {
		this.senderPublicKey = senderPublicKey;
	}

	public String getEncryptedAesSymmetricKey() {
		return encryptedAesSymmetricKey;
	}

	public void setEncryptedAesSymmetricKey(String encryptedAesSymmetricKey) {
		this.encryptedAesSymmetricKey = encryptedAesSymmetricKey;
	}

	public String getEncryptedMessage() {
		return encryptedMessage;
	}

	public void setEncryptedMessage(String encryptedMessage) {
		this.encryptedMessage = encryptedMessage;
	}

	public byte[] getSignature() {
		return signature;
	}

	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	public boolean processMessage() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		
		if(!verifyECDSASig(getKeyFromString(this.senderPublicKey), this.senderPublicKey + this.recipientPublicKey + this.encryptedMessage, this.signature) == false) {
			System.out.println("#Transaction Signature failed to verify");
			return false;
		}
		
		return true;
	}
	
	public static String getStringFromKey(Key key) {
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}
	
	public static PublicKey getKeyFromString(String keyString) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		byte[] publicBytes = Base64.getDecoder().decode(keyString);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		PublicKey public_key = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));
		return public_key;
	}
	
	private boolean verifySignature(String senderPublicKey, String recipientPublicKey, String encryptedPayload, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		String data = senderPublicKey + recipientPublicKey + encryptedPayload;
		return verifyECDSASig(getKeyFromString(senderPublicKey), data, signature);
	}
	
	public static boolean verifyECDSASig(PublicKey publicKey, String data, byte[] signature) {
		try {
			Signature ecdsaVerify = Signature.getInstance("ECDSA", "BC");
			ecdsaVerify.initVerify(publicKey);
			ecdsaVerify.update(data.getBytes());
			return ecdsaVerify.verify(signature);
		}catch(Exception e) {
			throw new RuntimeException(e);
		}
	}
}
