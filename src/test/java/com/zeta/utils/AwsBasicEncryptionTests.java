package com.zeta.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.util.Base64;

public class AwsBasicEncryptionTests {

	final static String keyArn = "arn:aws:kms:ap-northeast-2:638947113641:key/8526f3a5-829e-450a-9913-65cbbbcb5d7f";

	@Test
	public void encryptAndDecryptTest() {

		encryptAndDecrypt(keyArn);
	}

	private void encryptAndDecrypt(String keyArn) {
		final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(Regions.AP_NORTHEAST_2).build();
		GenerateDataKeyRequest request = new GenerateDataKeyRequest().withKeyId(keyArn).withKeySpec("AES_256");
		GenerateDataKeyResult response = kms.generateDataKey(request);

		// generateDataKey로 2개의 plaintextKey,encryptedKey를 얻는다.
		String plaintextKey = Base64.encodeAsString(response.getPlaintext().array());
		String encryptedKey = Base64.encodeAsString(response.getCiphertextBlob().array());

		System.out.println("plaintextKey:" + plaintextKey);
		System.out.println("encryptedKey:" + encryptedKey);

		// 암호화할 내용
		String originalString = "Say hello";

		// 1. plaintextKey로 내용(Say hello)을 암호화
		String en = AES.encrypt(originalString, plaintextKey);
		System.out.println("en: " + en);

		// 2. encryptedKey를 kms에 접속해서, 복호화
		final DecryptRequest decReq1 = new DecryptRequest();
		decReq1.setCiphertextBlob(ByteBuffer.wrap(Base64.decode(encryptedKey)));
		final ByteBuffer decrypted = kms.decrypt(decReq1).getPlaintext();
		final String decoded_plaintextKey = Base64.encodeAsString(decrypted.array());

		System.out.println("encryptedKey to plaintextKey: " + decoded_plaintextKey);

		// 3.복호화된 plaintextKey를 가지고 암호내용을 복호화
		String de = AES.decrypt(en, decoded_plaintextKey);

		System.out.println("de: " + de);

		// ========================================================================

		Map<String, String> key = AwsCrypt.getKey(keyArn);

		System.out.println("plaintextKey:" + key.get("plaintextKey"));
		System.out.println("encryptedKey:" + key.get("encryptedKey"));

		en = AwsCrypt.enc(originalString, plaintextKey);
		de = AwsCrypt.dec(en, encryptedKey);
		System.out.println("en:" + en);
		System.out.println("de:" + de);
		System.out.println("===========================================================");

		assertEquals(originalString, de);
	}

}
