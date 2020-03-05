package com.zeta.utils;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.util.Base64;

/**
 * AWS KMS를 이용해서 암복호화.
 * generateDataKey를 이용해서, 암호화할 plaintextKey와 이 plaintextKey를 암호화한 encryptedKey를 받는다.
 * 암호화대상은 plaintextKey로 암호화하고, 복호화할 때는 encryptedKey를 복호화하여 암호화대상을 복호화한다.
 * 이 방식은 최초 AWS KMS에 접속해서 2개의 key를 받은 후, 로컬에서 사용하는 것이라 AWS KMS 접속이 달라져도 
 * 암복호화하는데 문제 없다.
 * 
 *  AWS KMS에서 key를 보관하여 사용하는 방식이 AWS에서 권고하는 방식이다.
 *  그러나, AWS 접속계정이 달라졌을 때 arn를 바꿔서 다시 요청하는게 필요한다. 
 *  이것은 AWS에 종속되기는 방법이라서  generateDataKey를 사용한다.
 * @author zeta
 *
 */
public class AwsCrypt {

	private static String keyArn;  //예시:"arn:aws:kms:ap-northeast-2:638947113641:key/8526f3a5-829e-450a-9913-65cbbbcb5d7f";
    private static AWSKMS kms;

	public static void set(String key) {
		keyArn = key;
		kms = AWSKMSClientBuilder.standard().withRegion(Regions.AP_NORTHEAST_2).build();
		
	}
	
	/**
	 * AWS KMS에 접속해서 key가져오기
	 * @param key
	 * @return
	 */
	public static Map<String, String> getKey(String key) {

		// keyArn세팅
		set(key);
		
		Map<String, String> map = new HashMap<String, String>();
		
		// key요청.generateDataKey권한이 있어야 동작
		GenerateDataKeyRequest request = new GenerateDataKeyRequest().withKeyId(keyArn).withKeySpec("AES_256");
		GenerateDataKeyResult response = kms.generateDataKey(request);

		String plaintextKey = Base64.encodeAsString(response.getPlaintext().array());
		String encryptedKey = Base64.encodeAsString(response.getCiphertextBlob().array());

		map.put("plaintextKey", plaintextKey);
		map.put("encryptedKey", encryptedKey);

		return map;
	}

	/**
	 * 암호화
	 * @param strToEnc
	 * @param plaintextKey
	 * @return
	 */
	public static String enc(String strToEnc, String plaintextKey) {
		return AES.encrypt(strToEnc, plaintextKey);
	}

	/**
	 * 복호화.
	 * AWS KMS에서 받은 encryptedKey를 복호화하여, plaintextKey로 만들고
	 * 이것으로 암호화된 내용을 복호화
	 * @param enToStr
	 * @param encryptedKey
	 * @return
	 */
	public static String dec(String enToStr, String encryptedKey) {

		// Decrypt encryptedKey
		final DecryptRequest decReq = new DecryptRequest();
		decReq.setCiphertextBlob(ByteBuffer.wrap(Base64.decode(encryptedKey)));
		final ByteBuffer decrypted = kms.decrypt(decReq).getPlaintext();
		final String plaintextKey = Base64.encodeAsString(decrypted.array());
		System.out.println("plaintextKey: " + plaintextKey);

		return AES.decrypt(enToStr, plaintextKey);
	}

}