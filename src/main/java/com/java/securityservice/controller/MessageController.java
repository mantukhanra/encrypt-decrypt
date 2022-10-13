package com.java.securityservice.controller;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.java.securityservice.dto.EmpDetails;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

@RestController
@RequestMapping("service")
public class MessageController {

	private final ConcurrentHashMap<String, RSAPublicKey> pubKeyMap = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<String, PrivateKey> pvtKeyMap = new ConcurrentHashMap<>();

	@PostMapping("/encrypt")
	public String getMsg(@RequestBody EmpDetails empDetails,
			@RequestHeader(value="KeyId", required=false) String keyId) {
		JWEObject jwe = null;
		String keyIdentifierFinal = null;
		RSAPublicKey publicKey = null;


		try {
			String jsonObj = new ObjectMapper().writeValueAsString(empDetails);
			keyIdentifierFinal = keyId;
			publicKey = getPublicKey(keyIdentifierFinal);

			JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
					.keyID(keyIdentifierFinal).build();
			jwe = new JWEObject(header, new Payload(jsonObj));
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			generator.init(EncryptionMethod.A256GCM.cekBitLength());
			SecretKey key = generator.generateKey();
			JWEEncrypter encrypter = new RSAEncrypter(publicKey,key);
			jwe.encrypt(encrypter);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return jwe.serialize();
	}

	@PostMapping(value="/decrypt", consumes = MediaType.TEXT_PLAIN_VALUE)
	public String getMsg(@RequestBody String encString) {
		JWEObject jwe = null;
		try {
			jwe = JWEObject.parse(encString);

			JWEDecrypter jweDecrypter = new RSADecrypter(getPrivateKey(jwe.getHeader().getKeyID()));
			jwe.decrypt(jweDecrypter);
		}catch (Exception e) {
			e.printStackTrace();
		}
		return jwe.getPayload().toString();
	}


	private RSAPublicKey getPublicKey(String kid) {
		pubKeyMap.computeIfAbsent(kid, k->loadPubKey(kid));
		return pubKeyMap.get(kid);
	}

	private RSAPublicKey loadPubKey(String keyIdentifierFinal) {
		PublicKey pk =null;
		Properties prop = new Properties();
		prop.put("keyidone", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1CHJZtHRk4uspzRxSygo\r\n" + 
				"4wAsI83OFHYwt2nyBb+jvIjNLLj+Fqw3cdECxwd1zJhoJskOpu+LlYnHsEjy6W8h\r\n" + 
				"dAQOARefzwTrqf2ph8oVTg9VEpD38KB21R0k1GoW29sH+9P/wVyBO8OsqJP5mCjp\r\n" + 
				"tWnR1Y6vHFPjQgSuSAL+YqFChRmRu3cA+bm1ECQilyDk1W2UepaSe/7ebf2vDYal\r\n" + 
				"b8SItk90QLP/we7S07Q7Xx05bMwwSATKH7+u3TQIP+JRURUjWcJ1F791l/LRpikl\r\n" + 
				"3qIdbEISyQn4SdNMVHU8mBn/pki7eYLtBuzQ+jdG7THGknlezLiQQsba0cZdjTG+\r\n" + 
				"NwIDAQAB");
		X509EncodedKeySpec spec = new X509EncodedKeySpec(getPemObjectForPubkey((String) prop.get(keyIdentifierFinal)));

		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
			pk = kf.generatePublic(spec);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return (RSAPublicKey) pk;
	}

	private byte[] getPemObjectForPubkey(String kid) {	

		ByteArrayInputStream in = new ByteArrayInputStream(org.apache.commons.codec.binary.Base64.decodeBase64(kid.getBytes()));

		return in.readAllBytes();

	}

	private PrivateKey getPrivateKey(String kid) {
		pvtKeyMap.computeIfAbsent(kid, k->loadPvtKey(kid));
		return pvtKeyMap.get(kid);
	}

	private PrivateKey loadPvtKey(String kid) {
		Properties prop = new Properties();
		prop.put("keyidone", "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDUIclm0dGTi6ynNHFLKCjjACwjzc4UdjC3afIFv6O8iM0suP4WrDdx0QLHB3XMmGgmyQ6m74uVicewSPLpbyF0BA4BF5/PBOup/amHyhVOD1USkPfwoHbVHSTUahbb2wf70//BXIE7w6yok/mYKOm1adHVjq8cU+NCBK5IAv5ioUKFGZG7dwD5ubUQJCKXIOTVbZR6lpJ7/t5t/a8NhqVvxIi2T3RAs//B7tLTtDtfHTlszDBIBMofv67dNAg/4lFRFSNZwnUXv3WX8tGmKSXeoh1sQhLJCfhJ00xUdTyYGf+mSLt5gu0G7ND6N0btMcaSeV7MuJBCxtrRxl2NMb43AgMBAAECggEARHcjKaxOl/BcqRqj9j3f9GP52xRxjukWkBwBoRlZH2CH2Adc+rRasMFkxBgETSRjeSErOXXW90ygxqTEwdK8WVV1r6SQT6Cm7xaPwOPYPHl2W6euXltr/xyI5oXXGt52lTC3OxFAJKni8AXSaOnLhGHC98o1ek8Y6hXYqiVNNUeAY2uaGZuTdfQVIknvI2d6eBKxXMeEy4A7R1CtCMPhLts0HWkaAvW4bN1QCkRL4vrcGgsPIBwwDDaq0m2NDEhlwwc9s1Kb3K/v49vMHVn2VicureEFoF28Y86i/8ihJn98x9IVRsCeuMC92GGmA5tPvaryueVxTMMKUFARSuifAQKBgQDojIFd7wA8o3ncodHHieB7jU5JWLD4Gx/M575r/E5zLfi2Eq4ka3pK/6WQ1Ru3yXE6FFRMdhQdqOUE8TplO+LUS6KDDAOeGitD74VfRHM37V+gEbGd6sshks10ttqRRwIxiqQILgpUhKq1kBj1OIKYSq70bHalsTCP18ufndhSswKBgQDphjLDCJ5/9hwUk+Z6Qs+8KuqB8MwF0LznmwQltmNz3rFzdGoIbNp89SVG8AUTLpIPW94GJ2UNkqhsnpvrIGXnAEFuaKiUlBe4lU8LcedDuegxMIv10c+5pjxeN/4xIv9dtHGc6yhcK+YLnmiy2jxO5d6+XBeQ4kjxRx5adjNYbQKBgQCwFXP/hHFReRdVENKfnK713tFgiF+3/hHePbvaWHmujSi99PcXbKp1D452VGdgio/JworyOpaQvsprK51j+iyPQ5YSVI6IsJgCIOOEd3gm6P53Xe53/MlC6r3Xmn11c6cdjDUYXIRF6w633ByJ0fhRCHvhaB+O5tQ2ltgATKz4MQKBgQCShUEUXjQU1baIssPJsmHlDohVP2DDxVTBfOH9R5LfALsWVdSxtJriDG53M+H7Rx0dxeZotg8RlRNYE6yAurM1XVOwkrozfzfi+Mu/wpf4Ro0JUAyBEEPlmAgIldlHu02+3ZjrfCC2tFSCtcG7dnKgjlpT1jRzE4fw206QM9nDgQKBgQCwhKlBRkGoZ2xeDQLrLrsgt6pwPlp3MF5K/qxbzyMUnnEwt/gxLCGNmW9jJ7VwIVn4ulufT8kaksZH6PmfJPW2kgspzMSYUwyMHBCARrvSJlxrSTUTnk6KiXB7TwsYy8WdhGuyffVVrFgCrOApRpoJfqOSEZdoT0O05AN4nV6dCQ==");

		PrivateKey privateKey = null;
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(getPemObjectForPvtkey((String) prop.get(kid)));
			privateKey = kf.generatePrivate(spec);
		}catch(Exception e) {
			e.printStackTrace();
		}
		return privateKey;

	}

	private byte[] getPemObjectForPvtkey(String kid) {	
		

		return Base64.getDecoder().decode(kid);

	}

}
