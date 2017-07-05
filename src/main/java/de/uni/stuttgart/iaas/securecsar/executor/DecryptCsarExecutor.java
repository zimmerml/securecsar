package de.uni.stuttgart.iaas.securecsar.executor;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.uni.stuttgart.iaas.securecsar.info.Constant;
import de.uni.stuttgart.iaas.securecsar.info.Csar;
import de.uni.stuttgart.iaas.securecsar.info.request.DecryptCsarRequest;
import de.uni.stuttgart.iaas.securecsar.info.response.DecryptCsarResponse;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.info.response.StatusCode;
import de.uni.stuttgart.iaas.securecsar.processor.CsarProcessor;
import de.uni.stuttgart.iaas.securecsar.processor.SecurityProcessor;
import de.uni.stuttgart.iaas.securecsar.validator.DecryptCsarRequestValidator;

public class DecryptCsarExecutor {
	private static final Logger LOGGER = LogManager.getLogger();

	public DecryptCsarResponse execute(DecryptCsarRequest request) {
		InputStream iosForKeysstore = null;
		DecryptCsarResponse response = new DecryptCsarResponse();
		response.setStatusCode(StatusCode.SUCCESS);
		
		try {
			DecryptCsarRequestValidator validator = new DecryptCsarRequestValidator();
			
			if (validator.validate(request, response)) {
				SecurityProcessor securityProcessor = new SecurityProcessor();
				KeyStore keystore = null;
				
				if (request.getKeystoreInfo() != null && request.getKeystoreInfo().getJksFile() != null) {
					// make keystore object from provided byte array
					iosForKeysstore = new ByteArrayInputStream(request.getKeystoreInfo().getJksFile());
					keystore = KeyStore.getInstance("JCEKS");
					keystore.load(iosForKeysstore, request.getKeystoreInfo().getKeystorePass().toCharArray());
				}
				
				// Creating csar object from .casr file in request
				Csar csar = new Csar(request.getCsarName(), request.getCsar(), null, null, false);
				CsarProcessor csarProcessor = new CsarProcessor();
				//decrypting csar
				securityProcessor.decryptCsar(keystore, request.getKeystoreInfo(), csar, response);
				// Generate decrypted csar
				byte[] csarBytes = csarProcessor.generateCsar(csar);
				response.setName(request.getCsarName());
				response.setData(csarBytes);
				
				for (ResponseMessage resp: response.getResponseMsgs()) {
					if (MessageType.WARNING.equals(resp.getMessageType())) {
						response.setStatusCode(StatusCode.WARNING);
						break;
					}
				}
			} else {
				response.setStatusCode(StatusCode.ERROR);
			}
		} catch (Exception ex) {
			LOGGER.log(Level.ERROR, ex.getMessage(), ex);
			response = new DecryptCsarResponse();
			response.setStatusCode(StatusCode.ERROR);
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.RESPONSE_ERROR_MSG_UNEXPECTED_ERROR));
		}

		return response;
	}
}
