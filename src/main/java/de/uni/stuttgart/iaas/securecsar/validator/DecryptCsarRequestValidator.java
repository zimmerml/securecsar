package de.uni.stuttgart.iaas.securecsar.validator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.uni.stuttgart.iaas.securecsar.info.Constant;
import de.uni.stuttgart.iaas.securecsar.info.request.DecryptCsarRequest;
import de.uni.stuttgart.iaas.securecsar.info.response.DecryptCsarResponse;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.util.StringUtil;

public class DecryptCsarRequestValidator {

	private static final Logger LOGGER = LogManager.getLogger();
	
	// This function validates DecryptCsarRequest.
	// Incase validation fails, it sets respective message in
	// DecryptCsarResponse object and returns false.
	public boolean validate(DecryptCsarRequest request, DecryptCsarResponse response) throws Exception {
		InputStream iosForKeysstore = null;
		
		try {
			if (request.getCsar() == null) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_PROVIDE_CSAR));
				return false;
			}
			
			if (StringUtil.isEmpty(request.getCsarName())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_PROVIDE_CSAR_NAME));
				return false;
			}
			
			if (StringUtil.isEmpty(request.getKeystoreInfo().getKeystorePass())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_PROVIDE_KS_PW));
				return false;
			}

			if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getAliasName())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_PROVIDE_KS_ENTRY_NAME));
				return false;
			}
			
			if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getAliasPass())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_PROVIDE_KS_ENTRY_PW));
				return false;
			}
			
			// Verifying if provided keystore credentials are correct and getting keyalg from keystore (Exceptions are caught for verification)
			if (request.getKeystoreInfo().getJksFile() != null) {
				iosForKeysstore = new ByteArrayInputStream(request.getKeystoreInfo().getJksFile());
				KeyStore keystore = KeyStore.getInstance("JCEKS");
				keystore.load(iosForKeysstore, request.getKeystoreInfo().getKeystorePass().toCharArray());
				Key key = keystore.getKey(request.getKeystoreInfo().getEntry().getAliasName(), request.getKeystoreInfo().getEntry().getAliasPass().toCharArray());
				
				if (key == null) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_INVALID_ALIAS));
					return false;
				} else {
					request.getKeystoreInfo().getEntry().setKeyalg(key.getAlgorithm());
				}
			} else {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_PROVIDE_KS));
				return false;
			}
			
			return true;
		} catch (IOException ex) {
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_WRONGE_KEYSTORE_PW));
			LOGGER.log(Level.DEBUG, ex);
			return false;
		} catch (UnrecoverableKeyException ex) {
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_WRONG_ALIAS_PW));
			LOGGER.log(Level.DEBUG, ex);
			return false;
		} catch (Exception ex) {
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_KEYSTORE));
			throw ex;
		} finally {
			if (iosForKeysstore != null) {
				iosForKeysstore.close();
			}
		}
	}
}