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

import de.uni.stuttgart.iaas.securecsar.info.CertificateInfo;
import de.uni.stuttgart.iaas.securecsar.info.Constant;
import de.uni.stuttgart.iaas.securecsar.info.KeystoreEntryInfo;
import de.uni.stuttgart.iaas.securecsar.info.KeystoreInfo;
import de.uni.stuttgart.iaas.securecsar.info.request.EncryptCsarRequest;
import de.uni.stuttgart.iaas.securecsar.info.response.EncryptCsarResponse;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.util.AlgorithmOptions.EncryptionAlgo;
import de.uni.stuttgart.iaas.securecsar.util.AlgorithmOptions.SymetricKeyAlgo;
import de.uni.stuttgart.iaas.securecsar.util.StringUtil;

public class EncryptCsarRequestValidator {

	private static final Logger LOGGER = LogManager.getLogger();
	
	// This function validates EncryptCsarRequest.
	// Incase validation fails, it sets respective message in
	// DecryptCsarResponse object and returns false.
	// This function also set default mandatory values
	public boolean validate(EncryptCsarRequest request, EncryptCsarResponse response) throws Exception {
		InputStream iosForKeysstore = null;
		
		try {
			if (request.getKeystoreInfo() == null) {
				request.setKeystoreInfo(new KeystoreInfo());
				request.getKeystoreInfo().setEntry(new KeystoreEntryInfo());
				request.getKeystoreInfo().getEntry().setCertificateInfo(new CertificateInfo());
			} else if (request.getKeystoreInfo().getEntry() == null) {
				request.getKeystoreInfo().setEntry(new KeystoreEntryInfo());
				request.getKeystoreInfo().getEntry().setCertificateInfo(new CertificateInfo());
			} else if (request.getKeystoreInfo().getEntry().getCertificateInfo() == null) {
				request.getKeystoreInfo().getEntry().setCertificateInfo(new CertificateInfo());
			}
			
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
				// Request to create new create keystore - setting default values which are not provided
				// default aliasname
				if (StringUtil.isEmpty(request.getKeystoreInfo().getKeystoreName())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_PROVIDE_KS_NAME));
					return false;
				}
				
				if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getAliasName())) {
					request.getKeystoreInfo().getEntry().setAliasName(Constant.DEFAULT_ALIAS_NAME);
				}
				
				if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getKeyalg())) {
					// default key algorithm
					request.getKeystoreInfo().getEntry().setKeyalg(SymetricKeyAlgo.getDefault());
				} else if (!SymetricKeyAlgo.exists(request.getKeystoreInfo().getEntry().getKeyalg())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_INVALID_KEYALG));
					return false;
				}
				
				if (request.getKeystoreInfo().getEntry().getKeysize() == 0) {
					// default keysize (based on key algorithm)
					SymetricKeyAlgo myKeyAlgo = SymetricKeyAlgo.valueOf(request.getKeystoreInfo().getEntry().getKeyalg());
					if (myKeyAlgo != null) {
						request.getKeystoreInfo().getEntry().setKeysize(myKeyAlgo.getDefaultKeysize());
					}
				} else {
					if (request.getKeystoreInfo().getEntry().getKeyalg() == "AES") {
						if (request.getKeystoreInfo().getEntry().getKeysize() != 128
							&& request.getKeystoreInfo().getEntry().getKeysize() != 192
							&& request.getKeystoreInfo().getEntry().getKeysize() != 256) {
							response.addResponseMsg(
							new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_KEYSIZE_AES));
							return false;
						}
					} else if (request.getKeystoreInfo().getEntry().getKeyalg() == "DES") {
						if (request.getKeystoreInfo().getEntry().getKeysize() != 56) {
							response.addResponseMsg(
							new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_KEYSIZE_DES));
							return false;
						}
					} else if (request.getKeystoreInfo().getEntry().getKeyalg() == "DESede") {
						if (request.getKeystoreInfo().getEntry().getKeysize() != 112
							&& request.getKeystoreInfo().getEntry().getKeysize() != 168) {
							response.addResponseMsg(
							new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_KEYSIZE_DES));
							return false;
						} 
					} 
				}
			}
			
			// default encryption algorithm
			if (StringUtil.isEmpty(request.getEncAlg())) {
				request.setEncAlg(EncryptionAlgo.getDefault());
			} else if (!EncryptionAlgo.exists(request.getEncAlg())) {
				// Encryption algorithm provided but is not valid
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_ENCALG));
				return false;
			}
						
			// Validation if encryption algorithm is compliant with key algorithm or not
			EncryptionAlgo myEncSigAlo = EncryptionAlgo.valueOf(request.getEncAlg());
			if (!myEncSigAlo.validate(request.getKeystoreInfo().getEntry().getKeyalg())) {
				ResponseMessage responseMsg = new ResponseMessage(MessageType.ERROR,
				Constant.VALIDATION_MSG_UNCOMPLIANT_ENCALG);
				response.addResponseMsg(responseMsg);
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
