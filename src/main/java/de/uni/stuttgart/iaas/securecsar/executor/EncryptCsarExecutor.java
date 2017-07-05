package de.uni.stuttgart.iaas.securecsar.executor;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.uni.stuttgart.iaas.securecsar.info.Artifact;
import de.uni.stuttgart.iaas.securecsar.info.Constant;
import de.uni.stuttgart.iaas.securecsar.info.Csar;
import de.uni.stuttgart.iaas.securecsar.info.PolicyInfo;
import de.uni.stuttgart.iaas.securecsar.info.request.EncryptCsarRequest;
import de.uni.stuttgart.iaas.securecsar.info.response.EncryptCsarResponse;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.info.response.StatusCode;
import de.uni.stuttgart.iaas.securecsar.processor.CsarProcessor;
import de.uni.stuttgart.iaas.securecsar.processor.ResponseProcessor;
import de.uni.stuttgart.iaas.securecsar.processor.SecurityProcessor;
import de.uni.stuttgart.iaas.securecsar.validator.EncryptCsarRequestValidator;

public class EncryptCsarExecutor {
	private static final Logger LOGGER = LogManager.getLogger();

	public EncryptCsarResponse execute(EncryptCsarRequest request) {
		InputStream iosForKeysstore = null;
		EncryptCsarResponse response = new EncryptCsarResponse();
		response.setStatusCode(StatusCode.SUCCESS);
		
		try {
			EncryptCsarRequestValidator validator = new EncryptCsarRequestValidator();
			
			if (validator.validate(request, response)) {
				SecurityProcessor securityProcessor = new SecurityProcessor();
				KeyStore keystore = null;
				
				if (request.getKeystoreInfo().getJksFile() == null) {
					keystore = securityProcessor.generateKeyStore(false, request.getKeystoreInfo().getKeystorePass(),
						request.getKeystoreInfo().getEntry());
				} else {
					// make keystore object from provided byte array
					iosForKeysstore = new ByteArrayInputStream(request.getKeystoreInfo().getJksFile());
					keystore = KeyStore.getInstance("JCEKS");
					keystore.load(iosForKeysstore, request.getKeystoreInfo().getKeystorePass().toCharArray());
				}
				
				// Creating csar object from .casr file in request
				Csar csar = new Csar(request.getCsarName(), request.getCsar(), null, null, false);
				CsarProcessor csarProcessor = new CsarProcessor();
				// Getting encrypt csar policy
				PolicyInfo policyInfo = new PolicyInfo();
				Artifact policyArtifact = csarProcessor.getArtifactByName(csar, csar.getManifest().getMainAttributes().getValue(Constant.MANIFEST_ENTRY_POLICY_FILE_KEY));
				if (policyArtifact != null) {
					policyInfo.init(policyArtifact);
					csarProcessor.setEncFlagOfArtifacts(csar, policyInfo);
					
					// Updaing Manfifest file (encrypting files and adding their entry in manifest)
					String encAlg = request.getEncAlg();
					securityProcessor.encryptCsar(request.getEncryptedBy(), request.getEncryptorContact(), keystore, request.getKeystoreInfo(), encAlg, csar, policyInfo.getDecryptionMode());
					
					// Generate encrypted csar
					byte[] csarBytes = csarProcessor.generateCsar(csar);
					
					if (request.getKeystoreInfo().getJksFile() == null) {
						byte[] packedZip = new ResponseProcessor().packCsarWithKeystore(keystore, request.getKeystoreInfo(), request.getCsarName(), csarBytes);
						String responseFileName = request.getCsarName() + "_and_keytsore.zip";
						response.setName(responseFileName);
						response.setData(packedZip);
						response.addResponseMsg(new ResponseMessage(MessageType.SUCCESS,
							responseFileName + " has been generated, which contains encrypted CSAR and a keystore that you can use to decrypt the CSAR."));
					} else {
						String responseFileName = request.getCsarName();
						response.setName(responseFileName);
						response.setData(csarBytes);
						response.addResponseMsg(new ResponseMessage(MessageType.SUCCESS,
							responseFileName + " has been generated which is your encrypted CSAR. You can use the same provided keystore to decrypt the CSAR."));
					}
				} else {
					response = new EncryptCsarResponse();
					response.setStatusCode(StatusCode.ERROR);
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.RESPONSE_ERROR_MISSING_POLCY_CONFIG));
				}
			} else {
				response.setStatusCode(StatusCode.ERROR);
			}
		} catch (Exception ex) {
			LOGGER.log(Level.ERROR, ex.getMessage(), ex);
			response = new EncryptCsarResponse();
			response.setStatusCode(StatusCode.ERROR);
			
			if (ex instanceof ConfigurationException) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.RESPONSE_ERROR_INVALID_POLICY_CONFIG));
			} else {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.RESPONSE_ERROR_MSG_UNEXPECTED_ERROR));
			}
		}

		return response;
	}
}
