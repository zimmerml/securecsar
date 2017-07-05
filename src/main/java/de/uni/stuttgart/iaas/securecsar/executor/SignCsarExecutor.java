package de.uni.stuttgart.iaas.securecsar.executor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyStore;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.uni.stuttgart.iaas.securecsar.info.Artifact;
import de.uni.stuttgart.iaas.securecsar.info.Constant;
import de.uni.stuttgart.iaas.securecsar.info.Csar;
import de.uni.stuttgart.iaas.securecsar.info.PolicyInfo;
import de.uni.stuttgart.iaas.securecsar.info.SignatureBlockInfo;
import de.uni.stuttgart.iaas.securecsar.info.SignatureFileInfo;
import de.uni.stuttgart.iaas.securecsar.info.request.SignCsarRequest;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.info.response.SignCsarResponse;
import de.uni.stuttgart.iaas.securecsar.info.response.StatusCode;
import de.uni.stuttgart.iaas.securecsar.processor.CsarProcessor;
import de.uni.stuttgart.iaas.securecsar.processor.ResponseProcessor;
import de.uni.stuttgart.iaas.securecsar.processor.SecurityProcessor;
import de.uni.stuttgart.iaas.securecsar.util.StringUtil;
import de.uni.stuttgart.iaas.securecsar.validator.SignCsarRequestValidator;

public class SignCsarExecutor {

	private static final Logger LOGGER = LogManager.getLogger();

	public SignCsarResponse execute(SignCsarRequest request) {
		InputStream iosForKeysstore = null;
		SignCsarResponse response = new SignCsarResponse();
		response.setStatusCode(StatusCode.SUCCESS);
		
		try {
			SignCsarRequestValidator validator = new SignCsarRequestValidator();
			
			if (validator.validate(request, response)) {
				SecurityProcessor securityProcessor = new SecurityProcessor();
				KeyStore keystore = null;
				
				if (request.getKeystoreInfo().getJksFile() == null) {
					keystore = securityProcessor.generateKeyStore(true, request.getKeystoreInfo().getKeystorePass(),
						request.getKeystoreInfo().getEntry());
				} else {
					// make keystore object from provided byte array
					iosForKeysstore = new ByteArrayInputStream(request.getKeystoreInfo().getJksFile());
					keystore = KeyStore.getInstance("JCEKS");
					keystore.load(iosForKeysstore, request.getKeystoreInfo().getKeystorePass().toCharArray());
				}
				
				String sigFileName = StringUtil.genSignatureFileName(request.getSigfile(), request.getKeystoreInfo().getEntry().getAliasName(), true);
				String sigBlockName = StringUtil.genSignatureBlockName(request.getSigfile(), request.getKeystoreInfo().getEntry().getAliasName(), request.getSigalg(), true);
				// Creating csar object from .casr file in request
				Csar csar = new Csar(request.getCsarName(), request.getCsar(), sigFileName, sigBlockName, false);
				CsarProcessor csarProcessor = new CsarProcessor();
				// Getting sign csar policy
				PolicyInfo policyInfo = new PolicyInfo();
				Artifact policyArtifact = csarProcessor.getArtifactByName(csar, csar.getManifest().getMainAttributes().getValue(Constant.MANIFEST_ENTRY_POLICY_FILE_KEY));
				
				if (policyArtifact != null) {
					policyInfo.init(policyArtifact);
					csarProcessor.setSignFlagOfArtifacts(csar, policyInfo);
					
					//Updaing Manfifest file (making digest for each file and adding its entry)
					String digestAlg = request.getDigestalg();
					securityProcessor.addManifestDigests(digestAlg, csar);
					
					// Generation of signature file from csar
					SignatureFileInfo sigFileInfo = new SignatureFileInfo(Constant.META_INF + File.separator + sigFileName, digestAlg, csar);
					csar.setSigFileInfo(sigFileInfo);
					
					// Generation of signature block file
					byte[] signatureBlockBytes = securityProcessor.generateSignature(request.getKeystoreInfo(), keystore, request.getSigalg(), sigFileInfo.getData());
					SignatureBlockInfo sigBlockInfo = new SignatureBlockInfo(Constant.META_INF + File.separator + sigBlockName, signatureBlockBytes);
					csar.setSigBlockInfo(sigBlockInfo);
					
					// Generate signed csar
					byte[] csarBytes = csarProcessor.generateCsar(csar);
					
					if (request.getKeystoreInfo().getJksFile() == null) {
						byte[] packedZip = new ResponseProcessor().packCsarWithKeystore(keystore, request.getKeystoreInfo(), request.getCsarName(), csarBytes);
						String responseFileName = request.getCsarName() + "_and_keytsore.zip";
						response.setName(responseFileName);
						response.setData(packedZip);
						response.addResponseMsg(new ResponseMessage(MessageType.SUCCESS,
							responseFileName + " has been generated, which contains signed CSAR and your new keystore"));
					} else {
						String responseFileName = request.getCsarName();
						response.setName(responseFileName);
						response.setData(csarBytes);
						response.addResponseMsg(new ResponseMessage(MessageType.SUCCESS,responseFileName + " has been generated which is your signed CSAR."));
					}
				} else {
					response = new SignCsarResponse();
					response.setStatusCode(StatusCode.ERROR);
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.RESPONSE_ERROR_MISSING_POLCY_CONFIG));
				}
			} else {
				response.setStatusCode(StatusCode.ERROR);
			}
		} catch (Exception ex) {
			LOGGER.log(Level.ERROR, ex.getMessage(), ex);
			response = new SignCsarResponse();
			response.setStatusCode(StatusCode.ERROR);
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.RESPONSE_ERROR_MSG_UNEXPECTED_ERROR));
		}

		return response;
	}
}
