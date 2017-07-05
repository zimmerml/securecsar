package de.uni.stuttgart.iaas.securecsar.service;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import de.uni.stuttgart.iaas.securecsar.executor.EncryptCsarExecutor;
import de.uni.stuttgart.iaas.securecsar.info.KeystoreInfo;
import de.uni.stuttgart.iaas.securecsar.info.request.EncryptCsarRequest;
import de.uni.stuttgart.iaas.securecsar.info.response.EncryptCsarResponse;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.info.response.StatusCode;
import de.uni.stuttgart.iaas.securecsar.util.FileUtil;

@RestController
@RequestMapping("/encrypt")
public class EncryptCsarService {
	private static final Logger LOGGER = LogManager.getLogger();
	
	@RequestMapping(method = RequestMethod.POST, consumes = { "multipart/form-data" }, produces = "application/json")
	public ResponseEntity<EncryptCsarResponse> encrypt(
		@RequestParam(name="csarFile", required=false) MultipartFile csarFile,
		@RequestParam(name="keystoreFile", required=false) MultipartFile keystoreFile,
		EncryptCsarRequest request) {
		EncryptCsarResponse response = null;
		HttpStatus httpStatus = HttpStatus.OK;
		
		try {
						
			if (csarFile != null) {
				request.setCsarName(csarFile.getOriginalFilename());
				request.setCsar(csarFile.getBytes());
			}
			
			if (keystoreFile != null) {
				if (request.getKeystoreInfo() == null) {
					request.setKeystoreInfo(new KeystoreInfo());
				}
				request.getKeystoreInfo().setJksFile(keystoreFile.getBytes());;
				request.getKeystoreInfo().setKeystoreName(keystoreFile.getOriginalFilename());
			}

			EncryptCsarExecutor executor = new EncryptCsarExecutor();
			response = executor.execute(request);
			
			if (response.getStatusCode().equals(StatusCode.SUCCESS)) {
				FileUtil fileUtil = new FileUtil();
				String downloadLink = fileUtil.storeFileAndGetDownloadLink(response.getName(), response.getData());
				response.setDownloadLink(downloadLink);
				response.setData(null);
				response.setName(null);
			} else {
				httpStatus = HttpStatus.NOT_ACCEPTABLE;
			}
		} catch (Exception ex) {
			LOGGER.log(Level.ERROR, "Error while executing service", ex);
			response = new EncryptCsarResponse();
			response.setStatusCode(StatusCode.ERROR);
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, "Something went wrong while executing request."));
		}
		
		return new ResponseEntity<EncryptCsarResponse>(response, httpStatus);
	}
}