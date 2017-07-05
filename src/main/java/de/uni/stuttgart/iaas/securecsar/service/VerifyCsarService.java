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

import de.uni.stuttgart.iaas.securecsar.executor.VerifyCsarExecutor;
import de.uni.stuttgart.iaas.securecsar.info.request.VerifyCsarRequest;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.info.response.StatusCode;
import de.uni.stuttgart.iaas.securecsar.info.response.VerifyCsarResponse;

@RestController
@RequestMapping("/verify")
public class VerifyCsarService {
	private static final Logger LOGGER = LogManager.getLogger();
	
	@RequestMapping(method = RequestMethod.POST, consumes = { "multipart/form-data" }, produces = "application/json")
	public ResponseEntity<VerifyCsarResponse> encrypt(
		@RequestParam(name="csarFile", required=false) MultipartFile csarFile,
		VerifyCsarRequest request) {
		VerifyCsarResponse response = null;
		HttpStatus httpStatus = HttpStatus.OK;
		
		try {
						
			if (csarFile != null) {
				request.setCsar(csarFile.getBytes());
			}

			VerifyCsarExecutor executor = new VerifyCsarExecutor();
			response = executor.execute(request);
			
			if (!response.getStatusCode().equals(StatusCode.SUCCESS)) {
				httpStatus = HttpStatus.NOT_ACCEPTABLE;
			}
		} catch (Exception ex) {
			LOGGER.log(Level.ERROR, "Error while executing service", ex);
			response = new VerifyCsarResponse();
			response.setStatusCode(StatusCode.ERROR);
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, "Something went wrong while executing request."));
		}
		
		return new ResponseEntity<VerifyCsarResponse>(response, httpStatus);
	}
}