package de.uni.stuttgart.iaas.securecsar.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import de.uni.stuttgart.iaas.securecsar.util.ConfigUtil;

@RestController
public class DownloadFileService {
	private static final Logger LOGGER = LogManager.getLogger();

	@RequestMapping(value = "/downloadfile/{file_name:.+}", method = RequestMethod.GET)
	public void getFile(@PathVariable("file_name") String fileName, HttpServletResponse response) {
		try {
			// get your file as InputStream
			String containerPath = ConfigUtil.getInstance().getProperty("download.files.container");
			File downloadFile = new File(containerPath + File.separator + fileName);
			InputStream is = new FileInputStream(downloadFile);
			String downloadFilename = fileName.substring(fileName.indexOf("_") + 1);
			response.setHeader("Content-disposition", "attachment; filename="+ downloadFilename);
			// copy it to response's OutputStream
			org.apache.commons.io.IOUtils.copy(is, response.getOutputStream());
			response.flushBuffer();
			downloadFile.delete();
		} catch (Exception ex) {
			LOGGER.log(Level.ERROR, "Error writing file to output stream. Filename was '{}'", fileName , ex);
		}
	}
}