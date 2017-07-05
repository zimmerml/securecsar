package de.uni.stuttgart.iaas.securecsar.util;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.io.FileUtils;

public class FileUtil {
	
	public String storeFileAndGetDownloadLink(String fileName, byte[] data) throws Exception {
		String downloadFilesContainer = ConfigUtil.getInstance().getProperty("download.files.container");
		SimpleDateFormat timestampFormat = new SimpleDateFormat("yyyyMMddHHmmssSSS");
		Date now = new Date();
	    String timestampString = timestampFormat.format(now);
		String filePath = downloadFilesContainer + File.separator + timestampString + "_" + fileName;
		FileUtils.writeByteArrayToFile(new File(filePath), data);
		return "/downloadfile/" + timestampString + "_" + fileName;
	}
}
