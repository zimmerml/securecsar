package de.uni.stuttgart.iaas.securecsar.util;

import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.FileBasedConfiguration;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import de.uni.stuttgart.iaas.securecsar.info.Constant;

public class ConfigUtil {
	private static final Logger LOGGER = LogManager.getLogger();
	private static ConfigUtil myObj;
	private Configuration config;

	private ConfigUtil() throws Exception {
		Parameters params = new Parameters();
		FileBasedConfigurationBuilder<FileBasedConfiguration> builder = new FileBasedConfigurationBuilder<FileBasedConfiguration>(
				PropertiesConfiguration.class).configure(params.properties().setFileName(Constant.CONFIG_FILE_NAME));
		try {
			this.config = builder.getConfiguration();
		} catch (ConfigurationException cex) {
			LOGGER.log(Level.ERROR, "Could not initialize configuration properties", cex);
			throw cex;
		}
	}

	/**
	 * Static method to get instance.
	 */
	public static ConfigUtil getInstance() throws Exception{
		if (myObj == null) {
			myObj = new ConfigUtil();
		}
		return myObj;
	}

	public String getProperty(String propName) {
		return config.getString(propName);
	}
}
