package de.uni.stuttgart.iaas.securecsar.util;

public final class StringUtil {
	public static boolean isEmpty(String value){
        if (value == null || "".equals(value)) {
        	return true;
        } else {
        	return false;
        }
    }
	
	/**
	 * This function return combination of hash and encryption algorithm string
	 * based on key algorithm. If the algorithm is DSA, then string is
	 * SHA1withDSA, If the algorithm is RSA then SHA256withRSA algorithm, and if
	 * keys is EC then string is SHA256withECDSA.
	 * 
	 * This function can be used to set default value of sigAlg
	 * 
	 * @param keyAlgo
	 */
	public static String getDigestAlgoCombination(String keyAlgo) {
		if ("DSA".equals(keyAlgo)) {
			return "SHA1withDSA";
		} else if ("RSA".equals(keyAlgo)) {
			return "SHA256withRSA";
		} else {
			return null;
		}
	}
	
	public static String getManifestDigestAttrName(String digestAlgo) {
		String digestAlgoUppercase = digestAlgo.toUpperCase();
		digestAlgoUppercase = digestAlgoUppercase + "-Digest";
		return  digestAlgoUppercase;
	}
	
	public static String genSignatureFileName(String sigfile, String alias, boolean appendExtension) {
		if (StringUtil.isEmpty(sigfile)) {
			sigfile = alias;
		}
		
		if (sigfile.length() > 8) {
			sigfile = sigfile.substring(0, 8);
		} 
		
		sigfile = sigfile.toUpperCase();
		
		// convert illegal characters from the alias to be _'s
		StringBuilder tmpName = new StringBuilder(sigfile.length());
	
		for (int j = 0; j < sigfile.length(); j++) {
			char c = sigfile.charAt(j);
		    if (!((c>= 'A' && c<= 'Z') || (c>= '0' && c<= '9') || (c == '-') || (c == '_'))) {
		    	c = '_';
		    }
		    
		    tmpName.append(c);
		}
		
		sigfile = tmpName.toString();
		
		if (appendExtension) {
			sigfile = sigfile + ".SF";
		}
		
		return sigfile;
	}
	
	public static String genSignatureBlockName(String sigfile, String alias, String sigAlg, boolean appendExtension) {
		if (StringUtil.isEmpty(sigfile)) {
			sigfile = alias;
		}
		
		if (sigfile.length() > 8) {
			sigfile = sigfile.substring(0, 8);
		} 
		
		sigfile = sigfile.toUpperCase();
		
		// convert illegal characters from the alias to be _'s
		StringBuilder tmpName = new StringBuilder(sigfile.length());
	
		for (int j = 0; j < sigfile.length(); j++) {
			char c = sigfile.charAt(j);
		    if (!((c>= 'A' && c<= 'Z') || (c>= '0' && c<= '9') || (c == '-') || (c == '_'))) {
		    	c = '_';
		    }
		    
		    tmpName.append(c);
		}
		
		sigfile = tmpName.toString();
		
		if (appendExtension) {
			String extension = sigAlg.split("with")[1];
			sigfile = sigfile + "." + extension;
		}
		
		return sigfile;
	}
	
	/**
     * Adds line breaks to enforce a maximum 72 bytes per line.
     */
//    public static String make72Safe(String entry, String prefix) throws Exception{
//    	
//    	StringBuffer buffer = new StringBuffer(prefix);
//        if (entry != null) {
//            byte[] vb = entry.getBytes("UTF8");
//            entry = new String(vb, "UTF-8");
//        }
//        buffer.append(entry);
//        buffer.append("\r\n");
//        
//        
//        int length = buffer.length();
//        if (length > 72) {
//            int index = 70;
//            while (index < length - 2) {
//            	buffer.insert(index, "\r\n ");
//                index += 72;
//                length += 3;
//            }
//        }
//        return buffer.toString();
//    }
}
