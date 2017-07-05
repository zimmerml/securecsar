package de.uni.stuttgart.iaas.securecsar.info.response;

import java.util.ArrayList;

public class Response {
	private StatusCode statusCode;
	private ArrayList<ResponseMessage> responseMsgs;
	
	public StatusCode getStatusCode() {
		return statusCode;
	}
	public void setStatusCode(StatusCode statusCode) {
		this.statusCode = statusCode;
	}
	public ArrayList<ResponseMessage> getResponseMsgs() {
		return responseMsgs;
	}
	public void setResponseMsgs(ArrayList<ResponseMessage> responseMsgs) {
		this.responseMsgs = responseMsgs;
	}
	public void addResponseMsg(ResponseMessage responseMsg) {
		if (responseMsgs == null) {
			responseMsgs = new ArrayList<ResponseMessage>();
		}
		
		responseMsgs.add(responseMsg);
	}
}
