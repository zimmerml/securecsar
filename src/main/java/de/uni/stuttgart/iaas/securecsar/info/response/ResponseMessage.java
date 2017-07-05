package de.uni.stuttgart.iaas.securecsar.info.response;

public class ResponseMessage {
	private MessageType messageType;
	private String messageValue;
	public MessageType getMessageType() {
		return messageType;
	}
	public void setMessageType(MessageType messageType) {
		this.messageType = messageType;
	}
	public String getMessageValue() {
		return messageValue;
	}
	public void setMessageValue(String messageValue) {
		this.messageValue = messageValue;
	}
	public ResponseMessage() {
		super();
		// TODO Auto-generated constructor stub
	}
	public ResponseMessage(MessageType messageType, String messageValue) {
		super();
		this.messageType = messageType;
		this.messageValue = messageValue;
	}
}
