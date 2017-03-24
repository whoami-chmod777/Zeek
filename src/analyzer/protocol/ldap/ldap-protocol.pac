# Generated by binpac_quickstart

# ## This is where we define the LDAP PDU structure according to RFC 4511
# ## some examples:

# Types are your basic building blocks.
# There are some builtins, or you can define your own.
# Here's a definition for a regular expression:
# type LDAP_WHITESPACE = RE/[ \t]*/;

%include ../asn1/asn1.pac
%include ldap-types.pac


type Common_PDU(is_orig: bool) = record {
	messageID	        :   ASN1Integer;
	protocolOp_meta     :   ASN1EncodingMeta;	
	what_prot			:	PDU(protocolOp_meta.tag, messageID, is_orig);

};


type PDU(choice: uint8, messageID : ASN1Integer, is_orig : bool) = case choice of {
	default -> unknown	:	UnknownOp(choice); 
};

refine casetype PDU += {
	#PDU Choices from RFC 4511
	0x66	->	mod_req		:	ModifyReqPDU(messageID);
	0x67	->	mod_res		:	ModifyResPDU(messageID);
	0x68    ->  add_req     :   AddReqPDU(messageID);
	0x69    ->  add_res     :   AddResPDU(messageID);
	0x6a    ->  del_req     :   DeleteReqPDU(messageID);
	0x6b	->	del_res		:	DeleteResPDU(messageID);
	0x6c	->	modDN_req	:	ModifyDNReqPDU(messageID);
	0x6d	->	modDN_res	:	ModifyDNResPDU(messageID);
};


type ModifyReqPDU(messageID : ASN1Integer) = record {
	object				: ASN1OctetString;
	big_seq				: ASN1SequenceMeta;
	mods				: ModificationControl[]; 

};


type ModificationControl() = record {
	meta				: ASN1EncodingMeta;
	appmeta1			: uint8;
	appmeta2			: uint8;
	mod_or_control		: case appmeta1 of {
		0x0a	->	mod	:	Modification;
		default ->	data: bytestring &restofdata;
	};
};

type Modification() = record {
	op					: uint8;
	partialmeta			: ASN1SequenceMeta;
	type				: ASN1OctetString;
	valmeta				: ASN1EncodingMeta;
	val					: ASN1OctetString;
};



type ModifyResPDU(messageID : ASN1Integer) = record {
	result				: LDAPResult(messageID);
};


type ModifyDNReqPDU(messageID : ASN1Integer) = record {
	entry				: ASN1OctetString;
	newrdn				: ASN1OctetString;
	boolmeta			: uint16;
	deleteoldrdn		: uint8;
	stringmeta			: uint8;
	stringlen			: uint8;
	newSuperior			: bytestring &length = stringlen;
};

type ModifyDNResPDU(messageID : ASN1Integer) = record {
	result      :   LDAPResult(messageID);
};

type DeleteReqPDU(messageID: ASN1Integer) = record  {
	request :	bytestring &restofdata;
};

type DeleteResPDU(messageID: ASN1Integer) = record  {
    result  : LDAPResult(messageID);
};

type AddReqPDU(messageID: ASN1Integer) = record  {  
	entry   : ASN1OctetString; 
    attributes  : AttributeList;
};

type AttributeList() = record  {
    meta        :   ASN1SequenceMeta;
	atts		:	Attribute[];    

};

type Attribute() = record {
	header		:	ASN1SequenceMeta;
	control_check: case header.encoding.tag of {
		0x30	->	att		: AttributeItem;
		default	->	control	: bytestring &restofdata;	
	};	
};

type AttributeItem() = record {
	type		:	ASN1OctetString;
	valseq		:	ASN1EncodingMeta;
	val			:	ASN1OctetString;
};

type AddResPDU(messageID: ASN1Integer) = record  {
    result      :   LDAPResult(messageID);
};

type LDAPResult(messageID: ASN1Integer) = record  {
    result_meta     : uint16;
    result          : uint8;
    matchedDN       : ASN1OctetString;
    error           : ASN1OctetString;
};

type UnknownOp(choice : uint8) = record {
	data :	bytestring &restofdata &transient;
};



