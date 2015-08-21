package cn.com.jit.signhp.protocol;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import cn.com.jit.assp.css.client.util.Base64;
import cn.com.jit.platform.pki.BasePKIToolKitsTest;
import cn.com.jit.platform.pki.SignHelper;

public class MessageProtocolTest extends BasePKIToolKitsTest {
	private static Map<String, MessageNodeType>	ruleData_p1			= new LinkedHashMap<String, MessageNodeType>();
	private static Map<String, MessageNodeType>	ruleData_p7			= new LinkedHashMap<String, MessageNodeType>();
	private static Map<String, MessageNodeType>	ruleData_signature	= new LinkedHashMap<String, MessageNodeType>();
	private static Map<String, MessageNodeType>	ruleData	= new LinkedHashMap<String, MessageNodeType>();
	@Before
	public void init() {
		ruleData_p1.put("DSignContext", MessageNodeType.NODE);
		ruleData_p1.put("DSignContext.Version", MessageNodeType.ATTRIBUTE);
		ruleData_p1.put("Request.svcid", MessageNodeType.ATTRIBUTE);
		ruleData_p1.put("PlainData", MessageNodeType.NODE);
		ruleData_p1.put("DSDigestALG", MessageNodeType.NODE);
		ruleData_p7.put("DSignContext.Version", MessageNodeType.ATTRIBUTE);
		ruleData_p7.put("Request.svcid", MessageNodeType.ATTRIBUTE);
		ruleData_p7.put("Pkcs7SignData", MessageNodeType.NODE);
		ruleData_p7.put("Type", MessageNodeType.NODE);
		ruleData_signature.put("DSignData.verifyMode", MessageNodeType.ATTRIBUTE);
		ruleData_signature.put("DSBaseInfo", MessageNodeType.CHILDNODE);
		ruleData_signature.put("DSCertBaseInfo", MessageNodeType.CHILDNODE);

		
		ruleData.put("DSignContext.Version", MessageNodeType.ATTRIBUTE);
		ruleData.put("Request.svcid", MessageNodeType.ATTRIBUTE);
		ruleData.put("PlainData.type", MessageNodeType.ATTRIBUTE);
		ruleData.put("DSignContext.Version", MessageNodeType.ATTRIBUTE);
		ruleData.put("Request.svcid", MessageNodeType.ATTRIBUTE);
		ruleData.put("DSignData.verifyMode", MessageNodeType.ATTRIBUTE);
		ruleData.put("VerifySignCertIssuerAndSN.paramType", MessageNodeType.ATTRIBUTE);
		ruleData.put("DSBaseInfo", MessageNodeType.CHILDNODE);
		ruleData.put("DSCertBaseInfo", MessageNodeType.CHILDNODE);
		ruleData.put("CertAlias", MessageNodeType.CHILDNODE);
		ruleData.put("alias.type", MessageNodeType.ATTRIBUTE);
	}

	@Test
	public void should_p1_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.P1MESSAGE), ruleData_p1);
		Assert.assertNotNull(req);
	}

	@Test
	public void should_contain_parameter_svcid_on_p1_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.P1MESSAGE), ruleData_p1);
		String expected = "doDSign";
		Assert.assertEquals(expected, req.get("Request.svcid"));
		;
	}

	@Test
	public void should_contain_parameter_plainData_on_p1_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.P1MESSAGE), ruleData_p1);
		String expected = "原文的Base64编码";
		Assert.assertEquals(expected, req.get("PlainData"));
	}

	@Test
	public void should_p7_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.P7MESSAGE), ruleData_p7);
		Assert.assertNotNull(req);
	}

	@Test
	public void should_contain_parameter_pkcs7SignData_on_p7_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.P7MESSAGE), ruleData_p7);
		String expected = "";
		Assert.assertEquals(expected, req.get("Pkcs7SignData"));
	}

	@Test
	public void should_signature_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.SIGNATUR_EMESSAGE), ruleData_signature);
		Assert.assertNotNull(req);
	}

	@Test
	public void should_contain_parameter_verifyMode_on_signature_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.SIGNATUR_EMESSAGE), ruleData_signature);
		String expected = "4";
		Assert.assertEquals(expected, req.get("DSignData.verifyMode"));
	}

	@Test
	public void should_contain_parameter_digestalg_in_DSBaseInfo__on_signature_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.SIGNATUR_EMESSAGE), ruleData_signature);
		String expected = "digestalg";
		@SuppressWarnings("unchecked")
		List<Map<String, String>> items = (List<Map<String, String>>) req.get("DSBaseInfo");
		for (Map<String, String> item : items) {
			for(String s : item.keySet()){
				if (s.equals(expected)) {
					Assert.assertEquals(expected, s);
				}
			}
		}
	}

	@Test
	public void should_contain_parameter_issuerdn_in_DSCertBaseInfo__on_signature_message_protocol_byteToMessage_return_request() {
		Map<String,Object> req = new LinkedHashMap<String,Object>();
		req = new MessageParser().parser(Base64.decode(SignHelper.SIGNATUR_EMESSAGE), ruleData_signature);
		String expected = "issuerdn";
		String value = "测试";
		@SuppressWarnings("unchecked")
		List<Map<String, String>> items = (List<Map<String, String>>) req.get("DSCertBaseInfo");
		for (Map<String, String> item : items) {
			for(String s : item.keySet()){
				if (s.equals(expected)) {
					Assert.assertEquals(value, item.get(s));
				}
			}
		}
	}
	@Test
	public void should_return_xml_for_p7_messageparser_parser(){
		Map<String,Object> resMap = new LinkedHashMap<String,Object>();
		resMap.put("DSignContext.Version", "1.0");
		resMap.put("Response.svcid", "verifyDSign");
		resMap.put("verifyDSignResult.status", "true");
		resMap.put("fileName", "");
		
		Map<String,Object> item1 = new LinkedHashMap<String,Object>();
		item1.put("subjectdn", "C=cn,O=jit,E=normal@jit.com.cn,CN=normal");
		item1.put("issuerdn", "C=CN,O=JIT,CN=DemoCA");
		item1.put("serialnumber", "453502305e804779");
		item1.put("version", "3");
		resMap.put("ReturnContent/DSCertInfo",item1);
		Map<String,Object> item2 = new LinkedHashMap<String,Object>();
		item2.put("digestalg", "SHA1");
		item2.put("digestdata", "YdfUvU2J0JdnfgGawiokR/7cMSg=".getBytes());
		item2.put("dscert", null);
		item2.put("plaindata", null);
		resMap.put("ReturnContent/DSInfo",item2);
		MessageParser s = new MessageParser();
		String actual = new String(s.parser(resMap));
		String expected = new String(Base64.decode(SignHelper.P7_DATA2XML));
		expected = expected.replaceAll("\r\n", "");
		Assert.assertEquals(expected, actual);
	}
	@Test
	public void should_return_xml_for_p1_messageparser_parser(){
		Map<String,Object> resMap = new LinkedHashMap<String,Object>();
		resMap.put("DSignContext.Version", "1.0");
		resMap.put("Response.svcid", "doDSign");
		resMap.put("doDSignResult.status", "true");
		resMap.put("DSignData.stream", "true");
		
		MessageParser s = new MessageParser();
		String actual = new String(s.parser(resMap));
		String expected = new String(Base64.decode(SignHelper.P1_DATA2XML));
		expected = expected.replaceAll("\r\n", "");
		Assert.assertEquals(expected, actual);
	}
	@Test
	public void should_return_xml_for_timestamp_messageparser_parser(){
		Map<String,Object> resMap = new LinkedHashMap<String,Object>();
		resMap.put("DSignContext.Version", "1.0");
		resMap.put("Response.svcid", "verifyTsa");
		resMap.put("verifyDSignResult.status", "true");
		resMap.put("fileName", "");
		
		Map<String,Object> item1 = new LinkedHashMap<String,Object>();
		item1.put("plaindata", "hvfkN/qlp/zhXR3cuerq6jd2Z7g=".getBytes());
		item1.put("digestalg", "SHA1");
		item1.put("signedTime", "20110301160410GMT+08:00");
		resMap.put("ReturnContent/DSInfo",item1);
		Map<String,String> item2 = new LinkedHashMap<String,String>();
		item2.put("subjectdn", "C=cn,O=jit,O=signserver,CN=RSA_1024_0");
		item2.put("issuerdn", "C=cn,O=jit,OU=signserver,CN=RSACA");
		item2.put("serialnumber", "65");
		item2.put("version", "3");
		resMap.put("ReturnContent/DSCertInfo",item2);
		MessageParser s = new MessageParser();
		String actual = new String(s.parser(resMap));
		String expected = new String(Base64.decode(SignHelper.TIMESTAMP_DATA2XML));
		expected = expected.replaceAll("\r\n", "");
		Assert.assertEquals(expected, actual);
	}
	//娴嬭瘯 p1 楠岀  鎸夌収鎴戠殑瑙勫垯瑙ｆ瀽鍑烘纭殑瀵硅薄 
	@Test
	public void shuold_return_map_for_p1_attestation_rule_data(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.P1_VERIFY), ruleData);
		Map<String,Object> attrs = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_map_for_p1_attestation_rule_data(attrs);
		for(String key : map.keySet()){
			Assert.assertEquals(attrs.get(key), map.get(key)); 
		}
	}
	private void initMapFor_shuold_return_map_for_p1_attestation_rule_data(Map<String,Object> expectedMap){
		expectedMap.put("PlainData", "dGVzdA==");
		expectedMap.put("DSignData", "qxlhJrhF4Zzr7ZrEgr/BOcVSjbEgAUzq1cuDdhUDiAHI2u6d85v33Bc5UVgQpyDd67qtCIYKneovnoKO/pgD9UHPDA+LaOFuKNmoEOaemVCxMp5hJbR5DSz3vSdvBpiH9ZkTWEQlnSNdNZcfk5tgb6zEFvQZgvgr5Ht0d5ix2Ek=");
		expectedMap.put("VerifySignCertIssuerAndSN", "rsa");
		expectedMap.put("DSDigestALG", "sha1");
		expectedMap.put("EncAlg", "des3");
		expectedMap.put("DSignContext.Version", "1.0");
		expectedMap.put("Request.svcid", "verifyDSign");
		expectedMap.put("PlainData.type", "dsds");
		expectedMap.put("DSignData.verifyMode", "3");
		expectedMap.put("VerifySignCertIssuerAndSN.paramType", "dsCert");
		
		List<Map<String,String>> items1 = new ArrayList<Map<String,String>>();
		Map<String, String> item1 = new LinkedHashMap<String,String>();
		item1.put("name", "digestalg");
		item1.put("Item", "");
		items1.add(item1);
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "digestdata");
		item1.put("Item", "");
		items1.add(item1);
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "plaindata");
		item1.put("Item", "");
		items1.add(item1);
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "dscert");
		item1.put("Item", "");
		items1.add(item1);
		expectedMap.put("DSBaseInfo", items1);
		
		items1 = new ArrayList<Map<String,String>>();
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "version");
		item1.put("Item", "");
		items1.add(item1);
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "issuerdn");
		item1.put("Item", "");
		items1.add(item1);
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "subjectdn");
		item1.put("Item", "");
		items1.add(item1);
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "serialnumber");
		item1.put("Item", "");
		items1.add(item1);
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "notbefore");
		item1.put("Item", "");
		items1.add(item1);
		item1 = new LinkedHashMap<String,String>();
		item1.put("name", "notafter");
		item1.put("Item", "");
		items1.add(item1);
		expectedMap.put("DSCertBaseInfo", items1);
		/*items1.add(value);
		items1.put("Item", value);
		expectedMap.put("DSBaseInfo", items1);
		Map<String, String> items2 = new LinkedHashMap<String,String>();
		expectedMap.put("DSCertBaseInfo", items2);*/
	}
	//娴嬭瘯 p1 楠岀  鎸夌収鎴戠殑瑙勫垯瑙ｆ瀽鍑烘纭殑瀵硅薄  plainDataType
	@Test
	public void shuold_return_map_for_p1_attestation_rule_data_plainDataType(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.P1_VERIFY_PLAINDATA_TYPE), ruleData);
		Map<String,Object> attrs = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_map_for_p1_attestation_rule_data(attrs);
		Assert.assertEquals(attrs.get("plainData.Type"), map.get("plainData.Type"));
	}
	@Test
	public void should_return_map_p7_doSign_rule_data_plainDataType(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.P7_DOSIGN), ruleData);
		Map<String,Object> attrs = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_map_for_p7_doSign_rule_data(attrs);
		for(String key : map.keySet()){
			Assert.assertEquals(attrs.get(key), map.get(key)); 
		}
	}
	//鍒濆鍖�p7绛惧悕鏁版嵁
	private void initMapFor_shuold_return_map_for_p7_doSign_rule_data(Map<String,Object> expectedMap){
		expectedMap.put("DSignContext.Version", "1.0");
		expectedMap.put("Request.svcid", "doDSign");
		expectedMap.put("ApplyID", "");
		expectedMap.put("PlainData.type", "0");
		expectedMap.put("PlainData", "YQ==");
		expectedMap.put("DSignMode", "3");
		expectedMap.put("DSDigestALG", "SHA1");
	}
	@Test
	public void should_return_map_for_timestamp_doSign_rule_data(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.TIMESTAMP_DOSIGN), ruleData);
		Map<String,Object> attrs = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_map_for_timestamp_doSign_rule_data(attrs);
		for(String key : map.keySet()){
			Assert.assertEquals(attrs.get(key), map.get(key)); 
		}
	}
	//初始化 时间戳 签名map
	private void initMapFor_shuold_return_map_for_timestamp_doSign_rule_data(Map<String,Object> expectedMap){
		expectedMap.put("DSignContext.Version", "1.0");
		expectedMap.put("Request.svcid", "WScreateTimeStampResponse");
		expectedMap.put("TimeStampRequest", " ");
	}
	@Test
	public void should_return_map_for_timestamp_verify_rule_data(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.TIMESTAMP_VERIFY), ruleData);
		Map<String,Object> attrs = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_map_for_timestamp_verify_rule_data(attrs);
		for(String key : map.keySet()){
			Assert.assertEquals(attrs.get(key), map.get(key)); 
		}
	}
	//初始化 时间戳 验证map
	private void initMapFor_shuold_return_map_for_timestamp_verify_rule_data(Map<String,Object> expectedMap){
		expectedMap.put("DSignContext.Version", "1.0");
		expectedMap.put("Request.svcid", "verifyTsa");
		expectedMap.put("TsaData.type", "rfc3161");
		expectedMap.put("TsaData", " ");
		
		List<Map<String, String>> items = new ArrayList<Map<String,String>>();
		Map<String, String> item = new LinkedHashMap<String,String>();
		item.put("name", "digestalg");
		item.put("Item", "");
		items.add(item);
		item = new LinkedHashMap<String,String>();
		item.put("name", "plaindata");
		item.put("Item", "");
		items.add(item);
		expectedMap.put("DSBaseInfo", items);
		
		items = new ArrayList<Map<String,String>>();
		item = new LinkedHashMap<String,String>();
		item.put("name", "version");
		item.put("Item", "");
		items.add(item);
		item = new LinkedHashMap<String,String>();
		item.put("name", "issuerdn");
		item.put("Item", "");
		items.add(item);
		item = new LinkedHashMap<String,String>();
		item.put("name", "subjectdn");
		item.put("Item", "");
		items.add(item);
		item = new LinkedHashMap<String,String>();
		item.put("name", "serialnumber");
		item.put("Item", "");
		items.add(item);
		expectedMap.put("DSCertBaseInfo", items);
	}
	@Test
	public void should_return_map_for_symmery_dosign_rule_data(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.SIMMETRY_DOSIGN), ruleData);
		Map<String,Object> attrs = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_map_for_symmery_dosign_rule_data(attrs);
		for(String key : map.keySet()){
			Assert.assertEquals(attrs.get(key), map.get(key)); 
		}
	}
	//初始化  对称加解密 签名map
	private void initMapFor_shuold_return_map_for_symmery_dosign_rule_data(Map<String,Object> expectedMap){
		expectedMap.put("DSignContext.Version", "1.0");
		expectedMap.put("Request.svcid", "doSymEncrypt");
		expectedMap.put("PlainData", "YWFhYWFhYWE=");
		expectedMap.put("KeyID", "test.00000");
	}
	//对称加解密签名响应 返回xml
	@Test
	public void should_return_xml_for_symmery_dosign_response_rule_data(){
		MessageParser s = new MessageParser();
		String expectedXml = new String(Base64.decode(SignHelper.SIMMETRY_DOSIGN_RESPONSE));
		Map<String,Object> attrs = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_xml_for_symmery_dosign_response_rule_data(attrs);
		String assertXml = new String(s.parser(attrs));
		Assert.assertEquals(expectedXml.replaceAll("\r\n", ""), assertXml);
	}
	//初始化  对称加解密 签名map
	private void initMapFor_shuold_return_xml_for_symmery_dosign_response_rule_data(Map<String,Object> assertMap){
		assertMap.put("DSignContext.Version", "1.0");
		assertMap.put("Response.svcid", "doSymEncrypt");
		assertMap.put("doSymEncryptResult", "");
		assertMap.put("doSymEncryptResult.status", "true");
		assertMap.put("EncryptedData", "acs7Mu6u6tk=");
	}
	@Test
	public void should_return_map_for_symmery_verify_rule_data(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.SIMMETRY_VERIFY), ruleData);
		Map<String,Object> attrs = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_map_for_symmery_verify_rule_data(attrs);
		for(String key : map.keySet()){
			Assert.assertEquals(attrs.get(key), map.get(key)); 
		}
	}
	//初始化 对称加解密 验证map
	private void initMapFor_shuold_return_map_for_symmery_verify_rule_data(Map<String,Object> expectedMap){
		expectedMap.put("DSignContext.Version", "1.0");
		expectedMap.put("Request.svcid", "doSymDecrypt");
		expectedMap.put("EncryptedData", "ueKXhg3fqgQ=");
		expectedMap.put("KeyID", "test.00000");
	}
	// 对称加解密 验签 响应测试
	@Test
	public void should_return_xml_for_symmery_verify_response_rule_data(){
		MessageParser s = new MessageParser();
		String expectedXml = new String(Base64.decode(SignHelper.SIMMETRY_VERIFY_RESPONSE));
		Map<String,Object> assertMap = new LinkedHashMap<String,Object>();
		initMapFor_shuold_return_xml_for_symmery_verify_response_rule_data(assertMap);
		String assertXml = new String(s.parser(assertMap));
		Assert.assertEquals(expectedXml.replaceAll("\r\n", ""), assertXml); 
	}
	//初始化 对称加解密 验证map
	private void initMapFor_shuold_return_xml_for_symmery_verify_response_rule_data(Map<String,Object> assertMap){
		assertMap.put("DSignContext.Version", "1.0");
		assertMap.put("Response.svcid", "doSymDecrypt");
		assertMap.put("doSymDecryptResult.status", "true");
		assertMap.put("doSymDecryptResult", "");
		assertMap.put("PlainData", "YQ==");
	}
	
	@Test
	public void should_return_map_for_envelop_doSign_rule_data(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.ENVELOP_DOSIGN), ruleData);
		Map<String,Object> expected = new LinkedHashMap<String,Object>();
		initMapFor_should_return_map_for_envelop_doSign_rule_data(expected);
		for(String key : map.keySet()){
			Assert.assertEquals(expected.get(key), map.get(key)); 
		}
	}
	//初始化 信封签名 map
	private void initMapFor_should_return_map_for_envelop_doSign_rule_data(Map<String,Object> expectedMap){
		expectedMap.put("DSignContext.Version", "1.0");
		expectedMap.put("Request.svcid", "doEnvelop");
		expectedMap.put("PlainData", "");
		expectedMap.put("PlainData.type", "default");
		List<Map<String,String>> items = new ArrayList<Map<String,String>>();
		Map<String,String> item = new LinkedHashMap<String,String>();
		item.put("alias", "test");
		items.add(item);
		expectedMap.put("CertAlias", items);
		expectedMap.put("alias", "test");
		expectedMap.put("EncAlg", "");
		expectedMap.put("DSDigestALG", "");
	}
	/**
	 * 信封签名 响应
	 */
	@Test
	public void should_return_xml_for_envelop_doSign_response_rule_data(){
		MessageParser s = new MessageParser();
		String expectedXml = new String(Base64.decode(SignHelper.ENVELOP_DOSIGN_RESPONSE));
		Map<String,Object> accessMap = new LinkedHashMap<String,Object>();
		initMapFor_should_return_xml_for_envelop_doSign_response_rule_data(accessMap);
		String accessXml = new String(s.parser(accessMap));
		Assert.assertEquals(expectedXml.replaceAll("\r\n", ""),accessXml); 
	}
	//初始化 信封签名 map 用于response的响应
	private void initMapFor_should_return_xml_for_envelop_doSign_response_rule_data(Map<String,Object> accessMap){
		accessMap.put("DSignContext.Version", "2.0");
		accessMap.put("Response.svcid", "doEnvelop");
		accessMap.put("doEnvelopResult", "");
		accessMap.put("doEnvelopResult.status", "true");
		accessMap.put("EnvelopData", "");
		accessMap.put("EnvelopData.stream", "true");
	}
	
	@Test
	public void should_return_map_for_envelop_verify_rule_data(){
		MessageParser s = new MessageParser();
		Map<String,Object> map = s.parser(Base64.decode(SignHelper.ENVELOP_VERIFY), ruleData);
		Map<String,Object> expected = new LinkedHashMap<String,Object>();
		initMapFor_should_return_map_for_envelop_verify_rule_data(expected);
		for(String key : map.keySet()){
			Assert.assertEquals(expected.get(key), map.get(key)); 
		}
	}
	//初始化 信封签名 map
	private void initMapFor_should_return_map_for_envelop_verify_rule_data(Map<String,Object> expectedMap){
		expectedMap.put("DSignContext.Version", "1.0");
		expectedMap.put("Request.svcid", "verifyEnvelop");
		expectedMap.put("EnvelopData", "");
		
		List<Map<String, String>> items = new ArrayList<Map<String,String>>();
		Map<String,String> item = new LinkedHashMap<String,String>();
		item.put("name", "plaindata");
		item.put("Item", "");
		items.add(item);
		item = new LinkedHashMap<String,String>();
		item.put("name", "dscert");
		item.put("Item", "");
		items.add(item);
		expectedMap.put("DSBaseInfo", items);
		items = new ArrayList<Map<String,String>>();
		item = new LinkedHashMap<String,String>();
		item.put("name", "sn");
		item.put("Item", "");
		items.add(item);
		item = new LinkedHashMap<String,String>();
		item.put("name", "version");
		item.put("Item", "");
		items.add(item);
		item = new LinkedHashMap<String,String>();
		item.put("name", "subjectdn");
		item.put("Item", "");
		items.add(item);
		item = new LinkedHashMap<String,String>();
		item.put("name", "issuerdn");
		item.put("Item", "");
		items.add(item);
		expectedMap.put("DSCertBaseInfo", items);
	}
	/**
	 * 根据map 对象返回xml ; 业务 信封验证响应
	 */
	@Test
	public void should_return_map_for_envelop_verify_response_rule_data(){
		MessageParser s = new MessageParser();
		String expectedXml = new String(Base64.decode(SignHelper.ENVELOP_VERIFY_RESPONSE));
		Map<String,Object> accessMap = new LinkedHashMap<String,Object>();
		initMapFor_should_return_map_for_envelop_verify_response_rule_data(accessMap);
		String accessXml = new String(s.parser(accessMap));
		Assert.assertEquals(expectedXml.replaceAll("\r\n", ""),accessXml); 
	}
	//初始化 信封签名 map
	private void initMapFor_should_return_map_for_envelop_verify_response_rule_data(Map<String,Object> accessMap){
		accessMap.put("DSignContext.Version", "1.0");
		accessMap.put("Response.svcid", "verifyEnvelop");
		accessMap.put("verifyEnvelopResult", "");
		accessMap.put("verifyEnvelopResult.status", "true");
		
		Map<String,Object> items = new LinkedHashMap<String,Object>();
		items.put("serialnumber", "453502305e804779");
		items.put("version", "3");
		items.put("subjectdn", "C=cn,O=jit,E=normal@jit.com.cn,CN=normal");
		items.put("issuerdn", "C=CN,O=JIT,CN=DemoCA");
		accessMap.put("ReturnContent/DSCertInfo", items);
		items = new LinkedHashMap<String,Object>();
		items.put("plaindata", "YQ==".getBytes());
		accessMap.put("ReturnContent/DSInfo", items);
	}
	/*@Test
	public void myTest(){
		try {
			System.out.println(new String(Base64.encode(FileUtils.readByteFromFile(new File("f:/t.txt")))));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}*/
}
