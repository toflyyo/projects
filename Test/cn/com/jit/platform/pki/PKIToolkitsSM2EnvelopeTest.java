package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.*;

import org.junit.Test;

public class PKIToolkitsSM2EnvelopeTest extends BasePKIToolKitsTest {

	/**
	 * 国密信封单元测试
	 */
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_success_sm2_envelope_and_without_base64() {

		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 4, PLAIN, handleResult);

		// 测试结果
		assertSuccess(handleResult);
	}

	@Test
	public void should_return_success_sm2_envelope_and_with_base64() {

		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 6, PLAINBASE, handleResult);
		// 测试结果
		assertSuccess(handleResult);
	}

	@Test
	public void should_return_plain_is_null_sm2_envelope_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 4, null, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_public_key_cert_is_null_with_base64() {
		// 测试执行
		pkiTool.p7Envelope(null, PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 6, PLAINBASE, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_symmetricarithmetictype_is_null_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, null, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_plain_is_empty_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 4, "".getBytes(), handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_public_key_cert_is_empty_without_base64() {
		// 测试执行
		pkiTool.p7Envelope("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_type_is_empty_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, "", 4, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);

	}

	@Test
	public void should_return_flag_is_negtive_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, -1, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_public_cert_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p7Envelope("&^%$8".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_type_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, "\\/;:", 4, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_plain_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SM2_SIGN_CER, PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 4, "[]^!~".getBytes(), handleResult);
		// 测试结果
		assertSuccess(handleResult);
	}

	/**
	 * GM解信封
	 */

	@Test
	public void should_right_without_base64_sm_decrypt_envelope() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(SM2_PRVKEY, 0, ENVELOPEDATA_SM2, handleResult);
		// 测试结果
		assertSuccess(handleResult);
	}

	@Test
	public void should_return_right_with_base64_sm_decrypt_envelope() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(SM2_PRVKEY, 2, ENVELOPEDATA_SM2_BASE64, handleResult);
		// 测试结果
		assertSuccess(handleResult);
	}

	@Test
	public void should_return_private_key_is_null_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(null, 0, ENVELOPEDATA_SM2, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_envelopedate_is_null_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, 0, null, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_private_key_is_empty_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope("".getBytes(), 0, ENVELOPEDATA_SM2, handleResult);
		// 测试结果
		assertFailed(handleResult);

	}

	@Test
	public void should_return_envelopedate_is_empty() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, 0, "".getBytes(), handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_flag_is_negtive_decrypt_envelope_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, -1, ENVELOPEDATA_SM2, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_private_key_is_special_decrypt_envelope_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope("<>".getBytes(), 0, ENVELOPEDATA_SM2, handleResult);
		// 测试结果
		assertFailed(handleResult);

	}

	@Test
	public void should_return_envelopedate_is_special_character_decrypt_envelope_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, 0, "%^&*@!".getBytes(), handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

}
