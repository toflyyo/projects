package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.ZERO;
import static cn.com.jit.platform.pki.SignHelper.assertFailP1Sign;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP1;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import cn.com.jit.cloud.common.Base64Utils;

public class PKIToolkitsP1SignStreamParamsTest extends BasePKIToolKitsTest {
	private HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_fail_when_signInit_with_empty_privateKey() {
		pkiTool.p1SignInit(new byte[0], PKIToolkits.DIGEST_SHA1, 0, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_when_signInit_with_null_privateKey() {
		pkiTool.p1SignInit(null, PKIToolkits.DIGEST_SHA1, 0, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_when_signInit_with_invalid_privateKey() {
		pkiTool.p1SignInit(ZERO, PKIToolkits.DIGEST_SHA1, 0, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_when_signInit_with_empty_digestArithmetic() {
		pkiTool.p1SignInit(PRVKEY, "", 0, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_when_signInit_with_null_digestArithmetic() {
		pkiTool.p1SignInit(PRVKEY, null, 0, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_when_signInit_with_invalid_digestArithmetic() {
		pkiTool.p1SignInit(PRVKEY, "*[]", 0, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_when_signInit_with_invalid_flag() {
		pkiTool.p1SignInit(PRVKEY, PKIToolkits.DIGEST_SHA1, -1, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_success_when_signInit() {
		pkiTool.p1SignInit(PRVKEY, PKIToolkits.DIGEST_SHA1, 0, handleResult);
		assertTrue(handleResult.errorCode == 0L);
		assertTrue(handleResult.handle > 0L);
	}

	@Test
	public void should_return_fail_when_signUpdate_with_invalid_handle() {
		pkiTool.p1SignUpdate(-1l, PLAIN, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_when_signUpdate_with_null_plainData() {
		pkiTool.p1SignInit(PRVKEY, PKIToolkits.DIGEST_SHA1, 0, handleResult);
		pkiTool.p1SignUpdate(handleResult.handle, null, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_when_signUpdate_with_empty_plainData() {
		pkiTool.p1SignInit(PRVKEY, PKIToolkits.DIGEST_SHA1, 0, handleResult);
		pkiTool.p1SignUpdate(handleResult.handle, new byte[0], handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_success_when_signUpdate() {
		pkiTool.p1SignInit(PRVKEY, PKIToolkits.DIGEST_SHA1, 0, handleResult);
		pkiTool.p1SignUpdate(handleResult.handle, PLAIN, handleResult);
		assertTrue(handleResult.errorCode == 0L);
	}

	@Test
	public void should_return_fail_when_signFinal_with_invalid_handle() {
		pkiTool.p1SignFinal(-1l, handleResult);
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_success_when_signFinal() {
		pkiTool.p1SignInit(PRVKEY, PKIToolkits.DIGEST_SHA1, 0, handleResult);
		long handle = handleResult.handle;
		pkiTool.p1SignUpdate(handle, PLAIN, handleResult);
		pkiTool.p1SignFinal(handle, handleResult);
		handleResult.setResultData(Base64Utils.encode(handleResult.getResultData()));
		assertSuccessP1(handleResult);
	}
}
