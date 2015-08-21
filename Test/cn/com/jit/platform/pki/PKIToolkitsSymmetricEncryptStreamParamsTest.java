package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.IV;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.SYMMETRICKEY;

import org.junit.Test;

public class PKIToolkitsSymmetricEncryptStreamParamsTest extends BasePKIToolKitsTest {
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_empty_symmetricArithmetic() {
		pkiTool.symmetricalEncryptionInit("", SYMMETRICKEY, IV, PLAIN.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_null_symmetricArithmetic() {
		pkiTool.symmetricalEncryptionInit(null, SYMMETRICKEY, IV, PLAIN.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_invalid_symmetricArithmetic() {
		pkiTool.symmetricalEncryptionInit("*[]", SYMMETRICKEY, IV, PLAIN.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_empty_symmetricKey() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, new byte[0], IV, PLAIN.length,
				handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_null_symmetricKey() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, null, IV, PLAIN.length,
				handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_invalid_symmetricKey() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SignHelper.ZERO, IV,
				PLAIN.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_empty_iv() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, new byte[0],
				PLAIN.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_null_iv() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, null,
				PLAIN.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_invalid_iv() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, SignHelper.ZERO,
				PLAIN.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionInit_with_invalid_plainDataLength() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, -1,
				handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_success_when_symmetricalEncryptionInit() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, PLAIN.length,
				handleResult);
		SignHelper.assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionUpdate_with_invalid_handle() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, PLAIN.length,
				handleResult);
		pkiTool.symmetricalEncryptionUpdate(-1, PLAIN, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionUpdate_with_empty_plainData() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, PLAIN.length,
				handleResult);
		pkiTool.symmetricalEncryptionUpdate(handleResult.handle, new byte[0], handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionUpdate_with_null_plainData() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, PLAIN.length,
				handleResult);
		pkiTool.symmetricalEncryptionUpdate(handleResult.handle, null, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_success_when_symmetricalEncryptionUpdate() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, PLAIN.length,
				handleResult);
		pkiTool.symmetricalEncryptionUpdate(handleResult.handle, PLAIN, handleResult);
		SignHelper.assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalEncryptionFinal_with_invalid_handle() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, PLAIN.length,
				handleResult);
		pkiTool.symmetricalEncryptionUpdate(handleResult.handle, PLAIN, handleResult);
		pkiTool.symmetricalEncryptionFinal(-1, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_success_when_symmetricalEncryptionFinal() {
		pkiTool.symmetricalEncryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, PLAIN.length,
				handleResult);
		long handle = handleResult.handle;
		pkiTool.symmetricalEncryptionUpdate(handle, PLAIN, handleResult);
		pkiTool.symmetricalEncryptionFinal(handle, handleResult);
		SignHelper.assertSuccessSymmetricKey(handleResult);
	}
}
