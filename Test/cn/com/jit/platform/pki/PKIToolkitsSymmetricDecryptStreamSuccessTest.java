package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.IV;
import static cn.com.jit.platform.pki.SignHelper.SYMMETRICARITHMETICTYPE_DES_CBC_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SYMMETRICKEY;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import cn.com.jit.cloud.common.Base64Utils;
import cn.com.jit.platform.childprocess.core.ByteBufToBytes;

@RunWith(Parameterized.class)
public class PKIToolkitsSymmetricDecryptStreamSuccessTest extends BasePKIToolKitsTest {
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = {
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, SYMMETRICARITHMETICTYPE_DES_CBC_RESULT },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, SYMMETRICKEY, IV,
						SYMMETRICARITHMETICTYPE_DES_CBC_RESULT },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, SYMMETRICKEY, IV,
						SignHelper.SYMMETRICARITHMETICTYPE_DES_EDE3_RESULT },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, SYMMETRICKEY, IV,
						SignHelper.SYMMETRICARITHMETICTYPE_DES_ECB_RESULT },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, SYMMETRICKEY, IV,
						Base64Utils.decode(SignHelper.SYMMETRICARITHMETICTYPE_SM4_ECB_RESULT) },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, SYMMETRICKEY, IV,
						SignHelper.SYMMETRICARITHMETICTYPE_RC4_RESULT },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, SYMMETRICKEY, IV,
						SignHelper.SYMMETRICARITHMETICTYPE_AES_128_CBC_RESULT },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, SYMMETRICKEY, IV,
						SignHelper.SYMMETRICARITHMETICTYPE_AES_128_ECB_RESULT } };
		return Arrays.asList(objects);
	}

	private String	symmetricArithmetic;
	private byte[]	symmetricKey;
	private byte[]	iv;
	private byte[]	encryptData;
	private ByteBuf	plainTmp	= Unpooled.buffer();

	public PKIToolkitsSymmetricDecryptStreamSuccessTest(String symmetricArithmetic, byte[] symmetricKey, byte[] iv,
			byte[] encryptData) {
		this.symmetricArithmetic = symmetricArithmetic;
		this.symmetricKey = symmetricKey;
		this.iv = iv;
		this.encryptData = encryptData;
	}

	@Test
	public void testSymmetricalEncryption() {
		HandleResult decryptionResult = new HandleResult();
		pkiTool.symmetricalDecryptionInit(symmetricArithmetic, symmetricKey, iv, encryptData.length, decryptionResult);
		long handle = decryptionResult.handle;
		for (int i = 0; i < encryptData.length; i++) {
			pkiTool.symmetricalDecryptionUpdate(handle, new byte[] { encryptData[i] }, decryptionResult);
			if (decryptionResult.resultData != null) {
				plainTmp.writeBytes(decryptionResult.resultData);
			}
		}
		pkiTool.symmetricalDecryptionFinal(handle, decryptionResult);
		if (decryptionResult.resultData != null) {
			plainTmp.writeBytes(decryptionResult.resultData);
		}

		ByteBufToBytes reader = new ByteBufToBytes();
		byte[] plainResult = reader.read(plainTmp);
		Assert.assertTrue(Arrays.equals(plainResult, SignHelper.PLAIN));
	}
}
