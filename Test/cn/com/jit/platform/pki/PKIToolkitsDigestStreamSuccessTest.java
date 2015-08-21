package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import cn.com.jit.cloud.common.Base64Utils;

@RunWith(Parameterized.class)
public class PKIToolkitsDigestStreamSuccessTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { 
				{ PKIToolkits.DIGEST_SHA1, PLAIN,handleResult},
				{ PKIToolkits.DIGEST_SHA256, PLAIN,handleResult},
				{ PKIToolkits.DIGEST_MD5, PLAIN,handleResult},
				{ PKIToolkits.DIGEST_SM3, PLAIN,handleResult}
		};
		return Arrays.asList(objects);
	}

	private String digestArithmeticType;
	private byte[] originalData;
	private HandleResult out;

	public PKIToolkitsDigestStreamSuccessTest(String digestArithmeticType, byte[] originalData,HandleResult out) {
		super();
		this.digestArithmeticType = digestArithmeticType;
		this.originalData = originalData;
		this.out=out;
	}

	@Test
	public void digestStreamTest() {
		try {
			pkiTool.digestInit(digestArithmeticType,out);
		} catch (Exception e) {
			e.printStackTrace();
		}
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		while (true) {
			int end = index + step;
			if(end > originalData.length){
				end = originalData.length;
				blocks = new byte[originalData.length-index];
			}
			blocks = Arrays.copyOfRange(originalData, index, end);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.digestUpdate(out.handle, blocks, resultTmp);
			if(resultTmp.errorCode!=0) throw new RuntimeException("digest error ...");
			if(index>=originalData.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.digestFinal(out.handle, resultTmp);
		HandleResult oldOut = new HandleResult();
		pkiTool.digest(digestArithmeticType, originalData, oldOut);
		System.out.println(new String(Base64Utils.encode(oldOut.resultData)));
		System.out.println(new String(Base64Utils.encode(resultTmp.resultData)));
		Assert.assertArrayEquals(oldOut.resultData ,resultTmp.resultData);
	}
}
