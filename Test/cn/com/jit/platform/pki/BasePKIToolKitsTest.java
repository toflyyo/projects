package cn.com.jit.platform.pki;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

public class BasePKIToolKitsTest {

	public static PKIToolkits	pkiTool;

	static {
		pkiTool = new PKIToolkits();
		pkiTool.loadLibrary();
	}

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		SignHelper.init();
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {}

	@Before
	public void setUp() throws Exception {}

	@After
	public void tearDown() throws Exception {}

}
