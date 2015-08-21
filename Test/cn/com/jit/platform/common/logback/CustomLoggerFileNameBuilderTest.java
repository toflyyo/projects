package cn.com.jit.platform.common.logback;

import junit.framework.Assert;

import org.junit.BeforeClass;
import org.junit.Test;

public class CustomLoggerFileNameBuilderTest {
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		LogConfiguration.init(9000, 1);
	}

	@Test
	public void should_return_null_with_null_file_name() {
		String file = null;
		CustomLoggerFileNameBuilder builder = new CustomLoggerFileNameBuilder(file);
		Assert.assertNull(builder.customFileName());
	}

	@Test
	public void should_return_empty_with_empty_file_name() {
		String file = "";
		CustomLoggerFileNameBuilder builder = new CustomLoggerFileNameBuilder(file);
		Assert.assertEquals("", builder.customFileName());
	}

	@Test
	public void should_return_correct_result_with_no_dir_file_name() {
		String file = "mainprocess.log";
		CustomLoggerFileNameBuilder builder = new CustomLoggerFileNameBuilder(file);
		Assert.assertEquals("1/mainprocess.log", builder.customFileName());
	}

	@Test
	public void should_return_correct_result_with_absolute_dir_file_name() {
		String file = "/logs/2014/02/13/mainprocess.zip";
		CustomLoggerFileNameBuilder builder = new CustomLoggerFileNameBuilder(file);
		Assert.assertEquals("/logs/2014/02/13/1/mainprocess.zip", builder.customFileName());
	}

	@Test
	public void should_return_correct_result_with_relative_dir_file_name() {
		String file = "logs/2014/02/13/mainprocess.zip";
		CustomLoggerFileNameBuilder builder = new CustomLoggerFileNameBuilder(file);
		Assert.assertEquals("logs/2014/02/13/1/mainprocess.zip", builder.customFileName());
	}
}
