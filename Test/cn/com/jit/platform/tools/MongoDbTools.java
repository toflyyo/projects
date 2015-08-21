package cn.com.jit.platform.tools;

import java.io.File;
import java.io.FileWriter;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cn.com.jit.cloud.common.DateFormatter;
import cn.com.jit.cloud.common.dao.MongoLogDao;
import cn.com.jit.cloud.common.dao.MongoManager;

// 清除数据
public class MongoDbTools {
	private static Logger	logger	= LoggerFactory.getLogger(MongoDbTools.class);

	public static void main(String[] args) throws Exception {
		loopCleanBusinessLog();
	}

	// 循环清空业务日志数据
	private static void loopCleanBusinessLog() throws Exception {
		int i = 1;
		File log = new File("log.txt");
		try (FileWriter logWriter = new FileWriter(log)) {
			while (true) {
				try {
					long count = cleanBusinessLog();
					String msg = "第" + i + "次 " + DateFormatter.formatDate(new Date())
							+ " : number of removed data is " + count + " .\n";
					logger.info(msg);
					logWriter.write(msg);
					logWriter.flush();
					i++;
					Thread.sleep(1000 * 60);
				} catch (InterruptedException e) {
					e.printStackTrace();
					logWriter.write(e.getMessage() + "\n");
					logWriter.write(e.toString() + "\n");
					logWriter.flush();
				}
			}
		}
	}

	private static long cleanBusinessLog() {
		MongoLogDao logDao = new MongoLogDao();
		MongoManager mongo = new MongoManager();
		long count = logDao.find("tb_sign_business_log").size();
		mongo.dropCollection(logDao.getDbName(), "tb_sign_business_log");
		return count;
	}
}
