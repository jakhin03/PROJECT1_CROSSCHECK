package API;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class Test {
	public static void main(String[] args) {
		ClamAVService clamAVService = new ClamAVService();
		File file = new File("/home/tung/Downloads");
		// File file = new File("abc.text");

		VirusScanResult scanResult = null;
		try {
			if (clamAVService.ping()) {
				try (InputStream inputStream = new FileInputStream(file)) {
					scanResult = clamAVService.scan(inputStream);
				} catch (IOException e) {
					System.out.println("An error occurred while scanning file., " + e.getMessage());
					scanResult = new VirusScanResult(VirusScanStatus.FAILED, e.getMessage());
				}
			} else {
				System.out.println("ClamAV did not respond to ping request!");
				scanResult = new VirusScanResult(VirusScanStatus.CONNECTION_FAILED,
						"ClamAV did not respond to ping request!");
			}
		} catch (Exception e) {
			System.out.println("An error occurred while scanning file., " + e.getMessage());
			scanResult =
					new VirusScanResult(VirusScanStatus.ERROR, "An error occurred while scanning file.");
		}

		System.out.println(scanResult);
		}
}
