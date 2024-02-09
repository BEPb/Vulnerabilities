###### Expanding archive files without controlling resource consumption is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 10min

Successful Zip Bomb attacks occur when an application expands untrusted archive files without controlling the size of the expanded data, which can lead to denial of service. A Zip bomb is usually a malicious archive file of a few kilobytes of compressed data but turned into gigabytes of uncompressed data. To achieve this extreme compression ratio, attackers will compress irrelevant data (eg: a long string of repeated bytes).

###### Ask Yourself Whether

Archives to expand are untrusted and:

    There is no validation of the number of entries in the archive.
    There is no validation of the total size of the uncompressed data.
    There is no validation of the ratio between the compressed and uncompressed archive entry.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

File f = new File("ZipBomb.zip");
ZipFile zipFile = new ZipFile(f);
Enumeration<? extends ZipEntry> entries = zipFile.entries(); // Sensitive

while(entries.hasMoreElements()) {
  ZipEntry ze = entries.nextElement();
  File out = new File("./output_onlyfortesting.txt");
  Files.copy(zipFile.getInputStream(ze), out.toPath(), StandardCopyOption.REPLACE_EXISTING);
}



######## Recommended Secure Coding Practices

    Define and control the ratio between compressed and uncompressed data, in general the data compression ratio for most of the legit archives is 1 to 3.
    Define and control the threshold for maximum total size of the uncompressed data.
    Count the number of file entries extracted from the archive and abort the extraction if their number is greater than a predefined threshold, in particular it’s not recommended to recursively expand archives (an entry of an archive could be also an archive).

Compliant Solution

Do not rely on getsize to retrieve the size of an uncompressed entry because this method returns what is defined in the archive headers which can be forged by attackers, instead calculate the actual entry size when unzipping it:

File f = new File("ZipBomb.zip");
ZipFile zipFile = new ZipFile(f);
Enumeration<? extends ZipEntry> entries = zipFile.entries();

int THRESHOLD_ENTRIES = 10000;
int THRESHOLD_SIZE = 1000000000; // 1 GB
double THRESHOLD_RATIO = 10;
int totalSizeArchive = 0;
int totalEntryArchive = 0;

while(entries.hasMoreElements()) {
  ZipEntry ze = entries.nextElement();
  InputStream in = new BufferedInputStream(zipFile.getInputStream(ze));
  OutputStream out = new BufferedOutputStream(new FileOutputStream("./output_onlyfortesting.txt"));

  totalEntryArchive ++;

  int nBytes = -1;
  byte[] buffer = new byte[2048];
  int totalSizeEntry = 0;

  while((nBytes = in.read(buffer)) > 0) { // Compliant
      out.write(buffer, 0, nBytes);
      totalSizeEntry += nBytes;
      totalSizeArchive += nBytes;

      double compressionRatio = totalSizeEntry / ze.getCompressedSize();
      if(compressionRatio > THRESHOLD_RATIO) {
        // ratio between compressed and uncompressed data is highly suspicious, looks like a Zip Bomb Attack
        break;
      }
  }

  if(totalSizeArchive > THRESHOLD_SIZE) {
      // the uncompressed data size is too much for the application resource capacity
      break;
  }

  if(totalEntryArchive > THRESHOLD_ENTRIES) {
      // too much entries in this archive, can lead to inodes exhaustion of the system
      break;
  }
}

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-409 - Improper Handling of Highly Compressed Data (Data Amplification)
    CERT, IDS04-J. - Safely extract files from ZipInputStream
    bamsoftware.com - A better Zip Bomb
