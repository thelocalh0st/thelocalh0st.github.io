---
title: <img width="50" height="50" alt="img" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/b15cfb83-bf16-49a4-b5f7-511473deae65"> S3 Bucket Misconfiguration!  
date: 2023-12-22 07:00:02 +730
categories: [Resources, bugbounty]
tags: [s3-misconfiguration,bug-bounty,100-days-of-cybersecurity] # TAG names should always be lowercase
mermaid: true

---


<h1 style="color: cyan; text-align: center">100 Day's Of Cybersecurity - Day 13</h1>

![Amazon-Web-Services-S3-Penetration-1054296230](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/b15cfb83-bf16-49a4-b5f7-511473deae65){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

#  Misconfigurations Of S3 Bucket

## Introduction:

Amazon S3 buckets, a fundamental component of cloud storage, are often a target for security researchers and VAPT (Vulnerability Assessment and Penetration Testing) analysts due to their prevalence in cloud infrastructures. In this blog post, we'll explore the steps and commands to identify and exploit S3 bucket misconfigurations, showcasing their potential impact.

## Prerequisites:

Before diving into the techniques, ensure you have the `AWS CLI` installed and configured with the necessary access key and secret key.

1. **Listing Bucket Items:**

The first step is to check if you can list items within the target S3 bucket.

```bash
aws s3 ls s3://<bucket name>
```

This command attempts to access the bucket and list its contents. If unsuccessful, try the following to bypass signature verification:

```bash
aws s3 ls s3://<bucket name> --no-sign-request
```

2. **Testing Access and Exploitation:**

If listing the items fails, it's time to check if you can perform more critical operations like moving or deleting files.

Create a test file:

```bash
echo "Testing purpose" >> test.txt
```

Attempt to move the file into the bucket:

```bash
aws s3 mv test.txt s3://<bucket name>
```

Additionally, try copying a file from your local drive to the S3 bucket:

```bash
aws s3 cp test.txt s3://<bucket name>/test.txt
```

If successful, this indicates a vulnerability. On the other hand, if any errors occur, the bucket may not be exploitable.

3. **Deleting Files from the Bucket:**

Check if you can delete files within the bucket:

```bash
aws s3 rm s3://<bucket name>/test.txt
```

This command attempts to remove the test file from the bucket. If the operation is successful, it further confirms the misconfiguration.

Additional Considerations:

- **Bucket Permissions:** Examine the bucket's permissions using the AWS Management Console or CLI to ensure proper access controls are in place.

- **Bucket Policies:** Review and analyze the bucket policies to identify any overly permissive settings.

- **Logging and Monitoring:** Check if logging and monitoring are enabled for the S3 bucket to detect any unauthorized access or suspicious activities.

<iframe width="560" height="315" src="https://www.youtube.com/embed/ITSZ8743MUk?si=pJdm5ihfcd65GVqe" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

## Conclusion:

Identifying and exploiting Amazon S3 bucket misconfigurations is crucial for securing cloud infrastructures. Security researchers and VAPT analysts play a pivotal role in identifying and mitigating these vulnerabilities. Regular assessments and adherence to security best practices are essential to prevent unauthorized access and potential data breaches.

References:
- [AWS CLI Documentation](https://aws.amazon.com/cli/)
- [Amazon S3 Documentation](https://aws.amazon.com/s3/)
- [https://hackerone.com/reports/229690](https://hackerone.com/reports/229690)


  
![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
