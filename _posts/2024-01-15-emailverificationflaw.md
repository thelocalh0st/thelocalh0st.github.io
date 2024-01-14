---
title: <img width="50" height="50" alt="img" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/7a2dbdf9-ffd0-4b1e-bf9c-2f6af62e74aa">  Access Control Flaw in Email Verification 📧
date: 2024-01-15 07:00:02 +730
categories: [Resources, bugbounty]
tags: [access-control-flaw,bug-bounty,100-days-of-cybersecurity] # TAG names should always be lowercase
mermaid: true

---

<h1 style="color: cyan; text-align: center">100 Day's Of Cybersecurity - Day 15</h1>

![email_verification_blog_banner-2742088540](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/7a2dbdf9-ffd0-4b1e-bf9c-2f6af62e74aa){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }




## Introduction:

Email verification is a crucial step in securing online accounts, ensuring that users have valid and accessible email addresses. However, not all verification processes are foolproof. In this blog post, we'll explore a significant access control flaw discovered in an email verification process, demonstrating how attackers could potentially exploit such vulnerabilities. We'll use examples from a real-world scenario and capture the interactions using Burp Suite.

## Understanding the Vulnerability:

The vulnerability lies in the lax access controls during the email verification process. In a typical scenario, a user creates an account, receives a verification email, and clicks on a link to confirm their email address. However, our exploit involves changing the email address associated with the account after receiving the verification email.

Example Request-Response Scenario (Captured in Burp Suite):

1. **Account Creation:**
   - User registers with a valid email address and receives an email with a verification link.

    Request:
    ```
    POST /api/register
    {
        "username": "example_user",
        "email": "valid@example.com",
        "password": "securepassword"
    }
    ```

    Response:
    ```
    200 OK
    Verification email sent to valid@example.com
    ```

2. **Email Change Exploit:**
   - The user changes their email to a non-existent address, e.g., "fake@example.com," before verifying the initial email.

    Request:
    ```
    POST /api/change-email
    {
        "new_email": "fake@example.com"
    }
    ```

    Response:
    ```
    200 OK
    Email changed successfully. Verification email sent to fake@example.com
    ```

3. **Exploiting Verification Token:**
   - The attacker retrieves the verification link from the initial email (sent to "valid@example.com") and uses it to verify the non-existent email ("fake@example.com").

    Request:
    ```
    GET /api/verify-email?token=verification_token
    ```

    Response:
    ```
    200 OK
    Email fake@example.com verified successfully.
    ```

## Impact and Mitigation:

This access control flaw allows attackers to validate non-existent email addresses, potentially leading to account takeover or abuse. To mitigate this issue, the system should implement stricter access controls during the email verification process. For example, preventing email address changes after the verification process has started or requiring additional authentication for email changes can enhance security.

## Conclusion:

This blog post has highlighted a real-world access control flaw in the email verification process. By understanding such vulnerabilities, developers and security professionals can work together to implement robust security measures, ensuring the integrity of user accounts and maintaining a secure online environment. Stay tuned for more insights into cybersecurity and best practices for safeguarding digital platforms.

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
