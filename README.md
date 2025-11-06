# Web eID for Mobile: electronic identity cards on mobile devices

## Table of Contents

* [Introduction](#introduction)
    * [Authentication (via NFC)](#authentication-via-nfc)
    * [Signing documents (via NFC)](#signing-documents-via-nfc)
    * [Web eID project websites](#web-eid-project-websites)
    * [Requirements notation and conventions](#requirements-notation-and-conventions)
    * [Glossary](#glossary)
* [Design choices](#design-choices)
    * [Overview of the current Open eID implementation](#overview-of-the-current-open-eid-implementation)
    * [Problems of the current implementation](#problems-of-the-current-implementation)
    * [Principles of the new technical design](#principles-of-the-new-technical-design)
* [Requirements for the new solution](#requirements-for-the-new-solution)
    * [Support for other security tokens besides smart cards](#support-for-other-security-tokens-besides-smart-cards)
* [New solution architecture](#new-solution-architecture)
    * [Technical overview of authentication and digital signing](#technical-overview-of-authentication-and-digital-signing)
        * [Authentication and WebAuthn](#authentication-and-webauthn)
        * [Authenticated identity](#authenticated-identity)
        * [Authentication and TLS Token Binding](#authentication-and-tls-token-binding)
        * [Protection against man\-in\-the\-middle attacks during authentication with origin validation](#protection-against-man-in-the-middle-attacks-during-authentication-with-origin-validation)
        * [Digital signing](#digital-signing)
    * [Security analysis](#security-analysis)
    * [JavaScript library](#javascript-library)
    * [Web eID authentication token specification](#web-eid-authentication-token-specification)
        * [Token format](#token-format)
        * [Requesting a Web eID authentication token](#requesting-a-web-eid-authentication-token)
    * [Native application](#native-application)
        * [General](#general)
        * [PKI operations](#pki-operations)
    * [Implementation guide and example applications](#implementation-guide-and-example-applications)
* [References](#references)

## Introduction

The Web eID for Mobile project enables secure authentication and digital signing using Estonian electronic identity (eID) cards over NFC on Android and iOS devices.

The solution extends the existing Web eID project by adding support for contactless ID-card communication, allowing users to authenticate and sign documents using their physical ID-card and a mobile device with NFC capability.

The mobile application communicates with the ID-card using standard NFC protocols, performs cryptographic operations directly on the card, and returns the result to the relying party.

This document defines the functionality and technical design of the NFC-based Web eID solution for mobile platforms.

#### Authentication (via NFC)

When a user accesses a website that supports Web eID authentication on a mobile device, they can authenticate using their physical ID-card over NFC.

1. The user brings the ID-card close to the phone’s NFC reader and initiates the authentication process.
2. The **RIA DigiDoc** mobile application (available as *RIA DigiDoc for Android* and *RIA DigiDoc for iOS*) is launched and guides the user through the following steps:
    - **Enter the CAN (Card Access Number)** printed on the ID-card to establish a secure NFC session.
    - **Grant consent** to share their authentication certificate with the website.
    - **Enter the authentication PIN (PIN1)** to authorize the use of the card’s authentication key.
3. The application communicates with the ID-card via NFC to:
    - Request the **authentication certificate** stored on the card.
    - - Instruct the ID-card to **sign the authentication value** — computed as `hash(origin) + hash(challenge)` — using the **authentication private key** protected by **PIN1**.
    - **Generate a Web eID authentication token**.
4. The authentication token is returned to the website, where it is **validated by the server**.  
   The server checks that:
    - The **token format and fields** are valid.
    - The associated **session** and **challenge nonce** are valid and not expired.
    - The **signature** matches the provided certificate.
    - The **certificate** itself is trusted and not revoked.
5. If validation succeeds, the user’s identity is confirmed and an authenticated session is established.

#### Signing documents (via NFC)

When a user opens a website that supports **digital signing** with an eID card on a mobile device, they can sign documents using their **physical ID-card** over **NFC**.

1. The user brings the ID-card close to the phone’s NFC reader and initiates the signing process.
2. The **RIA DigiDoc** mobile application (available as *RIA DigiDoc for Android* and *RIA DigiDoc for iOS*) is launched and guides the user through the following steps:
    - **Enter the CAN (Card Access Number)** printed on the ID-card to establish a secure NFC session.
    - **Grant consent** to use the **digital signature certificate** for signing.
    - **Enter the digital signature PIN (PIN2)** to authorize the signing operation.
3. The application communicates with the ID-card via NFC to:
    - Instruct the ID-card to **sign the hash of the data** provided by the website using the private key protected by **PIN2**.
4. The application builds a **signing response payload** containing:
    - The **digital signature**,
    - The **signing algorithm**, and
    - The **signing certificate** (previously retrieved either during authentication or via a separate certificate request).
5. The response is returned to the website, where it is **validated by the server**.  
   The server checks that:
    - The **response fields** are valid.
    - The **signature** matches the data that was sent for signing.
    - The **signing certificate** is trusted and not revoked.
6. If validation succeeds, the website confirms the successful signing and displays the signed document or confirmation message to the user.

> **Note:**  
> The signing flow can start in two different ways:
>
> 1. **Signing after authentication** —  
     >    The user has already authenticated with their ID-card.  
     >    In this case, the backend already holds the user’s signing certificate and supported algorithms (from the previous authentication token).  
     >    The signing flow begins directly with the **signing request**, where the server sends the data hash to be signed.
>
> 2. **Direct signing without prior authentication** —  
     >    The user has not yet authenticated in this session.  
     >    In this case, the flow begins with a **certificate request**, where the mobile app first retrieves the signing certificate from the ID-card (using PIN or biometric consent).  
     >    Once the certificate is returned to the website, the server verifies it, prepares the data hash, and only then initiates the **signing request** (using PIN2).

### Web eID project websites

The Web eID project website and authentication and digital signing test web application is available at https://web-eid.eu/. Links to Git repositories with the implementation of the Web eID components are available from the Web eID GitHub organization page https://github.com/web-eid and referenced below under corresponding components' sections.

### Requirements notation and conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

### Glossary

The following terms and abbreviations are used in this document:

- **APDU**, *application protocol data unit*, the communication unit between a smart card reader and a smart card
- **challenge nonce** (or challenge, or nonce), a cryptographic nonce, a large random number that can be used only once, with at least 256 bits of entropy
- **CNG**, *Cryptography API: Next Generation*, the pluggable Windows Cryptography API introduced in Windows Vista
- **CSRF**, *Cross-site request forgery*, a type of malicious exploit of a website where unauthorized commands are submitted from a user that the web application trusts
- **CTK**, *CryptoTokenKit*, a framework for accessing security tokens and the cryptographic assets they store in macOS
- **eID**, *electronic identification*, a digital solution for proof of identity of citizens or organizations
- **NFC**, *Near Field Communication*, a wireless technology used to communicate with the Estonian ID card via mobile devices
- **OCSP**, *Online Certificate Status Protocol*, an internet protocol for obtaining the revocation status of a X.509 digital certificate
- **OpenID Connect**, a simple identity layer on top of the OAuth 2.0 protocol
- **origin**, the website origin, the URL serving the web application
- **PC/SC**, *Personal Computer/Smart Card*, a specification for smart card integration into computing environments
- **PKCS#11**, one of the *Public-Key Cryptography Standards*, defines a platform-independent API to cryptographic tokens, such as hardware security modules and smart cards
- **TLS**, *Transport Layer Security*, a cryptographic protocol for secure Internet communication
- **TLS CCA**, *TLS Client Certificate Authentication*, a TLS protocol variant where the client (browser) uses a certificate to authenticate itself during the TLS handshake
- **TLS Token Binding**, a set of draft IETF RFC proposals for a TLS extension that aims to increase TLS security by using cryptographic certificates on both ends of the TLS connection
- **TokenD**, a software module for bridging a cryptographic device (like a smart card) and the CryptoTokenKit (CTK) framework in macOS
- **Web eID Mobile App**, the official application used on mobile devices to access Estonian ID cards over NFC for authentication and signing
- **WebAuthn**, *Web Authentication*, an API enabling the creation and use of public key-based credentials by web applications, for the purpose of strongly authenticating users
- **WebExtensions**, a new cross-browser system for developing browser extensions

## Design choices

### Overview of the current Open eID implementation

The current Open eID implementation for using eID smart cards is designed for desktop environments. It relies on native cryptographic APIs in the operating system and browser for secure authentication and signing. It uses:

- Cryptography API: Next Generation (CNG) in Windows,
- CTK/TokenD plug-in in macOS,
- PKCS#11 driver in Linux,
- and TLS Client Certificate Authentication (TLS-CCA) for browser-based login.

This approach enables secure login and signing but introduces complexity and maintenance challenges due to differences between platforms and browser behavior.

To support mobile usage over NFC, a different approach is needed that avoids OS-level integration and browser TLS features.

![Open eID authentication components](diagrams/Open-eID-mobile-authentication-components.png)  
Figure 1: Open eID authentication components

![Open eID digital signing components](diagrams/Open-eID-mobile-signing-components.png)  
Figure 2: Open eID digital signing components

The benefit of the deep integration is support for a wide range of use cases outside the web browser, e.g. secure login to the operating system with eID cards. However, there are significant downsides for the web browser platform due to that.

### Problems of the current implementation

The current Open eID solution was built for desktop usage and tightly integrated with browser and operating system APIs. This design presents several challenges that make it unsuitable for mobile environments and limit its usability.

Here is the listing of the most prominent problems:

- Depends on complex operating system and browser APIs that differ across platforms and are prone to breaking with updates.
- Not usable on mobile devices, where native browser TLS client certificate authentication is not supported.
- Authentication and signing use separate flows and components, leading to inconsistencies and increased maintenance effort.
- PIN prompts are managed by browser and OS middleware, often resulting in caching behavior that causes confusion or security concerns.
- Logout does not always clear authentication state, allowing re-authentication without PIN on the same session.
- Certificate selection dialogs and behavior vary across browsers and platforms, confusing users when multiple cards are in use.
- The solution does not provide a unified experience across web and mobile platforms.

To overcome these issues, a new design was introduced that avoids dependency on browser and operating system cryptographic APIs and enables communication with the ID-card directly over NFC on Android and iOS devices.

### Principles of the new technical design

The new technical design introduces support for using Estonian ID-cards over NFC in mobile applications.

The principles of the new design are:

- Support authentication and signing with Estonian ID-card using NFC on Android and iOS.
- Use platform-native NFC APIs (Core NFC on iOS, Android NFC stack) for communication with the card.
- Use PACE protocol for secure communication with the ID-card using the CAN number.
- Perform private key operations (authentication and signing) on-card using PIN1 and PIN2.
- Include authentication and signing certificates directly in the response from the card.
- Introduce new token format `web-eid:1.1` for mobile flows.
- Add fields like `unverifiedSigningCertificate` and `supportedSignatureAlgorithms` to support signing.
- Sign hash of origin and challenge to bind token to a specific relying party.
- Protect against man-in-the-middle (MITM) attacks with origin validation in the mobile app.

## Requirements for the new solution

Besides the principles listed above, the new solution satisfies the following requirements:

1. Support authentication and digital signing with Estonian ID-cards over NFC.
2. Support recent versions of Android and iOS mobile operating systems.
3. Use Core NFC (iOS) and Android NFC stack for ID-card communication.
4. Support secure communication with the ID-card using CAN and PACE protocol.
5. Require only the eID mobile application and do not depend on external NFC reader devices.
6. Ensure authentication and signing flows are stateless, secure, and event-driven.
7. Authentication flow must return the authentication certificate and signature bound to origin and challenge.
8. **Certificate flow (when signing without prior authentication) must return the signing certificate and supported signature algorithms.**
9. Signing flow must return the digital signature generated by the ID-card using PIN2.
10. Use the updated authentication token format `web-eid:1.1` for mobile flows.
11. Do not cache PIN codes or store sensitive data like CAN in persistent storage.

### Support for other security tokens besides smart cards

The current NFC solution is developed specifically for Estonian ID-cards. Support for other security tokens like Yubikey is out of scope for the NFC implementation at this stage.

## New solution architecture

The new architecture introduces support for authentication and signing with Estonian ID-cards over NFC on Android and iOS.

The **Web eID for Mobile** solution consists of the following components:

- A native mobile application (*RIA DigiDoc*) installed on the user’s Android or iOS device.
- Communication with the ID-card is handled over NFC using the mobile platform’s native NFC APIs (Core NFC for iOS, Android NFC stack).
- The application uses the **PACE protocol** to establish a secure channel with the card using the **CAN number**.
- The user enters the **PIN** directly in the app interface when prompted.
- During **authentication**, the application signs the hash of the origin and a server-provided challenge using the card’s **authentication key (PIN1)**.
- During **signing**, the application signs a document hash using the card’s **signing key (PIN2)** and returns the **digital signature**.
    - The **signing certificate** and **supported signature algorithms** are provided separately by the certificate flow (if not already obtained during authentication).
- The signed data or authentication result is returned via **app-to-app redirect** or **URL fragment**, depending on the integration type.
- Authentication tokens follow the `web-eid:1.1` format and include additional fields required for mobile and signing support.

The architecture avoids any dependency on browser extensions or operating system cryptographic APIs.
This architecture is implemented and maintained under the [RIA DigiDoc for Android](https://github.com/open-eid/RIA-DigiDoc-Android) and [RIA DigiDoc for iOS](https://github.com/open-eid/RIA-DigiDoc-iOS) projects.

![Web eID for Mobile authentication flow](diagrams/web-eid-mobile-authentication-flow.png)  
Figure 3: Web eID for Mobile authentication flow

### Technical overview of authentication and digital signing

The authentication and digital signing processes follow the same principle: the Web eID mobile application uses the private key on the ID-card to sign a server-provided challenge or document hash. The resulting signature and certificate are sent back to the server for verification.

In the following sections, _mobile application_ refers to the Web eID app on the user's Android or iOS device.

_Server application_ is the relying party's back-end system that initiates the authentication or signing flow and verifies the results.

#### Authentication

Authentication in the NFC solution uses digital signing and follows similar principles as the original Web eID flow:

- The server generates a cryptographic challenge (nonce).
- The mobile app signs the challenge together with the origin using the private authentication key on the ID-card.
- The signed result and authentication certificate are returned to the server for validation.

Unlike the desktop-based solution, the authentication flow is handled entirely within the mobile application, using NFC to communicate with the physical ID-card and returning the result back to the relying party.

Authentication uses the card’s authentication certificate and key, separate from the signing certificate and key.

The server retrieves user details from the subject field of the authentication certificate.

![Web eID for Mobile detailed authentication flow](diagrams/web-eid-nfc-detailed-authentication-flow.png)  
Figure 4: Web eID for Mobile detailed authentication flow

The authentication steps are as follows:

1. The user starts authentication from the relying party (RP) application.
2. The RP backend generates a challenge, stores it in session, and redirects to the Web eID mobile app using a universal/app link with the challenge and `login_uri` as parameters.
3. The mobile app reads and verifies the origin from the `login_uri`, and asks the user to:
    - Enter their CAN number,
    - Give consent to send their personal data,
    - Enter PIN1.
4. The app creates a secure NFC session using the PACE protocol with the ID-card and retrieves the authentication certificate.
5. The app signs `hash(origin) + hash(challenge)` with the authentication key on the card.
6. The authentication token is created in format `web-eid:1.1` and includes:
    - `unverifiedCertificate`
    - `signature`
    - `algorithm`
    - `origin`
    - `challenge`
    - `format`
    - `appVersion`
7. The token is returned to the `login_uri` using a URL fragment.
8. The browser automatically posts the token to the RP backend via `POST /auth/eid/login`.
9. The backend performs the following validation steps:
    - Verifies CSRF token.
    - Verifies that the session and nonce exist and have not expired.
    - Validates the authentication certificate (validity period, key usage, issuer, and policies).
    - Sends OCSP request to check revocation status.
    - Reconstructs `hash(origin) + hash(challenge)` and uses the public key from the certificate to verify the signature.
    - Verifies the subject field of the certificate.
10. If everything is valid, the user is authenticated and a new session is created.

Additional validation rules:

- The challenge must have at least 256 bits of entropy (base64-encoded length ≥ 44 bytes).
- The token must be bound to a specific origin and must be signed using the card’s private key.
- Authentication tokens are valid only once and must be tied to the issuing session.
- CSRF protection must be in place when handling POST requests.

The server must remove the nonce after successful lookup to prevent replay attacks. The recommended challenge lifetime is 5 minutes.

##### Authentication and WebAuthn

As mentioned above, the Web eID authentication subsystem is similar in principle, purpose and most of the steps to the WebAuthn specification. Like in WebAuthn, a server-generated challenge is encrypted with authentication private key, authentication takes place in the JavaScript application and browser extension layer using `fetch()` calls for communicating with the server and origin validation is an integral part of the security model.

However, WebAuthn has a different design with separate loosely coupled authenticator components that work on a different level of abstraction, and Web eID authentication token format is different, see the section [_Web eID authentication token specification_](#web-eid-authentication-token-specification) below for more details.

##### Authenticated identity

The server application can retrieve user details from the authentication certificate to access secure authenticated identity of an individual. The authenticity of the identity information is guaranteed via the state issued digital identity card and official public eID infrastructure.

##### Authentication and TLS Token Binding

[Token Binding](https://en.wikipedia.org/wiki/Token_Binding) is a set of draft IETF RFC proposals for a TLS extension that aims to increase TLS security by using cryptographic certificates on both ends of the TLS connection. Bound tokens are established by the browser that generates a private-public key pair per target server, providing the public key to the server, and thereafter proving possession of the corresponding private key on every TLS connection to the server.

Use of Token Binding protects the authentication flow from man-in-the-middle and token export and replay attacks. With token binding, man-in-the-middle attacks cannot forward requests or replay credentials because they cannot prove they have the key bound to the token, as the key is securely stored in the user's device.

A TLS terminating reverse proxy may be in use in front of the server application. There is a draft proposal [*HTTPS Token Binding with TLS Terminating Reverse Proxies*](https://tools.ietf.org/html/draft-ietf-tokbind-ttrp-07) to support forwarding token binding information through the proxy to the backend server, which facilitates the reverse proxy and backend server functioning together as though they are a single logical server side deployment of Token Binding.

However, Token Binding is not supported by mainstream browsers and proxy usage may still be problematic: the server application can see if token binding is missing but it is not obvious if that is malicious or a proxy has stripped off the token binding.

Thus, Token Binding support is not planned until it becomes more widely supported by browsers and proxy servers.

##### Protection against man-in-the-middle attacks during authentication with origin validation

The security properties of the Web eID authentication subsystem are provided by ensuring that all authentication tokens are scoped to a particular origin, and cannot be replayed against a different origin, by incorporating the origin under the signature that is included in the token.

Specifically, the full document origin [`location.origin`](https://developer.mozilla.org/en-US/docs/Web/API/Location) of the relying party is included in the signed data. This ensures that a token issued for one origin (e.g. `https://bank.example`) cannot be replayed against another (e.g. `https://fake-login.example`). The Web eID mobile app only allows HTTPS origins.

All dialogs in the mobile application display the origin to the user before consent and PIN entry, so that the user can confirm they are communicating with the correct site.

Including the origin in the signed data provides strong protection against:

- Man-in-the-middle (MITM) attacks
- Token replay
- Token export from one domain to another

Without this protection, an attacker could redirect a legitimate token to a different site and bypass authentication controls.

The following diagrams show a broken and a protected authentication flow:
![Man-in-the-middle attack, broken](diagrams/Man-in-the-middle-attack-broken.png)
![Man-in-the-middle attack, fixed](diagrams/Man-in-the-middle-attack-fixed.png)  
Figure 5: Man-in-the-middle attack and mitigation with origin validation

Figure 5.1 demonstrates how an attacker who deceives the user to visit a deceptive website that impersonates a legitimate website can gain unauthorized access to the legitimate website with user credentials by intercepting the authentication data, in case only the challenge nonce is signed over without including the origin. Figure 6.2 demonstrates how including origin under the signature helps to mitigate this attack.

#### NFC-specific origin validation flow

To protect the NFC authentication flow from MITM attacks, the origin is embedded in the signed data and verified at each step:

1. User begins authentication at the relying party (RP) website.
2. RP calls `/auth/eid/init`, which:
    - Creates a new session.
    - Generates a session-bound challenge.
    - Sets a cookie and redirects the user to the eID Application (via app/universal link) with `challenge` and `login_uri`.
3. The eID Application safely parses the origin from `login_uri` and displays it to the user.
4. The application signs `hash(origin) + hash(challenge)` using the ID-card’s authentication key and creates the authentication token.
5. The token is returned to `login_uri` as a URL fragment.
6. The browser auto-submits the token to `/auth/eid/login`.
7. Server verifies:
    - That the origin matches the session.
    - That the token is valid and signed with the correct certificate.
    - That the challenge has not expired or been reused.

If validation succeeds, the user is authenticated.

By validating the origin, using secure cookies, and rejecting reused challenges, Web eID Mobile ensures that only the intended relying party can successfully use the issued authentication token.

#### Additional security considerations

- The app must not allow HTTP origins.
- The app must not follow HTTP redirects during the request — this avoids phishing via open redirect vulnerabilities.
- It's not sufficient to check whether `response_uri` starts with `origin`. For example:

    - `origin = https://rp.example.com`
    - `response_uri = https://rp.example.com:whatever@evil.com` → **looks valid, but isn’t**

- Token binding relies on a strict match of signed origin and enforced session constraints on the backend.

#### Digital signing

The digital signature of a document is created by encrypting the document hash with the **signing key** on the eID card, protected by **PIN2**. 
The mobile Web eID digital signing subsystem follows the same principles as the existing Open eID design, but uses **NFC communication** handled by the **RIA DigiDoc** application.

![Web eID digital signing diagram](diagrams/Web-eID-signing-flow.png)  
Figure 6: Web eID digital signing diagram

The digital signing steps are as follows:

1. The user initiates document signing on a website that supports **Web eID Mobile**.
2. The website (server application) prepares the signing request by calculating the document hash and generating a **deep link** (`web-eid-mobile://sign#...`) that contains the hash, hash function, and response URI.
3. The user’s mobile browser opens the **RIA DigiDoc** application through the deep link.
4. The application prompts the user to:
    - **Enter the CAN** to establish a secure NFC session with the ID-card.
    - **Grant consent** to use the signing certificate for signing.
    - **Enter the signing PIN (PIN2)** to authorize the signing operation.
5. The app communicates with the ID-card over NFC to:
    - Verify the PIN (PIN2) and
    - **Sign the document hash** provided in the request using the card’s signing private key.
6. The app builds a **signing response payload** that includes:
    - The **digital signature**,
    - The **signature algorithm**, and
    - The **signing certificate** (obtained earlier from authentication or certificate flow).
7. The payload is returned to the relying-party website via the `response_uri` (app-to-app redirect or URL fragment).
8. The server validates the response by checking that:
    - The payload fields are valid.
    - The signature matches the document hash.
    - The signing certificate is trusted and not revoked (validated through OCSP).
9. If validation succeeds, the server adds the signature to the document container and confirms successful signing to the user.

### Security analysis

Security analysis of the solution is available in the document ["Analysis of planned architectural changes in Open-eID"](https://web-eid.github.io/web-eid-cybernetica-analysis/webextensions-main.pdf).

### JavaScript library

The `web-eid.js` JavaScript library is a thin wrapper on top of the messaging interface provided by the Web eID browser extension which in turn communicates with the Web eID application.

It gives access to the Web eID solution features by providing an asynchronous, [`Promise`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Promise)-based interface and listening to incoming messages and turning them into resolved `Promises`.

Design principles:

- All calls are asynchronous in nature and return a `Promise`.
- While asynchronous, the API is still sequential – only one call can be serviced by a smart card reader at a time. If a call can not be serviced because another call is underway, the promise shall be rejected.
- The `code` property of a rejected promise (an [`Error`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error)) contains a symbolic error code that can be handled in calling code.

The full specification of the `web-eid.js` JavaScript library API and its source code is available in the `web-eid.js` [GitHub repository](https://github.com/web-eid/web-eid.js).

### Web eID authentication token specification

Since there does not exist a standardized format of an authentication proof that fulfills the needs of the Web eID authentication protocol, we use a special purpose format for the Web eID authentication token. We intentionally avoid using the JWT format, but still use its proven basic building blocks: the JSON format and base64-encoding.

The OpenID Connect ID Token JWT format was initially considered, but it was found that any similarities of the Web eID authentication token to the JWT format are actually undesirable, as they would imply that the claims presented in the Web eID authentication token can be trusted and processed, while actually they cannot be trusted as the token is created in the user's untrusted environment. The solutions are fundamentally different – the purpose of OpenID Connect (and JWT in general) is to exchange identity claims that are signed by a trusted party (usually an authentication server), while the purpose of the Web eID authentication token is to prove that the user is able to create signatures with the private key that corresponds to the presented certificate.

The in-depth rationale of the Web eID authentication token format design is available in a separate [specification document](https://web-eid.github.io/web-eid-system-architecture-doc/web-eid-auth-token-v2-format-spec.pdf).

#### Token format

The Web eID authentication token is a JSON data structure that looks like the following example:

```json
{
    "unverifiedCertificate": "MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4...",
    "unverifiedSigningCertificate": "MIIFqzCCA5CgAwIBAgIQaHgHK-qWZuFw3...",
    "supportedSignatureAlgorithms": [
        {
            "cryptoAlgorithm": "RSA",
            "hashFunction": "SHA-256",
            "paddingScheme": "PKCS1.5"
        }
    ],
    "algorithm": "RS256",
    "signature": "HBjNXIaUskXbfhzYQHvwjKDUWfNu4yxXZha...",
    "format": "web-eid:1.1",
    "appVersion": "https://web-eid.eu/web-eid-mobile-app/releases/v1.0.0"
}
```

It contains the following fields:

- `unverifiedCertificate`: the base64-encoded DER-encoded authentication certificate of the eID user. The public key contained in this certificate should be used to verify the signature. The certificate cannot be trusted as it is received from client side and the client can submit a malicious certificate, to establish trust, it must be verified that the certificate is signed by a trusted certificate authority.

- `unverifiedSigningCertificate`: the base64-encoded DER-encoded signing certificate of the eID user. This certificate is used for digital signing flows and should be validated similarly to the authentication certificate.

- `supportedSignatureAlgorithms`: a list of supported signature algorithms that the card supports. Each item includes:
    - `cryptoAlgorithm`: the cryptographic algorithm used. Supported values:
        - `ECC`
        - `RSA`
    - `hashFunction`: the hash function used. Supported values:
        - `SHA-224`
        - `SHA-256`
        - `SHA-384`
        - `SHA-512`
        - `SHA3-224`
        - `SHA3-256`
        - `SHA3-384`
        - `SHA3-512`
    - `paddingScheme`: the padding scheme used. Supported values:
        - `NONE`
        - `PKCS1.5`
        - `PSS`

- `algorithm`: the signature algorithm used to produce the signature. The allowed values are the algorithms specified in [JWA RFC](https://www.ietf.org/rfc/rfc7518.html) sections 3.3, 3.4 and 3.5:

  ```
    "ES256", "ES384", "ES512", // ECDSA
    "PS256", "PS384", "PS512", // RSASSA-PSS
    "RS256", "RS384", "RS512"  // RSASSA-PKCS1-v1_5
  ```

  The algorithm field value depends on the capabilities of the eID card.

- `signature`: the base64-encoded signature of the token (see the signature description below).

- `format`: the type identifier and version of the token format separated by a colon character '`:`', `web-eid:1.1` as of now. The version number consists of the major and minor number separated by a dot, major version changes are incompatible with previous versions, minor version changes are backwards-compatible within the given major version.

- `appVersion`: the URL identifying the name and version of the application that issued the token. Informative purpose, can be used to identify the affected application in case of faulty tokens.

The value that is signed by the user’s authentication private key and included in the `signature` field is `hash(origin)+hash(challenge nonce)`. The hash function is used before concatenation to ensure field separation as the hash of a value is guaranteed to have a fixed length. Otherwise the origin `example.com` with challenge nonce `.eu1234` and another origin `example.com.eu` with challenge nonce `1234` would result in the same value after concatenation. The hash function `hash` is the same hash function that is used in the signature algorithm, for example SHA256 in case of RS256.

The `origin` value that is signed over must contain the URL of the website origin, i.e. the URL serving the web application. `origin` URL must be in the form of `<scheme> "://" <hostname> [ ":" <port> ]` as defined in [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/API/Location/origin), where `scheme` must be `https`. Note that the `origin` URL must not end with a slash `/`.

#### Requesting a Web eID authentication token

The Web eID authentication token is returned from the following `web-eid.js` JavaScript API call:

```js
const authToken = await webeid.authenticate('NONCEVALUE');
```

* The challenge nonce must be generated by the back end application and must contain at least 256 bits of entropy.
* The consuming back end application must assure that the authentication token is received from the same browser to which the corresponding challenge nonce was issued.
* The browser extension and native application reject challenge nonces shorter than 44 bytes (length of base64-encoded 256 bits of entropy).
* The browser extension rejects origins that are not secure.
* The session and expiry management used for the nonce in the consuming backend application must conform to the recommendations of the [OWASP Session Management Cheat Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet).

The full specification of the `web-eid.js` JavaScript library API and its source code is available in the `web-eid.js` [GitHub repository](https://github.com/web-eid/web-eid.js).

### Browser extensions

The NFC-based Web eID for Mobile solution does not use or depend on browser extensions.

All authentication and signing operations are handled by the Web eID mobile application installed on the user's Android or iOS device.

Communication between the relying party and the mobile app is done using universal links (iOS) or app links (Android), and the results are passed back via secure redirect using URL fragments.

This design removes the need for browser-specific integrations and works independently of desktop browser extension APIs.

### Native application

The Web eID native application is built with the [Qt](https://www.qt.io/) framework. It consists of

- the Qt application bootstrapping code that starts the Qt event loop,
- a controller component that is responsible for creating other component objects and coordinating communication between them and the user,
- command handlers that implement the actual PKI operations (authenticate, get signing certificate, sign) using the `libelectronic-id` library,
- thread management code, including the card reader and smart card event monitoring thread,
- a dynamic user interface dialog built with Qt Widgets.

The controller has an event-driven internal design that supports unexpected events like card or reader removal or insertion during all operations. Communication with the smart card and card monitoring run in separate threads to assure responsive, non-blocking operations.

The lifetime of the native application is managed by the Web eID browser extension, for example when Native messaging is used, then the application is launched when the extension calls `runtime.connectNative()`, and stopped with the `Port.disconnect()` call or when the `Port` object is garbage collected (e.g. during page reload).

The native application is not installed or managed by the browser, it is installed using the underlying operating system's installation facilities.

More information about the Web eID native application, its source code and the full specification of the messaging API is available in the `web-eid-app` [GitHub repository](https://github.com/web-eid/web-eid-app).

##### General

- Messaging API works in request-response pairs over `stdin`/`stdout` when using WebExtension Native messaging. Safari extension invokes the Web eID app API functions directly.
- Each request must send a single JSON object, the command, one of `"authenticate"`, `"get-signing-certificate"` or `"sign"`, and its arguments.
- For security reasons, authentication certificate can only be accessed through the `"authenticate"` command and there is no support for signing of raw hash values with the authentication key.
- All commands require the mandatory `origin` field in arguments.
- All commands support an optional `lang` field in arguments that, if provided, must contain a two-letter ISO 639-1 language code. If translations exist for the given language, then the user interface will be displayed in this language.
- The response is a single JSON object.
- Presence of the `error` field in a response indicates error. Additional information about the error is in the `code` and `message` fields of the error JSON object.
- When starting, the application sends an initial `version` message to `stdout` and starts listening for a command from `stdin`.
- When the command has been completed successfully or an error occurs and the response has been sent to `stdout`, the native application exits.
- All binary fields are base64-encoded.
- Incorrect requests are rejected with an error.
- Messages must not exceed 8 KiB (8192 bytes).

##### PKI operations

Messaging API supports the following PKI operations. The mandatory `origin` field and optional `lang` field have been omitted from arguments for brevity.

- Authenticate:
    - request: `{"command": "authenticate", "arguments": {"challengeNonce": "base64"}}`
    - response (Web eID authentication token): `{"unverifiedCertificate": "base64", "algorithm": "string", "signature": "base64", "format": "string", "appVersion": "URL"}`.

- Get signing certificate:
    - request: `{"command": "get-signing-certificate", "arguments": {}}`
    - response: `{"certificate": "base64", "supportedSignatureAlgorithms" : [{"cryptoAlgorithm": "string", "hashFunction": "string", "paddingScheme": "string"}]}`.

- Sign:
    - request: `{"command": "sign", "arguments": {"certificate": "base64", "hash": "base64", "hashFunction": "string"}}`
    - response: `{"signature": "base64", "signatureAlgorithm": {"cryptoAlgorithm": "string", "hashFunction": "string", "paddingScheme": "string"}}`.

### Implementation guide and example applications

To implement authentication and digital signing with Web eID in a Java or .NET web application,

- in the front end of the web application, use the *web-eid.js* JavaScript library according to the instructions [here](https://github.com/web-eid/web-eid.js#quickstart),
- in the back end of a Java web application,
    - for authentication, use the *web-eid-authtoken-validation-java* Java library according to instructions [here](https://github.com/web-eid/web-eid-authtoken-validation-java#quickstart),
    - for digital signing, use the *digidoc4j* Java library according to instructions [here](https://github.com/open-eid/digidoc4j/wiki/Examples-of-using-it),
- in the back end of a .NET web application,
    - for authentication, use the *web-eid-authtoken-validation-dotnet* .NET library according to instructions [here](https://github.com/web-eid/web-eid-authtoken-validation-dotnet#quickstart),
    - for digital signing, use the C# bindings of the `libdigidocpp` library according to instructions [here](https://github.com/web-eid/web-eid-asp-dotnet-example/wiki/How-to-implement-digital-signing-in-a-.NET-web-application-back-end).

The full source code and overview of an example Spring Boot web application that uses Web eID for authentication and digital signing is available [here](https://github.com/web-eid/web-eid-spring-boot-example). The .NET/C# version of the same example is available [here](https://github.com/web-eid/web-eid-asp-dotnet-example).

## References

1. ["Estonian ID card (EstEID)"](https://e-estonia.com/solutions/e-identity/), *E-Estonia*
2. ["Open Electronic Identity (Open eID)"](https://github.com/open-eid), *Open eID GitHub project*
3. The Web eID project GitHub organization page, https://github.com/web-eid
4. The Web eID project website, https://web-eid.eu/
5. ["Web eID for Mobile - Confluence documentation"](https://confluence.ria.ee/display/IB/Web+eID+for+Mobile), *RIA internal specification*
6. ["Key words for use in RFCs to Indicate Requirement Levels (RFC 2119)"](https://www.rfc-editor.org/rfc/rfc2119.txt), *IETF RFC*
7. ["Online Certificate Status Protocol (OCSP)"](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol), *Wikipedia*
8. ["Web Authentication (WebAuthn)"](https://www.w3.org/TR/webauthn-2/), *W3C Recommendation*
9. ["Associated Signature Containers (ASiC)"](http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf), *ETSI TS 102 918*
10. ["DigiDoc4j"](http://open-eid.github.io/digidoc4j/), *DigiDoc4j project documentation*
11. ["OWASP Session Management Cheat Sheet"](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
12. ["RIA DigiDoc for Android"](https://github.com/open-eid/RIA-DigiDoc-Android), *Official Android mobile application*
13. ["RIA DigiDoc for iOS"](https://github.com/open-eid/RIA-DigiDoc-iOS), *Official iOS mobile application*
