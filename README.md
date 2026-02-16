# Web eID for Mobile: electronic identity cards on mobile devices

<img src="docs/img/eu-fund-flags.jpg" width="300" alt="European Regional Development Fund">

## Table of Contents

* [Introduction](#introduction)
    * [Use cases](#use-cases)
        * [Authentication](#authentication)
        * [Signing documents](#signing-documents)
    * [Web eID project websites](#web-eid-project-websites)
    * [Requirements notation and conventions](#requirements-notation-and-conventions)
    * [Glossary](#glossary)
* [Design choices](#design-choices)
    * [Problems with the current implementation](#problems-with-the-current-implementation)
    * [Principles of the new technical design](#principles-of-the-new-technical-design)
* [Web eID for Mobile protocol](#web-eid-for-mobile-protocol)
    * [Authentication](#authentication-protocol)
        * [Origin serialization](#origin-serialization)
        * [Clarification on challenge nonce processing](#clarification-on-challenge-nonce-processing)
        * [Authentication request](#authentication-request)
        * [Authentication response](#authentication-response)
        * [Error response](#error-response)
    * [Digital signing](#signing-protocol)
        * [Certificate request](#certificate-request)
        * [Certificate response](#certificate-response)
        * [Signing request](#signing-request)
        * [Signing response](#signing-response)
        * [Error response](#error-response-1)
    * [Error codes](#error-codes)
    * [RIA-DigiDoc mobile app](#ria-digidoc-mobile-app)
    * [Security assumptions](#security-assumptions)
    * [Web eID authentication token specification](#web-eid-authentication-token-specification)
        * [Validation libraries](#validation-libraries)
    * [Implementation guide and example applications](#implementation-guide-and-example-applications)

## Introduction

The Web eID for Mobile protocol enables secure same-device authentication and digital signing on mobile devices via
browser-based flows using European Union electronic identity (eID) cards and public-key cryptography.

It extends the [Web eID protocol](https://github.com/web-eid/web-eid-system-architecture-doc) by adding support for
authentication and digital signing on mobile devices, where Web eID browser extensions are not available.

The solution is cross-platform and works in all modern mobile browsers.

This document defines the functionality and technical design of the Web eID for Mobile protocol.

### Use cases

The solution supports two main use cases – authentication and digital signing of documents.

#### Authentication

The user opens a website that requires authentication with an eID card and initiates the authentication. The website
creates an authentication session and opens
an [App Link](https://developer.android.com/training/app-links)/[Universal Link](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app)
to the [RIA-DigiDoc mobile app](#ria-digidoc-mobile-app) (eID app), which processes the authentication request. The
application asks the user for permission to send the authentication certificate to the website and prompts them to enter
their authentication PIN. The user taps the ID card to the mobile phone's NFC reader, enters the authentication PIN, and
confirms the authentication request. The mobile application directs the user back to the website, where the
authentication session and data are verified. The website notifies the user of a successful login and displays the
signed-in page.

#### Signing documents

The user opens a website that supports digital signing of documents and initiates digital signing. The website creates a
signing session and
opens
an [App Link](https://developer.android.com/training/app-links)/[Universal Link](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app)
to the [RIA-DigiDoc mobile app](#ria-digidoc-mobile-app) (eID app), which processes the signing request. The application
asks the
user for permission to send the signing certificate to the website and prompts them to enter their signing
PIN. The user taps the ID card to the mobile phone's NFC reader, enters the signing PIN, and confirms the signing
request. The mobile application directs the user back to the website, where the signing session and data are verified.
The website notifies the user of a successful signing and displays the signed document.

### Web eID project websites

The Web eID project website, including an authentication and digital signing test web application, is available
at https://web-eid.eu/. Links to Git repositories with the implementation of the Web eID components are available from
the Web eID GitHub organization page https://github.com/web-eid and referenced below under corresponding component
sections.

### Requirements notation and conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT
RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

### Glossary

The following terms and abbreviations are used in this document:

- **APDU**, *application protocol data unit*, the communication unit between a smart card reader and a smart card
- **base64url**, the URL-safe Base64 encoding defined
  in [RFC 4648, Section 5](https://datatracker.ietf.org/doc/html/rfc4648#section-5), without padding
- **challenge nonce** (or challenge, or nonce), a cryptographic nonce, a large random number that can be used only once,
  with at least 256 bits of entropy, Base64-encoded for transport (e.g. 44 Base64 characters for a 32-byte nonce).
- **CSRF**, *Cross-site request forgery*, a type of malicious exploit of a website where unauthorized commands are
  submitted from a user that the web application trusts
- **eID**, *electronic identification*, a digital solution for proof of identity of citizens or organizations
- **LDAP**, *Lightweight Directory Access Protocol*, a protocol for accessing and maintaining distributed directory
  information services, used here to retrieve user certificates from a directory
- **NFC**, *Near Field Communication*, a wireless technology used to communicate with eID smart cards via mobile
  devices
- **OCSP**, *Online Certificate Status Protocol*, an internet protocol for obtaining the revocation status of a X.509
  digital certificate
- **origin**, the website origin (scheme, host, port tuple) as defined
  in [RFC 6454](https://datatracker.ietf.org/doc/html/rfc6454), serialized as described
  in [Origin serialization](#origin-serialization)
- **TLS**, *Transport Layer Security*, a cryptographic protocol for secure Internet communication
- **RIA-DigiDoc mobile app** (also referred to as **eID app**), the official application used on mobile devices to
  access European Union eID cards over NFC for authentication and signing using the Web eID for Mobile protocol.
- **WebExtensions**, a new cross-browser system for developing browser extensions

## Design choices

### Problems with the current implementation

The current [Web eID protocol](https://github.com/web-eid/web-eid-system-architecture-doc) is not usable on mobile
devices due to the lack
of [WebExtensions](https://github.com/web-eid/web-eid-system-architecture-doc/blob/master/README.md#browser-extensions)
support on mobile browsers.

### Principles of the new technical design

To overcome this limitation, a cookie-based protocol is introduced.

The Web eID for Mobile protocol relies on standard mobile OS mechanisms instead of browser extensions. The key design
principles are:

**App Links / Universal Links.** The protocol uses OS-verified deep
links — [App Links](https://developer.android.com/training/app-links) on
Android, [Universal Links](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app) on
iOS — to transition between the mobile browser and the eID application. The operating system verifies domain ownership
of the link before opening the eID app, which prevents malicious applications from intercepting authentication or
signing requests.

**URL fragments for data transfer.** Request parameters (challenge, login URI) and response data (authentication token,
certificates, signatures) are exchanged via the URL fragment (`#`). According to
[RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.5), fragments are never sent to the server in HTTP
requests — they are only accessible to client-side JavaScript. This avoids leaking sensitive cryptographic material in
server logs, HTTP headers, or referrer URLs.

**Cookie-based session binding.** Since browser extensions are not available on mobile, the protocol uses HTTP cookies
with the `__Host-` prefix and `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` attributes to bind the authentication or
signing session
across browser-to-app-to-browser transitions. This ensures the response received from the eID app is linked to the
correct server-side session. The protocol cookies are named `__Host-web-eid-auth` for the authentication session and
`__Host-web-eid-sign` for the signing session. The authenticated session cookie that the relying party sets after
successful authentication is not part of the protocol and remains application-specific.

**Stateless browser, stateful server.** The browser acts as a stateless relay: it opens the eID app via a deep link,
receives the result back via a URL fragment, and submits it to the server. All session state — challenges, signing
containers, expiry timers — is maintained server-side, which simplifies the client-side logic and reduces the attack
surface.

**Cross-platform compatibility.** The approach works in all modern mobile browsers because it relies on standard OS
mechanisms (deep links, cookies, URL fragments) rather than browser-specific extension APIs.

## Web eID for Mobile protocol

The authentication and digital signing processes follow the same principle: the eID app uses the
private key on the ID card to sign a server-provided challenge or document hash. The resulting signature and certificate
are sent back to the server for verification.

Authentication uses the authentication key and certificate on eID smart cards, as most cards have separate keys for
authentication and digital signing.

### <a id="authentication-protocol"></a>Authentication

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant E as eID App
    participant B as Browser
    participant RP as Relying Party
    U ->>+ B: Login
    B ->>+ RP: Login
    RP ->> RP: Create authentication session <br/> (TTL: 5 minutes)
    RP ->> RP: Generate session bound challenge <br/> (min 256 bits of entropy)
    RP ->> RP: Create authentication AppLink/UniversalLink <br/> with challenge, loginUri <br/>and optionally getSigningCertificate=true
    critical
        RP -->>- B: Set authentication session cookie (HttpOnly, Secure, SameSite=Lax, Path=/, Max-Age=300) <br/> Return AppLink/UniversalLink
    end
    B -->> B: Open AppLink/UniversalLink
    B ->>+ E: Open AppLink/UniversalLink
    deactivate B
    critical
        E ->> E: Parse origin from loginUri
        E ->>+ U: Show authentication request with origin
        U -->>- E: Consent authentication request and origin with ID Card PIN1
    end
    Note over U, E: User taps ID Card
    E ->> E: Hash the authentication value hash(origin) + hash(challenge) <br/>and sign the digest with ID Card over NFC using PIN1
    E ->> E: Create authentication token using the signature
    E ->>+ B: Open browser with loginUri #35; <base64url-encoded-auth-token>
    deactivate E
    B ->>+ RP: HTTP GET <loginUri>
    RP -->>- B: HTTP 200 Login page
    B ->> B: Parse authentication token from loginUri fragment
    B ->>+ RP: POST authentication token <br/> Authentication session cookie (HttpOnly, Secure, SameSite=Lax, Path=/)
    alt Authentication success
        critical
            RP ->> RP: Verify authentication session exists
        end
        RP ->> RP: Remove challenge from session and verify it is not expired
        RP ->> RP: Validate authentication token user authentication and signing certificates
        RP ->> RP: Verify authentication token signature against<br/> expected origin and challenge from session
        RP ->> RP: Verify authenticated user is authorized to access the service
        RP ->> RP: Create new authenticated session
        alt getSigningCertificate=true
            RP ->> RP: Store the signing certificate <br/>received in authentication token to session <br/>(see signing flow for usage)
        end
        RP -->> B: HTTP 200, Delete authentication session cookie <br/> Set new application-specific authenticated session cookie (HttpOnly, Secure, SameSite=Strict, Path=/)
        B ->> B: Proceed to protected resource
    else Authentication failure
        RP ->> RP: End authentication session
        RP -->>- B: HTTP 401, Delete session cookie
        B ->> B: Show error
    end
    deactivate B
```

Figure 1: Web eID for Mobile authentication diagram

The authentication steps are as follows:

**Steps 1–2.** The user initiates login in the mobile browser. The browser sends a login request to the Relying Party
(RP).

**Steps 3–5.** The RP creates a new authentication session with a time-to-live that SHOULD NOT exceed 5 minutes,
generates a challenge that MUST be cryptographically random with at least 256 bits of entropy, and builds an
AppLink/UniversalLink containing the challenge and login URI. The AppLink/UniversalLink MAY include a
`getSigningCertificate=true` flag. When this flag is set, the eID app MUST include the user's signing certificate and
supported signature algorithms in the authentication token, allowing the RP to skip the certificate request phase of
the signing flow later.

**Step 6.** The RP sets an authentication session cookie (`__Host-web-eid-auth`; `Secure`, `HttpOnly`, `SameSite=Lax`,
`Path=/`, `Max-Age=300`) and returns the AppLink/UniversalLink to the browser. The cookie binds subsequent requests to
this authentication session. The `SameSite=Lax` attribute is REQUIRED so that the cookie is sent with the top-level
navigation triggered when the eID app redirects back to the browser.

**Steps 7–8.** The browser opens the AppLink/UniversalLink. The operating system verifies the domain ownership of the
link and launches the eID app.

**Steps 9–11.** The eID app parses and validates the `loginUri` from the URL fragment and extracts the origin. It
displays the authentication request to the user, showing the origin of the requesting website. The user reviews the
request and consents by entering their ID card PIN1.

**Step 12.** The eID app composes the authentication value `hash(origin) + hash(challenge)` and signs it with the ID
card's authentication key over NFC using PIN1. The hash function is the one used by the signature algorithm, for example
SHA-384 in case of ES384. Because eID cards sign a pre-computed hash, the eID app hashes the composed value and passes
the resulting digest to the card; that hash is the hash step of the signature algorithm itself, not part of the signed
value. The user taps the ID card to the phone's NFC reader during this step.

**Step 13.** The eID app creates an authentication token containing the authentication certificate, signature and
algorithm. The token format is `web-eid:1.0` when only authentication data is included, or `web-eid:1.1` when the
signing certificate and supported signature algorithms are also included (if `getSigningCertificate=true` was
requested).

**Step 14.** The eID app opens the browser with the `loginUri` appended with a URL fragment containing the
base64url-encoded authentication token (e.g. `https://rp.example.com/auth/eid/login#<base64url-encoded-auth-token>`).
The authentication token is carried in the fragment so it is never sent to the server in the HTTP request.

**Steps 15–16.** The browser makes an HTTP GET request to the `loginUri`. The RP responds with an HTTP 200 login page
that contains JavaScript to process the authentication token.

**Steps 17–18.** The JavaScript on the login page parses the authentication token from the URL fragment and
automatically submits it to the RP via an HTTP POST request. The authentication session cookie (`__Host-web-eid-auth`)
is
included with the request, binding it to the session created in steps 3–5.

**Steps 19–20.** The RP verifies that the authentication session identified by the session cookie exists and is valid.
It
then verifies that the challenge is stored in the session, removes it and verifies that it has not expired.

**Step 21.** The RP validates the user certificate from the authentication token. The server application extracts the
user certificate from the authentication token and MUST perform the following validation steps:

- validates that the purpose of the authentication certificate's key usage is client authentication
- validates that the authentication certificate does not contain any disallowed policies
- validates that the authentication certificate is signed by a trusted certificate authority, and that the current time
  falls within the validity periods of both the authentication certificate and the trusted CA certificate
- validates the certificate revocation status response from the OCSP responder

If the authentication request included `getSigningCertificate=true`, the authentication token MUST use the
`web-eid:1.1` format and MUST contain the `unverifiedSigningCertificates` field with at least one signing certificate
entry. Whenever the field is present, the RP MUST additionally validate each signing certificate provided in the token:

- validates that the supported signature algorithms listed for the signing certificate are from the allowed set
- validates that the signing certificate's subject matches the authentication certificate's subject
- validates that the signing certificate has the same issuer as the authentication certificate, by comparing the issuer
  distinguished names of both certificates
- validates that the current time falls within the signing certificate's validity period
- validates that the purpose of the signing certificate's key usage is non-repudiation
- validates that the signing certificate is signed by a trusted certificate authority

The signing certificate's revocation status is not checked at this point; it is checked during the signing flow when
the certificate is actually used.

**Step 22.** It then verifies the authentication token signature by reconstructing the authentication value
`hash(origin) + hash(challenge)` using the expected origin from server configuration and the challenge from the session,
and verifying the signature in the token's `signature` field against it with the public key of the authentication
certificate. The signature verification applies the hash function of the signature algorithm to the reconstructed value
itself, so the value MUST NOT be hashed again before verification.

**Step 23.** Successful validation of the authentication token proves only the identity of the user. Whether the identified user is
allowed to access the service is a domain-specific authorization decision that is out of scope of the Web eID for
Mobile protocol and the validation libraries: after token validation succeeds and before creating the authenticated
session, the RP MUST verify that the subject of the authentication certificate (identified, for example, by the
personal identification code in the certificate's subject field) has access to the service.

**Steps 24–25.** On success, the RP creates a new authenticated session. If the authentication token contained the
`unverifiedSigningCertificates` field, the RP MAY store the validated signing certificate and supported signature
algorithms from the token into the session for later use in the signing flow.

**Steps 26–27.** The RP returns HTTP 200, deletes the `__Host-web-eid-auth` cookie by setting its `Max-Age` to 0, sets
a new application-specific authenticated session cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`) and directs
the browser to the protected resource. The name of the authenticated session cookie is chosen by the application; it
SHOULD also use the `__Host-` prefix. The authenticated session cookie SHOULD use `SameSite=Strict` instead of the
`SameSite=Lax` required for the protocol cookies, because cross-application navigation is no longer required after
authentication completes, and `Strict` provides stronger CSRF protection for the authenticated session.

**Steps 28–30.** On failure, the RP ends the authentication session, deletes the session cookie by setting its
`Max-Age` to 0, and returns HTTP 401 Unauthorized. The browser displays an error to the user.

#### Origin serialization

The eID app derives the `origin` from the `loginUri` and `responseUri` request parameters, which MUST use the `https`
scheme. The app takes the scheme, host name and port from the URI and discards its path, query and fragment components,
serializing the origin as `<scheme> "://" <hostname> [ ":" <port> ]`, without a trailing slash `/`. The port is omitted
when the URI uses the default port 443 of the `https` scheme. The host name is serialized differently depending on
whether the origin is shown to the user or hashed, as described below.

##### Origin shown to the user for consent

The origin that the eID app shows to the user for consent SHOULD render internationalized domain names in their Unicode
form, as the user recognizes `https://päike.ee` but not its ASCII form. The eID app MUST fall back to the ASCII
(Punycode) form when the host name does not pass an internationalized domain name display policy, and MUST warn the
user that the name of the website could not be displayed safely. The display policy SHOULD follow the *Moderately
Restrictive* or *Highly Restrictive* restriction level and the confusable detection defined in
[UTS #39](https://www.unicode.org/reports/tr39/), which is what browsers apply to the address bar and which
implementations can obtain from the `uspoof` API of the ICU library.

A Unicode host name that mixes scripts enables homograph phishing, where a look-alike host name is mistaken for a
familiar one: the Cyrillic letters `а`, `е`, `р` and `о` render identically to the Latin `a`, `e`, `p` and `o`, so a
host name registered with them is indistinguishable from a familiar one on screen. The ASCII form cannot be mistaken
for a familiar name, but it is also not recognizable to the user, so it MUST NOT be presented as an ordinary origin.
The consent screen is the only place where the user sees which website made the request, as the eID app has no address
bar, and in the signing flow it is the only protection against signing a document prepared by a hostile website.

##### Origin used as input to hash(origin)

In the authentication flow, the origin that the eID app uses as input to `hash(origin)` in the authentication value
MUST be the
[ASCII serialization of the website origin](https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin),
matching the `location.origin`/`URL.origin` serialization of the browser. In particular, internationalized domain names
MUST be serialized in their ASCII (Punycode) form. The relying party MUST reconstruct and hash the same ASCII origin
string when it verifies the authentication token signature. A mismatch in serialization, such as an internationalized
domain name in Unicode form or a trailing slash, results in a different hash and makes signature verification fail.

Examples:

| Website URL                                    | Shown for consent          | Signed `origin` value      |
|------------------------------------------------|----------------------------|----------------------------|
| `https://ria.ee/`                              | `https://ria.ee`           | `https://ria.ee`           |
| `https://päike.ee/`                            | `https://päike.ee`         | `https://xn--pike-loa.ee`  |
| `https://example.com:8443/path?query#fragment` | `https://example.com:8443` | `https://example.com:8443` |
| `https://example.com:443/`                     | `https://example.com`      | `https://example.com`      |

#### Clarification on challenge nonce processing

- The challenge nonce value is supplied by the website as a Base64-encoded string representing a cryptographically
  strong random value that MUST contain at least 32 bytes of entropy.
- The Web eID application does not validate the nonce as Base64 and does not decode it into raw bytes.
- The Web eID application validates only the length of the supplied nonce: it MUST be at least 44 characters long,
  corresponding to the length of a Base64-encoded 32-byte value, and MUST NOT be longer than 128 characters.

Base64 encoding is used because the nonce is transported through web and JSON APIs as text. The Web eID application does
not require the nonce to be Base64-encoded — Base64 is simply the most suitable encoding for transmitting bytes through
the web layer. The application treats the nonce as an opaque challenge string and signs the hash of that exact string;
decoding the nonce would not add security value and would only complicate processing.

#### Authentication request

Authentication request AppLink/UniversalLink format:

https://mopp.ria.ee/auth#base64url-encoded-request

Decoded URI fragment payload:

```json
{
  "challenge": "YbQ7Q5p+xdr9HBrmGXqq5VdIqq9CfVoUNN1W6BfWE+8=",
  "loginUri": "https://rp.example.com/auth/eid/login",
  "getSigningCertificate": true
}
```

#### Authentication response

Authentication response URI format:

<loginUri>#base64url-encoded-response

Decoded URI fragment payload:

```json
{
  "authToken": {
    "unverifiedCertificate": "MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4...",
    "algorithm": "ES384",
    "signature": "HBjNXIaUskXbfhzYQHvwjKDUWfNu4yxXZha...",
    "unverifiedSigningCertificates": [
      {
        "certificate": "MIIFikACB3ugAwASAgIHHFrtdZ-zeQsas1...",
        "supportedSignatureAlgorithms": [
          {
            "cryptoAlgorithm": "ECC",
            "hashFunction": "SHA-384",
            "paddingScheme": "NONE"
          }
        ]
      }
    ],
    "format": "web-eid:1.1",
    "appVersion": "https://mopp.ria.ee/releases/v1.0.0"
  }
}
```

#### Error response

Error response URI format:

<loginUri>#base64url-encoded-response

Decoded URI fragment payload:

```json
{
  "error": true,
  "code": "ERR_WEBEID_MOBILE_INVALID_REQUEST",
  "message": "Invalid challenge length"
}
```

### <a id="signing-protocol"></a>Digital signing

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant E as eID App
    participant B as Browser
    participant RP as Relying Party
    U ->>+ B: Sign
    B ->>+ RP: Initiate signing
    RP ->> RP: Create signing session <br/> (TTL: 5 minutes)
    RP ->> RP: Create certificate request AppLink/UniversalLink <br/> with responseUri
    critical
        RP -->>- B: Set signing session cookie (HttpOnly, Secure, SameSite=Lax, Path=/, Max-Age=300) <br/> Return certificate request AppLink/UniversalLink
    end
    B ->> B: Open AppLink/UniversalLink
    B ->>- E: Open AppLink/UniversalLink
    activate E
    critical
        E ->> E: Parse origin from responseUri
        E ->>+ U: Show certificate request with origin
        U -->>- E: Consent certificate request and origin
    end

    E ->>- B: Open browser with responseUri #35; <base64url-encoded-certificate>
    activate B
    B ->>+ RP: HTTP GET <responseUri>
    RP -->>- B: HTTP 200 Certificate response view
    B ->> B: Parse certificate from responseUri fragment
    B ->>+ RP: POST Certificate <br/> Signing session cookie (HttpOnly, Secure, SameSite=Lax, Path=/)
    critical
        RP ->> RP: Verify signing session exists
    end
    RP ->> RP: Parse certificate, <br/> verify certificate subject matches <br/> expected user's subject <br/> and prepare a hash to sign
    RP ->> RP: Create signing request AppLink/UniversalLink <br/> with hash, hashFunction, signingCertificate and responseUri
    RP -->>- B: Return signing request AppLink/UniversalLink
    B ->> B: Open AppLink/UniversalLink
    B ->>+ E: Open AppLink/UniversalLink
    deactivate B
    critical
        E ->> E: Parse origin from responseUri
        E ->>+ U: Show signing request with origin <br/>and signing subject details
        U -->>- E: Consent signing request and origin <br/>with ID Card PIN2
    end
    Note over U, E: User taps ID Card
    E ->> E: Sign the hash <br/>with ID Card over NFC using PIN2
    E ->>- B: Open browser with responseUri #35; <base64url-encoded-signature>
    activate B
    B ->>+ RP: HTTP GET <responseUri>
    RP -->>- B: HTTP 200 Response view
    B ->> B: Parse signature from responseUri fragment
    B ->>+ RP: POST Signature <br/> Signing session cookie (HttpOnly, Secure, SameSite=Lax, Path=/)
    critical
        RP ->> RP: Verify signing session exists
    end
    RP ->> RP: Verify certificate and signature
    RP ->> RP: End signing session
    alt Verification success
        RP -->> B: HTTP 200, Return signed data <br/>Delete signing session cookie
    else Verification failure
        RP -->>- B: HTTP 401/403, Return error, Delete signing session cookie
        B ->> B: Show error
    end
    deactivate B
```

Figure 2: Web eID for Mobile digital signing diagram

The digital signing steps are as follows:

The digital signing flow consists of two phases: a **certificate phase** (steps 1–19) in which the RP obtains the user's
signing certificate, and a **signature phase** (steps 20–36) in which the actual hash is signed. The certificate phase
MAY be skipped if the user was authenticated using `getSigningCertificate=true` or the user's signing certificate is
obtained from LDAP. When the certificate phase is skipped, the RP uses the stored signing certificate to prepare the
hash and builds the signing request AppLink/UniversalLink directly, entering the flow at the signature phase (step 20).

#### Certificate phase

**Steps 1–2.** The user initiates signing in the mobile browser. The browser sends a signing initiation request to the
Relying Party (RP).

**Steps 3–4.** The RP creates a new signing session with a time-to-live that SHOULD NOT exceed 5 minutes and
prepares references to the data that will be signed. It builds a certificate request AppLink/UniversalLink containing
the `responseUri` to which the eID app returns the signing certificate (e.g.
`https://rp.example.com/sign/eid/certificate`).

**Step 5.** The RP sets a signing session cookie (`__Host-web-eid-sign`; `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`,
`Max-Age=300`) and returns the certificate request AppLink/UniversalLink to the browser. The cookie binds subsequent
requests to this signing session.

**Steps 6–7.** The browser opens the AppLink/UniversalLink. The operating system verifies the domain ownership of the
link and launches the eID app.

**Steps 8–10.** The eID app parses and validates the `responseUri` from the URL fragment and extracts the origin. It
displays the certificate request to the user, showing the origin of the requesting website. The user reviews the request
and consents.

**Step 11.** The eID app opens the browser with the `responseUri` appended with a URL fragment containing the
base64url-encoded signing certificate and supported signature algorithms (e.g.
`https://rp.example.com/sign/eid/certificate#<base64url-encoded-certificate>`).

**Steps 12–13.** The browser makes an HTTP GET request to the `responseUri`. The RP responds with an HTTP 200
certificate response page that contains JavaScript to process the certificate.

**Steps 14–15.** The JavaScript on the page parses the signing certificate from the URL fragment and automatically
submits it to the RP via an HTTP POST request. The signing session cookie (`__Host-web-eid-sign`) is included with the
request, binding it to the session created in steps 3–4.

**Step 16.** The RP verifies that the signing session identified by the session cookie exists and is valid.

**Steps 17–18.** The RP parses the signing certificate and verifies that it belongs to the expected subject. The RP then
prepares the data to sign using the certificate and supported signature algorithms, producing an unsigned container with
a hash and hash function. The RP builds a signing request AppLink/UniversalLink containing the `hash`, `hashFunction`,
`signingCertificate`, and a new `responseUri` for the signature (e.g. `https://rp.example.com/sign/eid/signature`). The
`hash` MUST be the Base64 encoding of the raw digest bytes, as described in the
[signing request](#signing-request) section.

**Step 19.** The RP returns the signing request AppLink/UniversalLink to the browser along with an updated signing
session cookie.

#### Signature phase

**Steps 20–21.** The browser opens the signing request AppLink/UniversalLink. The operating system verifies the domain
ownership of the link and launches the eID app.

**Steps 22–24.** The eID app parses and validates the `responseUri` from the URL fragment and extracts the origin. It
displays the signing request to the user, showing the origin and details (given name, surname, personal ID code) of the
requested signing subject. The user reviews the request and consents by entering their ID card PIN2.

**Step 25.** The eID app decodes the Base64-encoded `hash` received from the RP into raw bytes and signs those bytes
with the ID card's signing key over NFC using PIN2. The user taps the ID card to the phone's NFC reader during this
step.

**Step 26.** The eID app opens the browser with the `responseUri` appended with a URL fragment containing the
base64url-encoded signature and signature algorithm (e.g.
`https://rp.example.com/sign/eid/signature#<base64url-encoded-signature>`).

**Steps 27–28.** The browser makes an HTTP GET request to the `responseUri`. The RP responds with an HTTP 200 response
page that contains JavaScript to process the signature.

**Steps 29–31.** The JavaScript on the page parses the signature from the URL fragment and automatically submits it to
the RP via an HTTP POST request. The signing session cookie (`__Host-web-eid-sign`) is included with the request. The RP
verifies that the signing session identified by the session cookie exists and is valid.

**Steps 32–33.** The RP verifies the signing certificate (validity period, key usage extensions, OCSP revocation
status). The RP verifies the signature against the unsigned container prepared in steps 17–18 and finalizes the
signed container. The RP ends the signing session.

**Steps 34–36.** On success, the RP returns the signed data to the browser and deletes the signing session cookie. On
failure, the browser displays an error to the user and the signing session cookie is deleted.

#### Certificate request

Certificate request AppLink/UniversalLink format:

https://mopp.ria.ee/cert#base64url-encoded-request

Decoded URI fragment payload:

```json
{
  "responseUri": "https://rp.example.com/sign/eid/certificate"
}
```

#### Certificate response

Certificate response URI format:

<responseUri>#base64url-encoded-response

Decoded URI fragment payload:

```json
{
  "certificate": "MIIFikACB3ugAwASAgIHHFrtdZ-zeQsas1...",
  "supportedSignatureAlgorithms": [
    {
      "cryptoAlgorithm": "ECC",
      "hashFunction": "SHA-256",
      "paddingScheme": "NONE"
    },
    {
      "cryptoAlgorithm": "ECC",
      "hashFunction": "SHA-384",
      "paddingScheme": "NONE"
    },
    {
      "cryptoAlgorithm": "ECC",
      "hashFunction": "SHA-512",
      "paddingScheme": "NONE"
    }
  ]
}
```

#### Signing request

Signing request AppLink/UniversalLink format:

https://mopp.ria.ee/sign#base64url-encoded-request

Decoded URI fragment payload:

```json
{
  "hash": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
  "hashFunction": "SHA-256",
  "signingCertificate": "MIIFikACB3ugAwASAgIHHFrtdZ-zeQsas1...",
  "responseUri": "https://rp.example.com/sign/eid/signature"
}
```

The `hash` field is the Base64 encoding of the raw digest bytes of the data to be signed, computed with the hash
function named in `hashFunction`. The same encoding is used by the `hash` argument of the `sign` command of the
[Web eID protocol](https://github.com/web-eid/web-eid-system-architecture-doc/blob/master/README.md#native-application-messaging-api).
Base64 is used because the request payload is transported as JSON text.

Before signing, the eID app MUST decode the `hash` into raw bytes and MUST verify that the number of decoded bytes
matches the digest length of `hashFunction` (for example 32 bytes for `SHA-256`). The decoded raw digest bytes are what
is signed with the signing key on the ID card. A request whose `hash` is not valid Base64 or whose decoded length does
not match `hashFunction` MUST be rejected with the `ERR_WEBEID_MOBILE_INVALID_REQUEST` error.

#### Signing response

Signing response URI format:

<responseUri>#base64url-encoded-response

Decoded URI fragment payload:

```json
{
  "signature": "HBjNXIaUskXbfhzYQHvwjKDUWfNu4yxXZha...",
  "signatureAlgorithm": {
    "cryptoAlgorithm": "ECC",
    "hashFunction": "SHA-256",
    "paddingScheme": "NONE"
  }
}
```

#### Error response

Error response URI format:

<responseUri>#base64url-encoded-response

Decoded URI fragment payload:

```json
{
  "error": true,
  "code": "ERR_WEBEID_MOBILE_INVALID_REQUEST",
  "message": "Invalid challenge length"
}
```

### Error codes

The eID app returns the following error codes in the error response:

- `ERR_WEBEID_MOBILE_INVALID_REQUEST` — the request received by the eID app is invalid (e.g. malformed URI, invalid
  challenge length, unsupported parameters).
- `ERR_WEBEID_MOBILE_UNKNOWN_ERROR` — application error.
- `ERR_WEBEID_USER_CANCELLED` — the user cancelled the authentication or signing operation.

### RIA-DigiDoc mobile app

The RIA-DigiDoc mobile app is the official application that supports Web eID for Mobile protocol. The app is developed
by the Estonian Information System Authority (RIA) and is available on
the [Google Play Store](https://play.google.com/store/apps/details?id=ee.ria.DigiDoc)
and [Apple App Store](https://apps.apple.com/app/ria-digidoc/id1216104448). The app is open source and its source
code is available in the [RIA-DigiDoc-Android](https://github.com/open-eid/RIA-DigiDoc-Android)
and [RIA-DigiDoc-iOS](https://github.com/open-eid/RIA-DigiDoc-iOS) GitHub repositories.

> The RIA-DigiDoc mobile app AppLink/UniversalLink is https://mopp.ria.ee
>
> If the user has not installed the RIA-DigiDoc mobile app, the AppLink/UniversalLink will direct them to the app store
> to install it.

### Security assumptions

The security of the Web eID for Mobile protocol relies on the following assumptions:

- The relying party MUST correctly implement the protocol and securely validate authentication tokens and signatures
  according to the specification. The relying party MUST use the cookies and validate the session state as described
  in the protocol; this is critical to prevent MITM and replay attacks.
- The relying party MUST perform a domain-specific authorization check after successful authentication: validating the
  authentication token establishes the user's identity, not their right to access the service.
- The relying party MUST use the official RIA-DigiDoc mobile app AppLink/UniversalLink https://mopp.ria.ee, ensuring
  that only the legitimate eID app can receive the authentication and signing requests. This prevents malicious apps
  from intercepting or forging requests.
- The protocol assumes that the user verifies the origin and details of authentication and signing requests in the eID
  app and only consents to legitimate requests. User education and clear UI design in the eID app are important to
  mitigate phishing risks.
- RIA-DigiDoc mobile app MUST only accept requests in the formats defined by the specification and MUST parse the
  `origin`, which MUST be shown to the user for consent, from the `loginUri` and `responseUri` request parameters, as
  described in [Origin serialization](#origin-serialization).
- The `loginUri` and `responseUri` parameters MUST use the HTTPS scheme, MUST be valid URLs, and SHOULD have a
  maximum origin length of 255 characters. The eID app MUST reject requests with malformed or non-HTTPS URIs.
- The relying party's login and response pages MUST be free of cross-site scripting (XSS) vulnerabilities, as the
  JavaScript on these pages reads sensitive data (authentication tokens, certificates, signatures) from URL fragments.
  Relying parties SHOULD deploy Content Security Policy (CSP) headers to mitigate XSS risks.
- When the signing certificate is received in the authentication token, the relying party MUST validate the signing
  certificate as described in the authentication flow, before using it to prepare the hash to sign.
- The relying party MUST verify that the signing certificate used in the hash-to-sign step of the signing flow belongs
  to the expected user by checking that its subject matches the subject of the expected user's certificate, regardless
  of whether the signing certificate was received in the certificate phase, in the authentication token via
  `getSigningCertificate=true`, or obtained from the LDAP.
- The `SameSite=Lax` protocol cookies prevent cookies from being sent with direct cross-site POST requests, but do
  not prevent an external site from navigating the browser to `loginUri#<payload>` or `responseUri#<payload>`. The
  top-level GET includes the cookie, and the callback page relays the fragment in a same-origin POST with that cookie.
  The cookie therefore binds the request to a session but does not prove that the payload came from the eID app.
  `SameSite` also does not protect against attacks from a different origin within the same site, such as a compromised
  subdomain.
- The RP MUST treat callback fragments as untrusted input and validate them against the existing, unexpired session
  as specified in the authentication and signing flows. Authentication requires a valid signature over the expected
  origin and the session's single-use challenge. Signing requires the expected user's certificate and a valid signature
  over the data prepared for that signing session. The certificate response itself contains no proof of possession of
  the private key. These checks constrain which payloads can be accepted; `SameSite=Lax` alone does not provide complete
  CSRF protection for the callback flow.
- Relying parties SHOULD implement additional CSRF protection (e.g., synchronizer tokens) for the POST endpoints.
  However, a CSRF token automatically attached by the callback page, or an origin check on its same-origin POST, does
  not prevent the navigation-and-relay flow described above. See the
  [OWASP guidance on client-side CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#dealing-with-client-side-csrf-attacks-important).
- The eID app MUST verify that the `signingCertificate` received in the signing request matches the signing
  certificate on the user's physical ID card before proceeding with signing.

### Web eID authentication token specification

The authentication token specification can be found in
the [Web eID protocol](https://github.com/web-eid/web-eid-system-architecture-doc/blob/master/README.md#web-eid-authentication-token-specification)
page.

To support skipping the [certificate request flow](#certificate-phase) described in the
[digital signing flow](#signing-protocol), the Web eID authentication token format version `web-eid:1.1` adds an
`unverifiedSigningCertificates` field for sending the signing certificate and supported signature algorithms. The
conditions under which the field is present in the token format itself are defined by the Web eID authentication token
specification; the Web eID for Mobile protocol REQUIRES the field in the authentication token when the authentication
request included `getSigningCertificate=true`.

#### Validation libraries

The Web eID project provides official reference implementations of the Web eID authentication token validation algorithm
for Java, .NET and PHP. The reference implementations also include secure challenge nonce generation as required by the
Web
eID authentication protocol. The reference implementations are distributed as libraries to make them easy to integrate
into applications that intend to use Web eID authentication.

Java applications can use the `web-eid-authtoken-validation-java` library. The full specification of the library API and
its source code is available in the
`web-eid-authtoken-validation-java` [GitHub repository](https://github.com/web-eid/web-eid-authtoken-validation-java).

.NET applications can use the `web-eid-authtoken-validation-dotnet` library. The full specification of the library API
and its source code is available in the
`web-eid-authtoken-validation-dotnet` [GitHub repository](https://github.com/web-eid/web-eid-authtoken-validation-dotnet).

PHP applications can use the `web-eid-authtoken-validation-php` library. The full specification of the library API
and its source code is available in the
`web-eid-authtoken-validation-php` [GitHub repository](https://github.com/web-eid/web-eid-authtoken-validation-php).

### Implementation guide and example applications

To implement authentication and digital signing with Web eID for Mobile in a Java, .NET or PHP web application,
follow the steps below:

- in the back end of a Java web application,
    - for authentication, use the *web-eid-authtoken-validation-java* Java library according to
      instructions [here](https://github.com/web-eid/web-eid-authtoken-validation-java#quickstart),
    - for digital signing, use the *digidoc4j* Java library according to
      instructions [here](https://github.com/open-eid/digidoc4j/wiki/Examples-of-using-it),
- in the back end of a .NET web application,
    - for authentication, use the *web-eid-authtoken-validation-dotnet* .NET library according to
      instructions [here](https://github.com/web-eid/web-eid-authtoken-validation-dotnet#quickstart),
    - for digital signing, use the C# bindings of the `libdigidocpp` library according to
      instructions [here](https://github.com/web-eid/web-eid-authtoken-validation-dotnet/wiki/How-to-implement-digital-signing-in-a-.NET-web-application-back-end).
- in the back end of a PHP web application,
    - for authentication, use the *web-eid-authtoken-validation-php* PHP library according to
      instructions [here](https://github.com/web-eid/web-eid-authtoken-validation-php#quickstart),
    - digital signing in PHP is not currently covered by the Web eID project libraries.

The full source code and overview of an example Spring Boot web application that uses Web eID for Mobile protocol
authentication and digital signing is
available [here](https://github.com/web-eid/web-eid-authtoken-validation-java/tree/main/example). The
.NET/C# version of the same example is
available [here](https://github.com/web-eid/web-eid-authtoken-validation-dotnet/tree/main/example). The PHP version of
the example application is
available [here](https://github.com/web-eid/web-eid-authtoken-validation-php/tree/main/example).
